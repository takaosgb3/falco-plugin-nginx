package parser

import (
	"testing"
)

func TestParser_ParseLine(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name    string
		line    string
		wantErr bool
		checks  func(t *testing.T, entry *LogEntry)
	}{
		{
			name: "Normal request",
			line: `127.0.0.1 - - [30/Aug/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.RemoteAddr != "127.0.0.1" {
					t.Errorf("RemoteAddr = %v, want 127.0.0.1", entry.RemoteAddr)
				}
				if entry.Method != "GET" {
					t.Errorf("Method = %v, want GET", entry.Method)
				}
				if entry.Path != "/index.html" {
					t.Errorf("Path = %v, want /index.html", entry.Path)
				}
				if entry.Status != 200 {
					t.Errorf("Status = %v, want 200", entry.Status)
				}
			},
		},
		{
			name: "SQL injection attempt",
			line: `192.168.1.100 - - [30/Aug/2025:10:00:00 +0000] "GET /search?q=' OR '1'='1 HTTP/1.1" 200 5678 "-" "sqlmap/1.0"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.QueryString != "q=' OR '1'='1" {
					t.Errorf("QueryString = %v, want q=' OR '1'='1", entry.QueryString)
				}
				if entry.UserAgent != "sqlmap/1.0" {
					t.Errorf("UserAgent = %v, want sqlmap/1.0", entry.UserAgent)
				}
			},
		},
		{
			name: "XSS attempt with script tag",
			line: `10.0.0.1 - - [30/Aug/2025:10:00:00 +0000] "GET /page?input=<script>alert('XSS')</script> HTTP/1.1" 200 1000 "-" "Chrome/100"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.QueryString != "input=<script>alert('XSS')</script>" {
					t.Errorf("QueryString = %v, want script tag", entry.QueryString)
				}
			},
		},
		{
			name: "URL encoded XSS",
			line: `10.0.0.2 - - [30/Aug/2025:10:00:00 +0000] "GET /page?input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1" 200 1000 "-" "Firefox/120"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.QueryString != "input=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E" {
					t.Errorf("QueryString = %v, want URL encoded script", entry.QueryString)
				}
			},
		},
		{
			name: "Path traversal attempt",
			line: `192.168.1.50 - - [30/Aug/2025:10:00:00 +0000] "GET /../../etc/passwd HTTP/1.1" 404 100 "-" "curl/7.68.0"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.Path != "/../../etc/passwd" {
					t.Errorf("Path = %v, want /../../etc/passwd", entry.Path)
				}
				if entry.Status != 404 {
					t.Errorf("Status = %v, want 404", entry.Status)
				}
			},
		},
		{
			name: "POST request with body",
			line: `192.168.1.10 - admin [30/Aug/2025:10:00:00 +0000] "POST /api/login HTTP/1.1" 401 150 "https://example.com" "PostmanRuntime/7.0"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.Method != "POST" {
					t.Errorf("Method = %v, want POST", entry.Method)
				}
				if entry.RemoteUser != "admin" {
					t.Errorf("RemoteUser = %v, want admin", entry.RemoteUser)
				}
				if entry.Referer != "https://example.com" {
					t.Errorf("Referer = %v, want https://example.com", entry.Referer)
				}
			},
		},
		{
			name: "Multibyte characters in path",
			line: `192.168.1.1 - - [30/Aug/2025:10:00:00 +0000] "GET /日本語/テスト.html HTTP/1.1" 200 2000 "-" "Safari/15.0"`,
			checks: func(t *testing.T, entry *LogEntry) {
				if entry.Path != "/日本語/テスト.html" {
					t.Errorf("Path = %v, want /日本語/テスト.html", entry.Path)
				}
			},
		},
		{
			name:    "Malformed log line",
			line:    `this is not a valid nginx log line`,
			wantErr: true,
		},
		{
			name:    "Empty line",
			line:    ``,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := p.ParseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.checks != nil && entry != nil {
				tt.checks(t, entry)
			}
		})
	}
}

func TestParser_EdgeCases(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "Very long URI",
			line: `127.0.0.1 - - [30/Aug/2025:10:00:00 +0000] "GET /` + string(make([]byte, 1000, 1000)) + ` HTTP/1.1" 414 0 "-" "Test"`,
			want: "414", // Request-URI Too Large
		},
		{
			name: "Special characters in user agent",
			line: `127.0.0.1 - - [30/Aug/2025:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "User-Agent: <script>alert('XSS')</script>"`,
			want: "<script>", // Should preserve dangerous content for detection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := p.ParseLine(tt.line)
			if err != nil && tt.name != "Very long URI" {
				t.Errorf("ParseLine() unexpected error = %v", err)
				return
			}
			if entry != nil {
				// Validate specific fields based on test case
				switch tt.name {
				case "Very long URI":
					if entry.Status != 414 {
						t.Errorf("Expected status 414 for long URI, got %d", entry.Status)
					}
				case "Special characters in user agent":
					if !contains(entry.UserAgent, tt.want) {
						t.Errorf("UserAgent should contain %s, got %s", tt.want, entry.UserAgent)
					}
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr || 
		len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(substr) > 0 && len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}