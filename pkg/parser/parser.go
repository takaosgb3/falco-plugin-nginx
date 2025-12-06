// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package parser provides nginx log parsing functionality for the Falco nginx plugin.
// It supports both common and combined log formats, as well as custom formats.
// The parser can detect various security threats including SQL injection, XSS attempts,
// path traversal attacks, and suspicious user agents.
package parser

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEntry represents a parsed nginx log entry with all extracted fields.
// It contains standard nginx log fields as well as security-related flags
// and additional metadata that can be used for threat detection.
type LogEntry struct {
	RemoteAddr     string
	RemoteUser     string
	TimeLocal      time.Time
	Timestamp      time.Time // Alias for TimeLocal for consistency
	Request        string
	Method         string
	Path           string
	QueryString    string
	HTTPVersion    string
	Status         int
	BodyBytes      int
	Referer        string
	UserAgent      string
	ResponseTime   float64
	UpstreamAddr   string
	UpstreamTime   float64
	Raw            string
	Extra          map[string]interface{}
	SecurityThreat SecurityThreatType
	Headers        map[string]string // HTTP request headers (e.g., X-Test-ID, X-Category)
}

// SecurityThreatType represents types of security threats
type SecurityThreatType int

const (
	// NoThreat indicates no security threat detected
	NoThreat SecurityThreatType = iota
	// SQLInjection indicates SQL injection attempt detected
	SQLInjection
	// XSSAttempt indicates XSS attempt detected
	XSSAttempt
	// PathTraversal indicates path traversal attempt detected
	PathTraversal
	// CommandInjection indicates command injection attempt detected
	CommandInjection
	// SuspiciousUserAgent indicates suspicious user agent detected
	SuspiciousUserAgent
)

// Parser parses nginx log entries according to the configured format.
// It supports common, combined, and custom log formats and can detect
// various security threats in the parsed data.
type Parser struct {
	config           Config
	parseFunc        func(string) (*LogEntry, error)
	timeLayout       string
	securityDetector *SimpleSecurityDetector
}

// Common nginx log format patterns
// NOTE: These patterns expect single spaces between fields. Logs with multiple consecutive
// spaces or tabs may not parse correctly. This is a known limitation to maintain performance
// and compatibility with standard nginx log formats.
var (
	// Combined log format (default)
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	combinedPattern = regexp.MustCompile(
		`^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\S+) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`,
	)

	// Common log format
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
	commonPattern = regexp.MustCompile(
		`^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\S+) (?P<body_bytes>\S+)`,
	)

	// Combined log format with request time
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time
	combinedWithTimePattern = regexp.MustCompile(
		`^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\S+) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<request_time>[\d\.]+)`,
	)

	// Extended log format with upstream info
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $request_time $upstream_addr $upstream_response_time
	extendedPattern = regexp.MustCompile(
		`^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\S+) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" (?P<request_time>[\d\.\-]+) (?P<upstream_addr>\S+) (?P<upstream_time>[\d\.\-]+)`,
	)

	// E2E custom log format with HTTP headers for test correlation
	// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" x_test_id=$http_x_test_id x_category=$http_x_category x_pattern_id=$http_x_pattern_id
	e2eCustomPattern = regexp.MustCompile(
		`^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\S+) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)" x_test_id=(?P<x_test_id>\S+) x_category=(?P<x_category>\S+) x_pattern_id=(?P<x_pattern_id>\S+)`,
	)

	// Request parsing pattern - handles spaces in URL for malformed/attack requests
	requestPattern = regexp.MustCompile(`^(\S+)\s+(.+?)\s+(HTTP/[\d\.]+)$`)

	// Time format used by nginx
	nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"
)

// New creates a new log parser with the given configuration.
// The parser will use the format specified in the configuration
// (common, combined, or custom) and apply security pattern detection
// if enabled.
func New(cfg Config) *Parser {
	p := &Parser{
		config:           cfg,
		timeLayout:       nginxTimeLayout,
		securityDetector: NewSimpleSecurityDetector(),
	}

	// Set parse function based on format
	switch cfg.LogFormat {
	case "combined":
		p.parseFunc = p.parseCombined
	case "common":
		p.parseFunc = p.parseCommon
	case "custom":
		if cfg.CustomFormat == "" {
			// Default to combined if custom format is empty
			p.parseFunc = p.parseCombined
		} else {
			// TODO: Implement custom format parser
			p.parseFunc = func(line string) (*LogEntry, error) {
				return nil, fmt.Errorf("custom format parser not yet implemented")
			}
		}
	default:
		// Default to combined format
		p.parseFunc = p.parseCombined
	}

	return p
}

// NewParser creates a new log parser with the specified format.
// Deprecated: Use New with a Config struct instead.
// This function is kept for backward compatibility.
//
// Valid formats are: "combined", "common", "custom"
// For "custom" format, customFormat must be provided.
// Returns an error for invalid format names.
func NewParser(format string, customFormat string) (*Parser, error) {
	// Validate format
	validFormats := map[string]bool{
		"combined": true,
		"common":   true,
		"custom":   true,
	}
	if !validFormats[format] {
		return nil, fmt.Errorf("invalid log format: %q (valid formats: combined, common, custom)", format)
	}

	// For custom format, customFormat must be provided
	if format == "custom" && customFormat == "" {
		return nil, fmt.Errorf("custom format requires a customFormat string")
	}

	cfg := Config{
		LogFormat:              format,
		CustomFormat:           customFormat,
		SecurityPatterns:       true,
		LargeResponseThreshold: 10 * 1024 * 1024, // 10MB default
	}
	return New(cfg), nil
}

// Parse parses a single log line according to the configured format.
// It extracts all standard nginx log fields and performs security
// analysis if enabled. Returns a LogEntry with parsed fields and
// security flags, or an error if parsing fails.
//
// The parser tries formats in this order:
// 1. E2E custom format (with HTTP headers for test correlation)
// 2. Configured format (combined/common/custom)
func (p *Parser) Parse(line string) (*LogEntry, error) {
	if line == "" {
		return nil, fmt.Errorf("empty log line")
	}

	// Try E2E custom format first (highest priority for E2E test correlation)
	entry, err := p.parseE2ECustom(line)
	if err != nil {
		// Fall back to configured format
		entry, err = p.parseFunc(line)
		if err != nil {
			return nil, err
		}
	}

	// Store raw line
	entry.Raw = line

	// Parse request details
	if err := p.parseRequest(entry); err != nil {
		// Log error but don't fail - some fields might still be useful
		entry.Extra["request_parse_error"] = err.Error()
	}

	// Detect potential security issues
	p.detectSecurityPatterns(entry)

	return entry, nil
}

// parseCombined parses the combined log format
func (p *Parser) parseCombined(line string) (*LogEntry, error) {
	// Try patterns in order from most specific to least specific
	matches := extendedPattern.FindStringSubmatch(line)
	formatType := "extended"
	if matches == nil {
		matches = combinedWithTimePattern.FindStringSubmatch(line)
		formatType = "combined_with_time"
		if matches == nil {
			matches = combinedPattern.FindStringSubmatch(line)
			formatType = "combined"
			if matches == nil {
				return nil, fmt.Errorf("line does not match combined format")
			}
		}
	}

	// Parse timestamp
	timeStr := matches[3]
	timestamp, err := time.Parse(p.timeLayout, timeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	// Parse numeric fields with error handling
	status, err := strconv.Atoi(matches[5])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		status = 0 // Use 0 for dash or malformed status
	}

	bodyBytes, err := strconv.Atoi(matches[6])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		bodyBytes = 0 // Use 0 for dash or malformed body bytes
	} else if bodyBytes < 0 {
		// Negative body bytes don't make sense, set to 0
		bodyBytes = 0
	}

	entry := &LogEntry{
		RemoteAddr: matches[1],
		RemoteUser: matches[2],
		TimeLocal:  timestamp,
		Timestamp:  timestamp, // Set both for compatibility
		Request:    matches[4],
		Status:     status,
		BodyBytes:  bodyBytes,
		Referer:    matches[7],
		UserAgent:  matches[8],
		Extra:      make(map[string]interface{}),
		Headers:    make(map[string]string), // Initialize Headers map for consistency
	}

	// Parse additional fields based on format type
	switch formatType {
	case "extended":
		// Parse request time
		if len(matches) > 9 && matches[9] != "-" {
			if requestTime, err := strconv.ParseFloat(matches[9], 64); err == nil {
				entry.ResponseTime = requestTime
			}
		}
		// Parse upstream address
		if len(matches) > 10 && matches[10] != "-" {
			entry.UpstreamAddr = matches[10]
		}
		// Parse upstream time
		if len(matches) > 11 && matches[11] != "-" {
			if upstreamTime, err := strconv.ParseFloat(matches[11], 64); err == nil {
				entry.UpstreamTime = upstreamTime
			}
		}
	case "combined_with_time":
		// Parse request time
		if len(matches) > 9 && matches[9] != "-" {
			if requestTime, err := strconv.ParseFloat(matches[9], 64); err == nil {
				entry.ResponseTime = requestTime
			}
		}
	}

	// Handle "-" values
	if entry.RemoteUser == "-" {
		entry.RemoteUser = ""
	}
	if entry.Referer == "-" {
		entry.Referer = ""
	}
	if entry.UserAgent == "-" {
		entry.UserAgent = ""
	}

	return entry, nil
}

// parseCommon parses the common log format
func (p *Parser) parseCommon(line string) (*LogEntry, error) {
	matches := commonPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("line does not match common format")
	}

	// Parse timestamp
	timeStr := matches[3]
	timestamp, err := time.Parse(p.timeLayout, timeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	// Parse numeric fields with error handling
	status, err := strconv.Atoi(matches[5])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		status = 0 // Use 0 for dash or malformed status
	}

	bodyBytes, err := strconv.Atoi(matches[6])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		bodyBytes = 0 // Use 0 for dash or malformed body bytes
	} else if bodyBytes < 0 {
		// Negative body bytes don't make sense, set to 0
		bodyBytes = 0
	}

	entry := &LogEntry{
		RemoteAddr: matches[1],
		RemoteUser: matches[2],
		TimeLocal:  timestamp,
		Timestamp:  timestamp, // Set both for compatibility
		Request:    matches[4],
		Status:     status,
		BodyBytes:  bodyBytes,
		Extra:      make(map[string]interface{}),
		Headers:    make(map[string]string), // Initialize Headers map for consistency
	}

	// Handle "-" values
	if entry.RemoteUser == "-" {
		entry.RemoteUser = ""
	}

	return entry, nil
}

// parseE2ECustom parses the E2E custom log format with HTTP headers.
// This format is used in E2E testing to include X-Test-ID, X-Category, and X-Pattern-ID
// headers for test correlation and detection tracking.
//
// Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" x_test_id=$http_x_test_id x_category=$http_x_category x_pattern_id=$http_x_pattern_id
//
// Example log line:
// 192.168.1.100 - - [12/Nov/2025:10:30:45 +0900] "GET /api/users?id=1' OR '1'='1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0" x_test_id=SQLI_BASIC_001-20251112-103045-abc123 x_category=sqli x_pattern_id=SQLI_BASIC_001
func (p *Parser) parseE2ECustom(line string) (*LogEntry, error) {
	matches := e2eCustomPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("line does not match e2e custom format")
	}

	// Parse timestamp
	timeStr := matches[3]
	timestamp, err := time.Parse(p.timeLayout, timeStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	// Parse numeric fields with error handling
	status, err := strconv.Atoi(matches[5])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		status = 0 // Use 0 for dash or malformed status
	}

	bodyBytes, err := strconv.Atoi(matches[6])
	if err != nil {
		// Handle special cases like "-" or non-numeric values
		bodyBytes = 0 // Use 0 for dash or malformed body bytes
	} else if bodyBytes < 0 {
		// Negative body bytes don't make sense, set to 0
		bodyBytes = 0
	}

	entry := &LogEntry{
		RemoteAddr: matches[1],
		RemoteUser: matches[2],
		TimeLocal:  timestamp,
		Timestamp:  timestamp, // Set both for compatibility
		Request:    matches[4],
		Status:     status,
		BodyBytes:  bodyBytes,
		Referer:    matches[7],
		UserAgent:  matches[8],
		Extra:      make(map[string]interface{}),
		Headers:    make(map[string]string), // Initialize Headers map
	}

	// Extract HTTP headers from log (nginx $http_* variables)
	// Match indices: 9=x_test_id, 10=x_category, 11=x_pattern_id
	if len(matches) > 9 && matches[9] != "-" {
		// Convert header name to lowercase for consistent lookup
		// nginx $http_x_test_id becomes "x-test-id" in Headers map
		entry.Headers["x-test-id"] = matches[9]
	}
	if len(matches) > 10 && matches[10] != "-" {
		entry.Headers["x-category"] = matches[10]
	}
	if len(matches) > 11 && matches[11] != "-" {
		entry.Headers["x-pattern-id"] = matches[11]
	}

	// Handle "-" values for standard fields
	if entry.RemoteUser == "-" {
		entry.RemoteUser = ""
	}
	if entry.Referer == "-" {
		entry.Referer = ""
	}
	if entry.UserAgent == "-" {
		entry.UserAgent = ""
	}

	return entry, nil
}

// parseRequest extracts method, path, and HTTP version from request string
func (p *Parser) parseRequest(entry *LogEntry) error {
	if entry.Request == "" {
		return fmt.Errorf("empty request string")
	}

	matches := requestPattern.FindStringSubmatch(entry.Request)
	if matches == nil {
		return fmt.Errorf("invalid request format")
	}

	entry.Method = matches[1]
	fullPath := matches[2]
	entry.HTTPVersion = matches[3]

	// Parse URL to extract query parameters
	if fullPath != "" {
		// Split path and query string
		if idx := strings.Index(fullPath, "?"); idx != -1 {
			entry.Path = fullPath[:idx]
			entry.QueryString = fullPath[idx+1:]
		} else {
			entry.Path = fullPath
			entry.QueryString = ""
		}

		// Parse query parameters
		if entry.QueryString != "" {
			parsedURL, err := url.Parse("?" + entry.QueryString)
			if err == nil {
				entry.Extra["query_params"] = parsedURL.Query()
			}
		}
	}

	return nil
}

// detectSecurityPatterns checks for common security patterns in the log entry
func (p *Parser) detectSecurityPatterns(entry *LogEntry) {
	// Helper function to check patterns with URL decoding
	checkWithDecoding := func(value string) (string, bool) {
		// Check original value
		threatType, found := p.securityDetector.DetectSecurityThreat(value)
		if found {
			return threatType, true
		}

		// Try URL decoding up to 3 levels
		decoded := value
		for i := 0; i < 3; i++ {
			newDecoded, err := url.QueryUnescape(decoded)
			if err != nil || newDecoded == decoded {
				break // No more decoding needed
			}
			decoded = newDecoded

			// Check decoded value
			threatType, found = p.securityDetector.DetectSecurityThreat(decoded)
			if found {
				return threatType, true
			}
		}

		return "", false
	}

	// Check various fields for security patterns
	fieldsToCheck := []string{
		entry.Path,
		entry.Request,
		entry.QueryString,
		entry.UserAgent,
	}

	for _, field := range fieldsToCheck {
		if field == "" {
			continue
		}

		if name, found := checkWithDecoding(field); found {
			if entry.Extra["security_alerts"] == nil {
				entry.Extra["security_alerts"] = []string{}
			}
			alerts, ok := entry.Extra["security_alerts"].([]string)
			if !ok {
				alerts = []string{}
				entry.Extra["security_alerts"] = alerts
			}
			// Avoid duplicate alerts
			alreadyExists := false
			for _, alert := range alerts {
				if alert == name {
					alreadyExists = true
					break
				}
			}
			if !alreadyExists {
				entry.Extra["security_alerts"] = append(alerts, name)
			}

			// Set SecurityThreat field based on the alert type
			switch name {
			case "sql_injection":
				entry.SecurityThreat = SQLInjection
			case "xss_attempt":
				entry.SecurityThreat = XSSAttempt
			case "path_traversal":
				entry.SecurityThreat = PathTraversal
			case "command_injection":
				entry.SecurityThreat = CommandInjection
			}
		}
	}

	// Check for suspicious user agents
	if p.securityDetector.DetectSuspiciousAgent(entry.UserAgent) {
		entry.SecurityThreat = SuspiciousUserAgent
		// Add to security alerts for consistency
		if entry.Extra["security_alerts"] == nil {
			entry.Extra["security_alerts"] = []string{}
		}
		alerts, ok := entry.Extra["security_alerts"].([]string)
		if !ok {
			alerts = []string{}
			entry.Extra["security_alerts"] = alerts
		}
		// Avoid duplicate alerts
		alreadyExists := false
		for _, alert := range alerts {
			if alert == "suspicious_agent" {
				alreadyExists = true
				break
			}
		}
		if !alreadyExists {
			entry.Extra["security_alerts"] = append(alerts, "suspicious_agent")
		}
	}

	// Also check decoded query parameters
	if queryParams, ok := entry.Extra["query_params"].(url.Values); ok {
		for _, values := range queryParams {
			for _, value := range values {
				threatType, found := p.securityDetector.DetectSecurityThreat(value)
				if found {
					if entry.Extra["security_alerts"] == nil {
						entry.Extra["security_alerts"] = []string{}
					}
					alerts, ok := entry.Extra["security_alerts"].([]string)
					if !ok {
						alerts = []string{}
						entry.Extra["security_alerts"] = alerts
					}
					// Avoid duplicate alerts
					alreadyExists := false
					for _, alert := range alerts {
						if alert == threatType {
							alreadyExists = true
							break
						}
					}
					if !alreadyExists {
						entry.Extra["security_alerts"] = append(alerts, threatType)
					}

					// Set SecurityThreat field based on the alert type
					switch threatType {
					case "sql_injection":
						entry.SecurityThreat = SQLInjection
					case "xss_attempt":
						entry.SecurityThreat = XSSAttempt
					case "path_traversal":
						entry.SecurityThreat = PathTraversal
					case "command_injection":
						entry.SecurityThreat = CommandInjection
					}
				}
			}
		}
	}

	// Check for suspicious status codes
	if entry.Status >= 400 && entry.Status < 500 {
		entry.Extra["client_error"] = true

		// High volume of 404s might indicate scanning
		if entry.Status == 404 {
			entry.Extra["potential_scan"] = true
		}

		// 403 might indicate access attempt
		if entry.Status == 403 {
			entry.Extra["access_denied"] = true
		}
	}

	// Check for unusually large responses
	if p.config.LargeResponseThreshold > 0 && entry.BodyBytes > p.config.LargeResponseThreshold {
		entry.Extra["large_response"] = true
	}

	// Check for suspicious HTTP methods
	suspiciousMethods := []string{"CONNECT", "TRACE", "TRACK", "OPTIONS", "PROPFIND"}
	for _, method := range suspiciousMethods {
		if entry.Method == method {
			entry.Extra["suspicious_method"] = true
			break
		}
	}
}
