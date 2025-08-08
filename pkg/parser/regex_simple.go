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

package parser

import (
	"strings"
)

// SimpleSecurityDetector uses string matching instead of regex for better performance
type SimpleSecurityDetector struct {
	maxInputLength int
}

// NewSimpleSecurityDetector creates a new detector that avoids regex where possible
func NewSimpleSecurityDetector() *SimpleSecurityDetector {
	return &SimpleSecurityDetector{
		maxInputLength: 10240, // 10KB max
	}
}

// DetectSQLInjection uses string matching for SQL injection patterns
func (d *SimpleSecurityDetector) DetectSQLInjection(input string) bool {
	if len(input) > d.maxInputLength {
		input = input[:d.maxInputLength]
	}

	lower := strings.ToLower(input)

	// Check for SQL keywords with minimal context
	sqlPatterns := []string{
		"union select",
		"union  select",
		"union   select",
		"select from",
		"select  from",
		"select   from",
		"drop table",
		"drop  table",
		"insert into",
		"insert  into",
		"delete from",
		"delete  from",
		"' or '",
		"' and '",
		"';--",
		"'; --",
		"--",
		"/*",
		"*/",
	}

	for _, pattern := range sqlPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	// Check for hex patterns (simple check)
	if strings.Contains(lower, "0x") && len(lower) > strings.Index(lower, "0x")+2 {
		// Check if followed by hex chars
		hexPart := lower[strings.Index(lower, "0x")+2:]
		if len(hexPart) >= 2 && isHexString(hexPart[:2]) {
			return true
		}
	}

	return false
}

// DetectXSS uses string matching for XSS patterns
func (d *SimpleSecurityDetector) DetectXSS(input string) bool {
	if len(input) > d.maxInputLength {
		input = input[:d.maxInputLength]
	}

	lower := strings.ToLower(input)

	xssPatterns := []string{
		"<script",
		"<iframe",
		"<object",
		"<embed",
		"<svg",
		"javascript:",
		"onerror=",
		"onload=",
		"onclick=",
		"onmouseover=",
	}

	for _, pattern := range xssPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectPathTraversal uses string matching for path traversal
func (d *SimpleSecurityDetector) DetectPathTraversal(input string) bool {
	if len(input) > d.maxInputLength {
		input = input[:d.maxInputLength]
	}

	patterns := []string{
		"../",
		"..\\",
		"/etc/",
		"/proc/",
		"/var/",
		"C:\\",
		"%2e%2e%2f",
		"%2e%2e%5c",
		"%252e%252e%252f",
		"%c0%ae%c0%ae",
		"..%2f",
		"..%5c",
	}

	lower := strings.ToLower(input)
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectCommandInjection uses string matching for command injection
func (d *SimpleSecurityDetector) DetectCommandInjection(input string) bool {
	if len(input) > d.maxInputLength {
		input = input[:d.maxInputLength]
	}

	// Check for command separators followed by commands
	separators := []string{";", "|", "&", "&&", "||"}
	commands := []string{
		"ls", "cat", "echo", "rm", "mv", "cp", "wget", "curl",
		"bash", "sh", "cmd", "nc", "netcat", "chmod", "chown",
		"whoami", "id", "uname", "ps", "kill", "sudo",
	}

	lower := strings.ToLower(input)

	// Check each separator
	for _, sep := range separators {
		idx := strings.Index(lower, sep)
		if idx >= 0 && idx < len(lower)-len(sep) {
			// Check what follows the separator
			remaining := strings.TrimSpace(lower[idx+len(sep):])
			for _, cmd := range commands {
				if strings.HasPrefix(remaining, cmd) {
					// Check if it's a command (followed by space or end)
					if len(remaining) == len(cmd) || (len(remaining) > len(cmd) && remaining[len(cmd)] == ' ') {
						return true
					}
				}
			}
		}
	}

	// Check for other injection patterns
	otherPatterns := []string{"$(", "`", "%0a", "%0d"}
	for _, pattern := range otherPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// DetectSuspiciousAgent uses string matching for suspicious user agents
func (d *SimpleSecurityDetector) DetectSuspiciousAgent(input string) bool {
	if len(input) > d.maxInputLength {
		input = input[:d.maxInputLength]
	}

	lower := strings.ToLower(input)

	// Tools that start with these
	prefixes := []string{
		"sqlmap", "nikto/", "nmap", "masscan", "w3af",
		"acunetix", "nessus", "openvas", "havij",
	}

	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	// Scanners
	if strings.HasSuffix(lower, "scanner") {
		return true
	}

	// Compound scanners
	scannerTypes := []string{"bot scanner", "vulnerability scanner", "security scanner"}
	for _, scanner := range scannerTypes {
		if strings.Contains(lower, scanner) {
			return true
		}
	}

	return false
}

// isHexString checks if a string contains only hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// DetectSecurityThreat checks all threat types
func (d *SimpleSecurityDetector) DetectSecurityThreat(input string) (string, bool) {
	// Check command injection first as it may contain path-like patterns
	if d.DetectCommandInjection(input) {
		return "command_injection", true
	}
	if d.DetectSQLInjection(input) {
		return "sql_injection", true
	}
	if d.DetectXSS(input) {
		return "xss_attempt", true
	}
	if d.DetectPathTraversal(input) {
		return "path_traversal", true
	}
	return "", false
}
