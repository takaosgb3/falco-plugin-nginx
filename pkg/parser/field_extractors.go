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
	"net/url"
	"strconv"
	"strings"
)

// ExtractDecodedPath performs URL decoding with ReDoS protection
// It limits the number of decoding iterations to prevent infinite loops
// and potential ReDoS attacks with deeply nested encodings
func ExtractDecodedPath(path string) string {
	if path == "" {
		return ""
	}

	// Limit iterations to prevent ReDoS
	const maxDecodingIterations = 3
	decoded := path

	for i := 0; i < maxDecodingIterations; i++ {
		next, err := url.QueryUnescape(decoded)
		// If we get an error, try to decode what we can
		if err != nil {
			// url.QueryUnescape returns the input string on error,
			// but we want to decode valid parts and keep invalid parts
			// Try to decode valid parts only
			partialDecoded := decodeValidParts(decoded)
			if partialDecoded == decoded {
				break
			}
			decoded = partialDecoded
			continue
		}
		// Stop if no change occurred
		if next == decoded {
			break
		}
		decoded = next
	}

	return decoded
}

// decodeValidParts attempts to decode only the valid URL-encoded parts
// while preserving invalid sequences
func decodeValidParts(s string) string {
	// This is a simplified approach - in production, you might want
	// a more sophisticated parser
	result := strings.Builder{}
	i := 0

	for i < len(s) {
		// Need at least 3 characters for %XX pattern
		if s[i] == '%' && i+3 <= len(s) {
			// Check if the next two characters are valid hex
			hex := s[i+1 : i+3]
			if isHex(hex[0]) && isHex(hex[1]) {
				// Valid encoding, decode it
				if decoded, err := url.QueryUnescape(s[i : i+3]); err == nil {
					result.WriteString(decoded)
					i += 3
					continue
				}
			}
		}
		// Not a valid encoding, keep as-is
		result.WriteByte(s[i])
		i++
	}

	return result.String()
}

// isHex checks if a byte is a valid hexadecimal character
// Returns true for characters 0-9, a-f, A-F
// This is used to validate URL-encoded sequences like %2F
func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isValidHTTPVersion checks if the version string is a valid HTTP version
// Valid versions include: 1.0, 1.1, 2, 2.0, 3
func isValidHTTPVersion(version string) bool {
	switch version {
	case "1.0", "1.1", "2", "2.0", "3":
		return true
	default:
		// Also accept versions like 0.9 for legacy support
		if len(version) >= 3 && version[0] >= '0' && version[0] <= '9' &&
			version[1] == '.' && version[2] >= '0' && version[2] <= '9' {
			return true
		}
		return false
	}
}

// ExtractRequestTime parses request time from various sources in LogEntry
// Returns -1.0 if the request time is not available
func ExtractRequestTime(entry *LogEntry) float64 {
	// Check if ResponseTime is populated (primary source)
	if entry.ResponseTime > 0 {
		return entry.ResponseTime
	}

	// Check Extra fields for custom format
	if entry.Extra != nil {
		// Try float64 first
		if rt, ok := entry.Extra["request_time"].(float64); ok {
			return rt
		}

		// Try string parsing
		if rt, ok := entry.Extra["request_time"].(string); ok {
			if val, err := strconv.ParseFloat(rt, 64); err == nil {
				return val
			}
		}

		// Also check for alternative field names
		if rt, ok := entry.Extra["rt"].(float64); ok {
			return rt
		}
		if rt, ok := entry.Extra["rt"].(string); ok {
			if val, err := strconv.ParseFloat(rt, 64); err == nil {
				return val
			}
		}
	}

	return -1.0 // Indicates not available
}

// ExtractHTTPReferer extracts the HTTP referer from LogEntry
func ExtractHTTPReferer(entry *LogEntry) string {
	if entry.Extra != nil {
		if referer, ok := entry.Extra["http_referer"].(string); ok {
			return referer
		}
		if referer, ok := entry.Extra["referer"].(string); ok {
			return referer
		}
	}
	return "-"
}

// ExtractRemoteUser extracts the authenticated username from LogEntry
func ExtractRemoteUser(entry *LogEntry) string {
	if entry.Extra != nil {
		if user, ok := entry.Extra["remote_user"].(string); ok {
			return user
		}
		if user, ok := entry.Extra["user"].(string); ok {
			return user
		}
	}
	return "-"
}

// ExtractHTTPVersion extracts the HTTP protocol version from the request
func ExtractHTTPVersion(entry *LogEntry) string {
	// Try to extract from the request line
	if entry.Request != "" {
		// Validate request line format: METHOD PATH VERSION
		parts := strings.Split(entry.Request, " ")
		if len(parts) >= 3 {
			// The third part should be the HTTP version
			version := parts[2]
			// Validate HTTP version format
			if strings.HasPrefix(version, "HTTP/") && len(version) > 5 {
				// Check for valid version numbers (e.g., HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3)
				versionNum := version[5:]
				if isValidHTTPVersion(versionNum) {
					return version
				}
			}
		}
	}

	// Check extra fields
	if entry.Extra != nil {
		if version, ok := entry.Extra["http_version"].(string); ok {
			return version
		}
		if version, ok := entry.Extra["server_protocol"].(string); ok {
			return version
		}
	}

	return "HTTP/1.1" // Default
}

// ExtractUpstreamAddr extracts the upstream server address
func ExtractUpstreamAddr(entry *LogEntry) string {
	if entry.Extra != nil {
		if addr, ok := entry.Extra["upstream_addr"].(string); ok {
			return addr
		}
		if addr, ok := entry.Extra["upstream"].(string); ok {
			return addr
		}
	}
	return "-"
}

// ExtractUpstreamTime extracts the upstream response time
func ExtractUpstreamTime(entry *LogEntry) float64 {
	if entry.Extra != nil {
		// Try float64 first
		if rt, ok := entry.Extra["upstream_response_time"].(float64); ok {
			return rt
		}

		// Try string parsing
		if rt, ok := entry.Extra["upstream_response_time"].(string); ok {
			if val, err := strconv.ParseFloat(rt, 64); err == nil {
				return val
			}
		}

		// Alternative field names
		if rt, ok := entry.Extra["upstream_time"].(float64); ok {
			return rt
		}
		if rt, ok := entry.Extra["upstream_time"].(string); ok {
			if val, err := strconv.ParseFloat(rt, 64); err == nil {
				return val
			}
		}
	}
	return -1.0 // Indicates not available
}
