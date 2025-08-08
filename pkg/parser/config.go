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

// Config holds the parser configuration options.
// It defines the log format to parse and various security
// detection settings that control how the parser analyzes
// log entries for potential threats.
type Config struct {
	// LogFormat is the nginx log format (combined, common, or custom)
	LogFormat string

	// CustomFormat is the custom log format string
	CustomFormat string

	// SecurityPatterns enables security pattern detection
	SecurityPatterns bool

	// LargeResponseThreshold is the threshold for detecting large responses (in bytes)
	LargeResponseThreshold int
}
