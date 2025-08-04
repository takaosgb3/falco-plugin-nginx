# Changelog

All notable changes to the Falco nginx plugin binaries will be documented in this file.

## [2025-08-04] - Initialization Fix (Latest)

### Changed
- Plugin initialization now handles missing log files gracefully
- Binary SHA256: `2eba662d43bf0fb14bd5dcc7a523c582c56ba06ee143d3ae2c773999ab2a75cb`
- API Version remains 3.11.0 for Falco 0.41.3 compatibility

### Fixed
- **Root cause fix**: Plugin no longer fails when nginx log files don't exist
- Removed strict directory existence check during validation
- Plugin now starts even if `/var/log/nginx/access.log` is missing
- Improved error messages for better debugging

### Added
- Warning messages when log files are missing (instead of failing)
- Default log paths are applied automatically
- Comprehensive config validation tests

## [2025-08-04] - API Version 3.11.0

### Changed
- Updated plugin API version from 3.6.0 to 3.11.0
- Full compatibility with Falco 0.41.3
- Binary SHA256: `f74bdc7f3228eb464b266bad702d3e3ed703c47abbaaee706eac3346ab2ca93c`

### Fixed
- Finally resolved plugin initialization errors with Falco 0.41.3
- Plugin now uses the exact API version that Falco 0.41.3 expects
- Updated binary includes all recent fixes

## [2025-08-04] - API Version 3.6.0

### Changed
- Updated plugin API version from 3.3.0 to 3.6.0
- Improved compatibility with Falco 0.41.x
- Binary SHA256: `2eb55f496a2a4be86f7ab35ca34d5c979d28cbed1404e51056b5b8537fa7174a`

### Fixed
- Resolved plugin initialization errors with Falco 0.41.3
- Fixed "plugin handle or 'get_last_error' function not defined" error

## [2025-08-04] - API Version 3.3.0

### Changed
- Updated plugin API version from 3.0.0 to 3.3.0
- First attempt to improve Falco 0.41.x compatibility
- Binary SHA256: `242d6b8d467abbb8dc8edc29f4a718d145537b78f1d4a15beb3a4359912bee0b`

## [2025-08-03] - Initial Release

### Added
- Pre-built binary for Linux x86_64
- Falco detection rules for nginx security monitoring
- Support for SQL injection detection
- Support for XSS attack detection
- Support for directory traversal detection
- Support for command injection detection
- Support for security scanner detection
- API version 3.0.0

### Documentation
- Quick start binary installation guide
- Troubleshooting guide
- Bilingual support (English/Japanese)