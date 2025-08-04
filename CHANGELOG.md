# Changelog

All notable changes to the Falco nginx plugin binaries will be documented in this file.

## [2025-08-04] - NULL Pointer Fix (Latest)

### Fixed
- **Critical fix**: Added NULL pointer check in plugin_init rc parameter
- Prevents segmentation fault when Falco calls plugin_init with NULL rc
- Binary SHA256: `23e28085a4f1cb83e8b63e47b1cfbf95610b249f65f27fd6ab642c3bf5cc9ab8`

### Technical Details
- plugin_init now checks if rc parameter is NULL before dereferencing
- Fixes 'plugin handle or get_last_error function not defined' error in Falco
- Maintains all previous fixes (CGO pointer safety, Linux ELF format)

## [2025-08-04] - Linux Binary with CGO Fix

### Fixed
- **Critical fix**: Resolved CGO "unpinned Go pointer" panic that was preventing plugin initialization
- Built on Linux environment to produce proper ELF binary format
- Plugin now uses ID-based state management instead of returning Go pointers to C code
- Binary SHA256: `a98cd2d8dffc0634d03638c149ae9f58b93df289b5acff2ebfa6ab4f64b995c0`

### Technical Details
- Changed from direct pointer return to ID-based state tracking
- Prevents runtime panic: "cgo result is unpinned Go pointer or points to unpinned Go pointer"
- Built using GitHub Actions self-hosted Linux runner
- Plugin now successfully initializes on Ubuntu 22.04 and other Linux systems
- Fixes "invalid ELF header" error from previous macOS-built binaries

## [2025-08-04] - CGO Pointer Safety Fix

### Fixed
- **Critical fix**: Resolved CGO "unpinned Go pointer" panic that was preventing plugin initialization
- Plugin now uses ID-based state management instead of returning Go pointers to C code
- Binary SHA256: `289370c8b161826e036e46454023dbd263eec01aabc3e4cc3f7601113b2fa7ec`

### Technical Details
- Changed from direct pointer return to ID-based state tracking
- Prevents runtime panic: "cgo result is unpinned Go pointer or points to unpinned Go pointer"
- Plugin now successfully initializes on Ubuntu 22.04 and other Linux systems

## [2025-08-04] - Initialization Fix

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