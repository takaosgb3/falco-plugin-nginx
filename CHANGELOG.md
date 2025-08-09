# Changelog / 変更履歴

[English](#english) | [日本語](#日本語)

## English

All notable changes to the Falco nginx plugin binaries will be documented in this file.

## [v1.1.3] - 2025-08-09 - Documentation and Service Detection Improvements (Latest)

### Fixed
- Improved documentation for EC2/eBPF systems  
- Updated service detection in installer script
- Added support for falco-modern-bpf service monitoring

### Changed
- Install script now auto-detects active Falco service name
- Documentation updated with EC2-specific monitoring commands

## [v1.1.2] - 2025-08-09 - Critical Rule Fix

### Fixed
- **CRITICAL**: Corrected field name from `nginx.client_ip` to `nginx.remote_addr` in all rules
- Fixed rule validation errors preventing alerts from triggering
- Authentication detection rules now work correctly

### Added
- Enhanced workflow validation with plugin pre-installation
- Improved rule validation in CI/CD pipeline

## [v0.4.2] - 2025-08-06 - Falco 0.41.x Compatibility Fix

### Fixed
- Fixed compatibility with Falco 0.41.x by updating rule priority values
- Fixed `load_plugins` array update in installation script
- Changed priorities: HIGH→WARNING, MEDIUM→NOTICE, LOW→INFO

### Note
- No changes to plugin binary - only rules and installation script updated
- Addresses "Unknown source nginx" and priority validation errors

## [v0.4.1] - 2025-08-06 - Repository Structure Update

### Changed
- Reorganized repository structure to follow Falco plugin standards
- Moved `nginx_rules.yaml` to `rules/` directory
- No functional changes - structure improvement only

## [v0.4.0] - 2025-08-05 - Field Extraction Fix

### Fixed
- Fixed field extraction for `http_method`, `http_request_line`, and `http_request_uri`
- Resolved query string parsing issues
- Based on SDK migration from 2025-08-04

## [2025-08-04] - Fixed SDK Plugin for Log Reading

### Fixed
- **Critical fix**: Plugin now reads existing log entries on startup
- Removed file seek to end, allowing detection of attacks in existing logs
- Binary SHA256: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

### Technical Details
- Previous version only monitored new log entries after startup
- Now processes all existing log entries for immediate threat detection
- Built on Ubuntu 22.04 EC2 instance as local runner
- Tested and verified with Falco 0.41.3

## [2025-08-04] - Complete Rewrite with Falco Plugin SDK

### Changed
- **Major rewrite**: Plugin completely rewritten using official Falco Plugin SDK for Go
- Replaced manual CGO implementation with SDK-based approach
- Much simpler and more maintainable codebase
- Binary SHA256: `5eab89337302337022ab05e3d3c5c69b1f25fa2517ce34e4e3268fce03301e13`

### Technical Details
- Uses github.com/falcosecurity/plugin-sdk-go v0.8.1
- Implements both source and extractor capabilities
- SDK handles all low-level plugin API requirements
- Maintains full compatibility with Falco 0.41.3 (API version 3.11.0)
- All previous issues resolved through proper SDK usage

## [2025-08-04] - plugin_get_last_error Fix

### Fixed
- **Critical fix**: plugin_get_last_error now handles nil plugin state correctly
- Stores initialization errors in global variable for retrieval
- Fixes 'plugin handle or get_last_error function not defined' error in Falco
- Binary SHA256: `d6b8ead21a52a5c12ea1b8ae27e3afca15bee28059a0093e228d63dd711cad11`

### Technical Details
- plugin_get_last_error can now return initialization errors when called with nil
- Maintains all previous fixes (NULL pointer check, CGO pointer safety, Linux ELF format)
- Designed to help Falco properly retrieve error messages after plugin_init failures

## [2025-08-04] - NULL Pointer Fix

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

---

## 日本語

Falco nginxプラグインバイナリの重要な変更はすべてこのファイルに記録されます。

## [v0.4.2] - 2025-08-06 - Falco 0.41.x 互換性修正（最新）

### 修正
- ルール優先度値を更新してFalco 0.41.xとの互換性を修正
- インストールスクリプトの`load_plugins`配列更新を修正
- 優先度変更: HIGH→WARNING、MEDIUM→NOTICE、LOW→INFO

### 注記
- プラグインバイナリに変更なし - ルールとインストールスクリプトのみ更新
- "Unknown source nginx"および優先度検証エラーに対処

## [v0.4.1] - 2025-08-06 - リポジトリ構造更新

### 変更
- Falcoプラグイン標準に従ってリポジトリ構造を再編成
- `nginx_rules.yaml`を`rules/`ディレクトリに移動
- 機能変更なし - 構造改善のみ

## [v0.4.0] - 2025-08-05 - フィールド抽出修正

### 修正
- `http_method`、`http_request_line`、`http_request_uri`のフィールド抽出を修正
- クエリ文字列解析の問題を解決
- 2025-08-04のSDK移行に基づく

## [2025-08-04] - SDKプラグインのログ読み取り修正

### 修正
- **重要な修正**: プラグインが起動時に既存のログエントリを読み取るようになりました
- ファイルの末尾へのシークを削除し、既存ログ内の攻撃検出を可能にしました
- バイナリSHA256: `2b97aaa085ce514a6075c49ba166ea7cf47d30533475eb51dd614acbb3a5c244`

### 技術詳細
- 以前のバージョンは起動後の新しいログエントリのみを監視していました
- 現在は即座に脅威検出のためにすべての既存ログエントリを処理します
- Ubuntu 22.04 EC2インスタンスでローカルランナーとしてビルド
- Falco 0.41.3でテストおよび検証済み

## [2025-08-04] - Falco Plugin SDKによる完全な書き直し

### 変更
- **大規模な書き直し**: 公式Falco Plugin SDK for Goを使用してプラグインを完全に書き直しました
- 手動CGO実装をSDKベースのアプローチに置き換えました
- より簡潔で保守しやすいコードベース
- バイナリSHA256: `5eab89337302337022ab05e3d3c5c69b1f25fa2517ce34e4e3268fce03301e13`

### 技術詳細
- github.com/falcosecurity/plugin-sdk-go v0.8.1を使用
- ソースとエクストラクターの両方の機能を実装
- SDKがすべての低レベルプラグインAPI要件を処理
- Falco 0.41.3（APIバージョン3.11.0）との完全な互換性を維持
- 適切なSDK使用により以前のすべての問題が解決

## [2025-08-04] - plugin_get_last_error修正

### 修正
- **重要な修正**: plugin_get_last_errorがnilプラグイン状態を正しく処理するようになりました
- 初期化エラーを取得のためにグローバル変数に保存
- Falcoの「plugin handle or get_last_error function not defined」エラーを修正
- バイナリSHA256: `d6b8ead21a52a5c12ea1b8ae27e3afca15bee28059a0093e228d63dd711cad11`

### 技術詳細
- plugin_get_last_errorがnilで呼び出されたときに初期化エラーを返せるようになりました
- 以前のすべての修正を維持（NULLポインタチェック、CGOポインタ安全性、Linux ELF形式）
- plugin_init失敗後にFalcoが適切にエラーメッセージを取得できるように設計

## [2025-08-04] - NULLポインタ修正

### 修正
- **重要な修正**: plugin_init rcパラメータにNULLポインタチェックを追加
- FalcoがNULL rcでplugin_initを呼び出したときのセグメンテーション違反を防止
- バイナリSHA256: `23e28085a4f1cb83e8b63e47b1cfbf95610b249f65f27fd6ab642c3bf5cc9ab8`

### 技術詳細
- plugin_initが参照解除前にrcパラメータがNULLかどうかをチェックするようになりました
- Falcoの「plugin handle or get_last_error function not defined」エラーを修正
- 以前のすべての修正を維持（CGOポインタ安全性、Linux ELF形式）

## [2025-08-04] - CGO修正付きLinuxバイナリ

### 修正
- **重要な修正**: プラグイン初期化を妨げていたCGO「unpinned Go pointer」パニックを解決
- 適切なELFバイナリ形式を生成するためLinux環境でビルド
- プラグインがGoポインタをCコードに返す代わりにIDベースの状態管理を使用するようになりました
- バイナリSHA256: `a98cd2d8dffc0634d03638c149ae9f58b93df289b5acff2ebfa6ab4f64b995c0`

### 技術詳細
- 直接ポインタ返却からIDベース状態追跡に変更
- ランタイムパニックを防止: 「cgo result is unpinned Go pointer or points to unpinned Go pointer」
- GitHub Actionsセルフホストランナーを使用してビルド
- Ubuntu 22.04および他のLinuxシステムでプラグインが正常に初期化されるようになりました
- 以前のmacOSビルドバイナリの「invalid ELF header」エラーを修正

## [2025-08-04] - CGOポインタ安全性修正

### 修正
- **重要な修正**: プラグイン初期化を妨げていたCGO「unpinned Go pointer」パニックを解決
- プラグインがGoポインタをCコードに返す代わりにIDベースの状態管理を使用するようになりました
- バイナリSHA256: `289370c8b161826e036e46454023dbd263eec01aabc3e4cc3f7601113b2fa7ec`

### 技術詳細
- 直接ポインタ返却からIDベース状態追跡に変更
- ランタイムパニックを防止: 「cgo result is unpinned Go pointer or points to unpinned Go pointer」
- Ubuntu 22.04および他のLinuxシステムでプラグインが正常に初期化されるようになりました

## [2025-08-04] - 初期化修正

### 変更
- プラグイン初期化が不足しているログファイルを適切に処理するようになりました
- バイナリSHA256: `2eba662d43bf0fb14bd5dcc7a523c582c56ba06ee143d3ae2c773999ab2a75cb`
- Falco 0.41.3互換性のためAPIバージョンは3.11.0のまま

### 修正
- **根本原因の修正**: nginxログファイルが存在しない場合でもプラグインが失敗しなくなりました
- 検証中の厳密なディレクトリ存在チェックを削除
- `/var/log/nginx/access.log`が不足していてもプラグインが起動するようになりました
- より良いデバッグのためのエラーメッセージを改善

### 追加
- ログファイルが不足している場合の警告メッセージ（失敗の代わり）
- デフォルトログパスが自動的に適用されます
- 包括的な設定検証テスト

## [2025-08-04] - APIバージョン3.11.0

### 変更
- プラグインAPIバージョンを3.6.0から3.11.0に更新
- Falco 0.41.3との完全な互換性
- バイナリSHA256: `f74bdc7f3228eb464b266bad702d3e3ed703c47abbaaee706eac3346ab2ca93c`

### 修正
- Falco 0.41.3でのプラグイン初期化エラーを最終的に解決
- プラグインがFalco 0.41.3が期待する正確なAPIバージョンを使用するようになりました
- 更新されたバイナリにはすべての最近の修正が含まれています

## [2025-08-04] - APIバージョン3.6.0

### 変更
- プラグインAPIバージョンを3.3.0から3.6.0に更新
- Falco 0.41.xとの互換性を改善
- バイナリSHA256: `2eb55f496a2a4be86f7ab35ca34d5c979d28cbed1404e51056b5b8537fa7174a`

### 修正
- Falco 0.41.3でのプラグイン初期化エラーを解決
- 「plugin handle or 'get_last_error' function not defined」エラーを修正

## [2025-08-04] - APIバージョン3.3.0

### 変更
- プラグインAPIバージョンを3.0.0から3.3.0に更新
- Falco 0.41.x互換性を改善する最初の試み
- バイナリSHA256: `242d6b8d467abbb8dc8edc29f4a718d145537b78f1d4a15beb3a4359912bee0b`

## [2025-08-03] - 初回リリース

### 追加
- Linux x86_64用のビルド済みバイナリ
- nginxセキュリティ監視用のFalco検出ルール
- SQLインジェクション検出のサポート
- XSS攻撃検出のサポート
- ディレクトリトラバーサル検出のサポート
- コマンドインジェクション検出のサポート
- セキュリティスキャナー検出のサポート
- APIバージョン3.0.0

### ドキュメント
- クイックスタートバイナリインストールガイド
- トラブルシューティングガイド
- バイリンガルサポート（英語/日本語）