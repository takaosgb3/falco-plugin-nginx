# Changelog / 変更履歴

[English](#english) | [日本語](#日本語)

## English

All notable changes to the Falco nginx plugin binaries will be documented in this file.

## [v1.5.1] - 2026-01-12 - Falco Plugin Registry Registration (Latest)

### Changed
- **Plugin ID**: Changed from 999 (development) to 27 (official registry ID)
  - Required for Falco Plugin Registry registration
  - PR: https://github.com/falcosecurity/plugins/pull/1146

### Added
- **Extractable Fields Documentation**: Added 17 fields reference to README
  - `nginx.remote_addr`, `nginx.method`, `nginx.path`, `nginx.query_string`, etc.
  - Complete field list with types and descriptions

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Plugin ID: 27 (Falco Plugin Registry)
- No functional changes from v1.5.0

## [v1.5.0] - 2026-01-12 - E2E 300 Patterns Release

### Added
- **300 Attack Patterns**: E2E test coverage expanded from 65 to 300 patterns across 12 categories
  - SQL Injection: 79 patterns (Time-based, Boolean-based, Error-based SQLi)
  - XSS: 56 patterns (Reflected, DOM-based, Stored XSS)
  - Path Traversal: 50 patterns (Directory traversal, LFI, RFI)
  - Command Injection: 55 patterns (Shell, OS command injection)
  - LDAP Injection: 10 patterns (LDAP query manipulation)
  - SSTI: 10 patterns (Server-Side Template Injection)
  - NoSQL Injection: 7 patterns (MongoDB, Redis injection)
  - XXE: 8 patterns (XML External Entity attacks)
  - XPath Injection: 5 patterns (XPath query manipulation)
  - GraphQL Injection: 5 patterns (GraphQL query attacks)
  - API Security: 5 patterns (BOLA, authentication bypass)
  - Other: 10 patterns (Additional security patterns)
- **Rule Mapping Trend** (Issue #59): Allure Report now shows Rule Mapping trend in Categories Trend graph
- **Rule Mapping Validation** (Issue #53): Automated validation of expected_rule mappings

### Fixed
- **15 Rule Mapping Mismatches** (Issue #56): Resolved all rule name inconsistencies between test patterns and Falco rules
- **Negative Test Display** (Issue #58): Improved display for expected_detection: false patterns showing "Expected: Not Detected"
- **API_BOLA_001 Detection** (Issue #51): Added URL-encoded pattern support for API security detection

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Tested with Falco 0.42.1
- E2E tested on GitHub Actions (ubuntu-24.04)
- Full compatibility with nginx combined log format

## [v1.4.2] - 2025-12-06 - Plugin Version Display Fix

### Fixed
- **Plugin Version Display**: Fixed hardcoded version string from 0.3.0 to 1.4.2
  - `falco --list-plugins` now correctly shows version 1.4.2
  - No functional changes from v1.4.0

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Tested with Falco 0.42.1
- Binary SHA256: See release assets

## [v1.4.0] - 2025-12-06 - E2E 100% Detection Rate Release

### Added
- **E2E Tested Rules**: All 65 attack patterns validated with 100% detection rate
  - SQL Injection: 19/19 patterns (100%)
  - XSS: 11/11 patterns (100%)
  - Path Traversal: 20/20 patterns (100%)
  - Command Injection: 10/10 patterns (100%)
  - Emerging Threats: 5/5 patterns (100%)
- **Unified Rules File**: Single `nginx_rules.yaml` merged from 5 E2E-tested rule files
  - advanced_sqli_enhanced.yaml
  - advanced_xss_enhanced.yaml
  - advanced_traversal_enhanced.yaml
  - advanced_cmdi_enhanced.yaml
  - advanced_emerging_enhanced.yaml
- **Automated Rule Merging**: `merge-rules.sh` script for reproducible rule generation

### Changed
- Rules file now auto-generated with version header and source tracking
- Enhanced rule organization with category-based sections

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Tested with Falco 0.42.1
- E2E tested on Kubernetes environment (Run #130)
- Full compatibility with nginx combined log format

## [v1.3.0] - 2025-08-30 - Enhanced XSS Detection and Testing

### Added
- **Enhanced XSS Detection**: Comprehensive detection for all 7 XSS test patterns
  - Inline script injection patterns
  - Event handler injection (onclick, onerror, etc.)
  - JavaScript protocol URLs
  - Data URIs with JavaScript
  - HTML entity encoded attacks
  - Mixed case evasion patterns
  - URL-encoded XSS payloads
- **Improved Testing Infrastructure**: Enhanced test coverage and validation
  - Comprehensive unit tests for parser package
  - Enhanced test validation and coverage
- **Performance Optimizations**: Improved log parsing and event processing
  - Optimized regex patterns for better performance
  - Reduced memory allocation in hot paths
  - Enhanced buffer management

### Fixed
- XSS detection rules now properly cover all attack vectors
- Parser validation for invalid log formats
- Memory management improvements in parser package
- Go version compatibility (using Go 1.22)

### Changed
- Updated rule priorities for better alert categorization
- Improved rule descriptions with more detailed examples
- Enhanced documentation with v1.3.0 features

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Tested with Falco 0.41.3+
- Full compatibility with nginx combined log format
- Support for URL-encoded and HTML-encoded payloads

## [v1.2.12] - 2025-08-09 - Documentation and Installation Improvements

### Added
- Environment variables for non-interactive installation (`SETUP_TEST_CONTENT`, `SKIP_TEST_CONTENT`)
- Test script generation (`test-attacks.sh`) with correct URL-encoded commands
- Comprehensive Falco service detection (handles symlinks and multiple service types)
- Support for all Falco service variants (falco, falco-modern-bpf, falco-bpf)

### Fixed
- Documentation links to TROUBLESHOOTING.md (case sensitivity)
- Replaced deprecated `nginx.client_ip` with `nginx.remote_addr` in documentation
- URL-encoded attack examples now display correctly in HTML
- Environment variable passing with sudo (must be after sudo, not before)
- Falco service detection for EC2 environments where falco.service is a symlink
- Version numbers updated throughout documentation
- Repository URLs changed from private to public repo

### Changed
- Test content setup script now shows URL-encoded patterns correctly
- Install script provides accurate service-specific monitoring commands
- Documentation simplified to use generic eBPF terminology instead of EC2-specific

### Documentation
- Added clear instructions for identifying active Falco service
- Japanese translations updated for all new features
- Installation options table added for environment variables

## [v1.2.11] - 2025-08-09 - URL Encoding and Detection Fixes

### Fixed
- Added URL-encoded patterns (`%27`, `%3C`, etc.) to detection rules
- Fixed alert counting logic in release workflow
- Corrected Falco rule syntax (removed invalid operators)
- Expanded macros to avoid list operator issues

### Changed
- Rules now properly detect URL-encoded SQL injection and XSS attacks
- Command injection detection improved with encoded patterns

## [v1.2.1] - 2025-08-09 - Macro-based Command Injection Rules

### Added
- Macro-based command injection detection rules for better organization
- `nginx_cmdinj_raw_chars` macro for raw command characters
- `nginx_cmdinj_pctenc_chars` macro for URL-encoded characters
- `nginx_cmdinj_words` macro for common command patterns
- Debug rule for semicolon detection

### Known Issues
- **Command Injection Detection**: Still not working despite comprehensive macro-based rules. Even simple semicolon detection is failing. This suggests the `nginx.query_string` field may not be properly extracted by the plugin. Further investigation required.

## [v1.1.3] - 2025-08-09 - Documentation and Service Detection Improvements

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

## [v1.5.1] - 2026-01-12 - Falco Plugin Registry登録（最新）

### 変更
- **Plugin ID**: 999（開発用）から27（公式レジストリID）に変更
  - Falco Plugin Registry登録に必要
  - PR: https://github.com/falcosecurity/plugins/pull/1146

### 追加
- **抽出可能フィールドのドキュメント**: READMEに17フィールドのリファレンスを追加
  - `nginx.remote_addr`, `nginx.method`, `nginx.path`, `nginx.query_string` など
  - 型と説明を含む完全なフィールド一覧

### 技術詳細
- Falco Plugin SDK v0.8.1でビルド
- Plugin ID: 27（Falco Plugin Registry）
- v1.5.0から機能変更なし

## [v1.5.0] - 2026-01-12 - E2E 300パターンリリース

### 追加
- **300攻撃パターン**: E2Eテストカバレッジを65から300パターン、12カテゴリに拡大
  - SQLインジェクション: 79パターン（時間ベース、ブールベース、エラーベースSQLi）
  - XSS: 56パターン（Reflected、DOM-based、Stored XSS）
  - パストラバーサル: 50パターン（ディレクトリトラバーサル、LFI、RFI）
  - コマンドインジェクション: 55パターン（シェル、OSコマンドインジェクション）
  - LDAPインジェクション: 10パターン（LDAPクエリ操作）
  - SSTI: 10パターン（サーバーサイドテンプレートインジェクション）
  - NoSQLインジェクション: 7パターン（MongoDB、Redisインジェクション）
  - XXE: 8パターン（XML外部エンティティ攻撃）
  - XPathインジェクション: 5パターン（XPathクエリ操作）
  - GraphQLインジェクション: 5パターン（GraphQLクエリ攻撃）
  - APIセキュリティ: 5パターン（BOLA、認証バイパス）
  - その他: 10パターン（追加セキュリティパターン）
- **Rule Mappingトレンド**（Issue #59）: AllureレポートにRule Mappingトレンドグラフを追加
- **Rule Mapping検証**（Issue #53）: expected_ruleマッピングの自動検証

### 修正
- **15件のRule Mappingミスマッチ**（Issue #56）: テストパターンとFalcoルール間のルール名不整合をすべて解決
- **ネガティブテスト表示**（Issue #58）: expected_detection: falseパターンの表示を改善し「Expected: Not Detected」を表示
- **API_BOLA_001検出**（Issue #51）: APIセキュリティ検出のURLエンコードパターンサポートを追加

### 技術詳細
- Falco Plugin SDK v0.8.1でビルド
- Falco 0.42.1でテスト済み
- GitHub Actions（ubuntu-24.04）でE2Eテスト済み
- nginx combinedログフォーマットとの完全な互換性

## [v1.4.2] - 2025-12-06 - プラグインバージョン表示修正

### 修正
- **プラグインバージョン表示**: ハードコードされたバージョン文字列を0.3.0から1.4.2に修正
  - `falco --list-plugins`でバージョン1.4.2が正しく表示されるようになりました
  - v1.4.0からの機能変更はありません

### 技術詳細
- Falco Plugin SDK v0.8.1でビルド
- Falco 0.42.1でテスト済み
- バイナリSHA256: リリースアセットを参照

## [v1.4.0] - 2025-12-06 - E2E 100%検出率リリース

### 追加
- **E2Eテスト済みルール**: 65の攻撃パターンすべてが100%検出率で検証済み
  - SQLインジェクション: 19/19パターン (100%)
  - XSS: 11/11パターン (100%)
  - パストラバーサル: 20/20パターン (100%)
  - コマンドインジェクション: 10/10パターン (100%)
  - 新興脅威: 5/5パターン (100%)
- **統一ルールファイル**: 5つのE2Eテスト済みルールファイルから統合された単一の`nginx_rules.yaml`
  - advanced_sqli_enhanced.yaml
  - advanced_xss_enhanced.yaml
  - advanced_traversal_enhanced.yaml
  - advanced_cmdi_enhanced.yaml
  - advanced_emerging_enhanced.yaml
- **自動ルールマージ**: 再現可能なルール生成のための`merge-rules.sh`スクリプト

### 変更
- ルールファイルにバージョンヘッダーとソース追跡が自動生成
- カテゴリベースのセクションによるルール編成の強化

### 技術詳細
- Falco Plugin SDK v0.8.1でビルド
- Falco 0.42.1でテスト済み
- Kubernetes環境でE2Eテスト済み (Run #130)
- nginx combinedログフォーマットとの完全な互換性

## [v1.3.0] - 2025-08-30 - XSS検出強化とテスト改善

### 追加
- **XSS検出の強化**: 7つのXSSテストパターンすべてに対する包括的な検出
  - インラインスクリプトインジェクションパターン
  - イベントハンドラーインジェクション（onclick、onerrorなど）
  - JavaScriptプロトコルURL
  - JavaScriptを含むデータURI
  - HTMLエンティティエンコード攻撃
  - 大文字小文字混在の回避パターン
  - URLエンコードされたXSSペイロード
- **テストインフラの改善**: テストカバレッジと検証の強化
  - パーサーパッケージの包括的なユニットテスト
  - テスト検証とカバレッジの強化
- **パフォーマンス最適化**: ログ解析とイベント処理の改善
  - パフォーマンス向上のための正規表現パターンの最適化
  - ホットパスでのメモリ割り当ての削減
  - バッファ管理の強化

### 修正
- XSS検出ルールがすべての攻撃ベクトルを適切にカバー
- 無効なログフォーマットに対するパーサー検証
- パーサーパッケージのメモリ管理改善
- Goバージョン互換性（Go 1.22を使用）

### 変更
- より良いアラート分類のためのルール優先度更新
- より詳細な例を含むルール説明の改善
- v1.3.0機能によるドキュメントの強化

### 技術詳細
- Falco Plugin SDK v0.8.1でビルド
- Falco 0.41.3+でテスト済み
- nginx combinedログフォーマットとの完全な互換性
- URLエンコードおよびHTMLエンコードペイロードのサポート

## [v1.2.12] - 2025-08-09 - ドキュメントとインストール改善

### 追加
- 非対話型インストール用環境変数（`SETUP_TEST_CONTENT`、`SKIP_TEST_CONTENT`）
- 正しいURLエンコードコマンドを含むテストスクリプト生成（`test-attacks.sh`）
- 包括的なFalcoサービス検出（シンボリックリンクと複数サービスタイプに対応）
- すべてのFalcoサービスバリアントのサポート（falco、falco-modern-bpf、falco-bpf）

### 修正
- TROUBLESHOOTING.mdへのドキュメントリンク（大文字小文字の区別）
- ドキュメント内の非推奨`nginx.client_ip`を`nginx.remote_addr`に置換
- HTMLでURLエンコード攻撃例が正しく表示されるよう修正
- sudoでの環境変数渡し（sudoの前ではなく後に配置）
- EC2環境でfalco.serviceがシンボリックリンクの場合のFalcoサービス検出
- ドキュメント全体のバージョン番号更新
- リポジトリURLをプライベートからパブリックに変更

### 変更
- テストコンテンツセットアップスクリプトがURLエンコードパターンを正しく表示
- インストールスクリプトが正確なサービス固有の監視コマンドを提供
- EC2固有ではなく一般的なeBPF用語を使用するようドキュメントを簡素化

### ドキュメント
- アクティブなFalcoサービスを特定するための明確な指示を追加
- すべての新機能の日本語翻訳を更新
- 環境変数のインストールオプション表を追加

## [v1.2.11] - 2025-08-09 - URLエンコーディングと検出修正

### 修正
- URLエンコードパターン（`%27`、`%3C`など）を検出ルールに追加
- リリースワークフローのアラートカウントロジックを修正
- Falcoルール構文を修正（無効なオペレータを削除）
- リストオペレータの問題を回避するためマクロを展開

### 変更
- URLエンコードされたSQLインジェクションとXSS攻撃を正しく検出
- エンコードパターンでコマンドインジェクション検出を改善

## [v0.4.2] - 2025-08-06 - Falco 0.41.x 互換性修正

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