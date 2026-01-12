# Release v1.5.0 Requirements Document

## Document Info

| Item | Value |
|------|-------|
| Version | v1.6.0 |
| Created | 2026-01-12 |
| Updated | 2026-01-12 |
| Status | Draft |
| Author | Claude Code |

---

## 1. Executive Summary

### 1.1 Purpose

300の攻撃パターンによるE2Eテストが完了したため、Falco nginx プラグインのリリース v1.5.0 を実施します。

### 1.2 Release Highlights

| Feature | Description |
|---------|-------------|
| 300 Attack Patterns | E2Eテストパターンを65から300に拡大 |
| Rule Mapping Trend | Allure ReportにRule Mapping Trendグラフを追加 (Issue #59) |
| Rule Mapping Fix | 15件のRule Mapping Mismatchを解決 (Issue #56) |
| Negative Test Support | expected_detection: false パターンの表示改善 (Issue #58) |

### 1.3 Version Decision

**New Version: v1.5.0**

セマンティックバージョニングに従い：
- **MAJOR (1)**: 変更なし（後方互換性維持）
- **MINOR (4→5)**: 新機能追加（300パターン対応、Rule Mapping Trend）
- **PATCH**: 0にリセット

前バージョン: v1.4.4 (internal) / v1.4.2 (public release)

---

## 2. Background

### 2.1 Current State

| Component | Version | Status |
|-----------|---------|--------|
| Private Repo (main) | v1.4.4 | 最新のコミット: 4e67e2e3 |
| Public Repo (release) | v1.4.2 | 2025-12-06リリース |
| E2E Tests | 300 patterns | 全パターン成功 |
| Rule Mapping | 100% Match | Issue #56完了 |

### 2.2 Recent Changes Since v1.4.2

```
4e67e2e3 feat(e2e): Add Rule Mapping Trend to Allure Report (#61)
067938c9 fix(e2e): Improve display of expected_detection: false patterns (#60)
2bd0c794 fix: Resolve 15 Rule Mapping Mismatches (#57)
c43cda94 feat(e2e): Add rule mapping validation (Issue #53) (#54)
c6cf72a3 fix: Add URL-encoded patterns for API_BOLA_001 detection (#52)
df1f4651 feat: Expand E2E test patterns to 300 (Phase 4) (#50)
8598d39c fix(e2e): Improve rule mapping accuracy from 36% to 97%+ (#48)
```

### 2.3 Completed Issues

| Issue | Title | PR | Status |
|-------|-------|-----|--------|
| #49 | Expand E2E test patterns to 300 | #50 | ✅ Closed |
| #51 | API_BOLA_001 URL Encoding | #52 | ✅ Closed |
| #53 | Rule Mapping Validation | #54 | ✅ Closed |
| #56 | Resolve Rule Mapping Mismatches | #57 | ✅ Closed |
| #58 | expected_detection: false display | #60 | ✅ Closed |
| #59 | Rule Mapping Trend Graph | #61 | ✅ Closed |

---

## 3. Functional Requirements

### FR-001: Plugin Binary

プラグインバイナリが以下の要件を満たすこと：

| Requirement | Specification |
|-------------|---------------|
| Format | ELF 64-bit LSB shared object |
| Platform | Linux x86_64 |
| Version | 1.5.0 |
| Build Method | GitHub Actions Workflow |

### FR-002: Falco Rules

ルールファイルが以下の要件を満たすこと：

| Requirement | Specification |
|-------------|---------------|
| File Name | nginx_rules.yaml |
| Categories | SQL Injection, XSS, Path Traversal, Command Injection, Emerging Threats |
| Detection Rate | 100% for all 300 E2E patterns |
| Falco Version | 0.42.1+ compatible |

### FR-003: E2E Test Patterns

E2Eテストパターンが以下を含むこと：

| Category | Count | Files |
|----------|-------|-------|
| SQL Injection | 79 patterns | sqli_patterns.json |
| XSS | 56 patterns | xss_patterns.json |
| Path Traversal | 50 patterns | path_patterns.json |
| Command Injection | 55 patterns | cmdinj_patterns.json |
| LDAP Injection | 10 patterns | ldap_patterns.json |
| SSTI | 10 patterns | ssti_patterns.json |
| NoSQL Injection | 7 patterns | nosql_extended_patterns.json |
| XXE | 8 patterns | xxe_patterns.json |
| XPath Injection | 5 patterns | xpath_patterns.json |
| GraphQL Injection | 5 patterns | graphql_patterns.json |
| API Security | 5 patterns | api_security_patterns.json |
| Other | 10 patterns | other_patterns.json |
| **Total** | **300 patterns** | **12 files** |

### FR-004: Documentation

以下のドキュメントが更新されていること：

#### FR-004.1: CHANGELOG.md

| Requirement | Specification |
|-------------|---------------|
| File | CHANGELOG.md |
| Content | v1.5.0セクション追加（英語・日本語） |
| Details | 300パターン対応、Issue #56/#58/#59の修正内容 |

#### FR-004.2: README.md（公開リポジトリ）

| File | Section | Current | Target |
|------|---------|---------|--------|
| README.md | E2E Security Tests (EN, Line ~110) | 65 attack patterns | 300 attack patterns |
| README.md | E2Eセキュリティテスト (JA, Line ~231) | 65攻撃パターン | 300攻撃パターン |
| README.md | Test Coverage Table (EN/JA) | 5 categories, 65 patterns | 12 categories, 300 patterns |

**重要**: Test Coverage Tableは単なる数値更新ではなく、**テーブル構造自体の更新**が必要：

現在のテーブル（5カテゴリ）:
```markdown
| Category | Patterns | Description |
|----------|----------|-------------|
| SQL Injection | 19 | Time-based, Boolean-based blind SQLi |
| XSS | 11 | DOM-based, Reflected XSS attacks |
| Path Traversal | 20 | Directory traversal, absolute path access |
| Command Injection | 10 | Shell command injection patterns |
| Other | 5 | NoSQL/MongoDB injection |
```

更新後のテーブル（12カテゴリ）:
```markdown
| Category | Patterns | Description |
|----------|----------|-------------|
| SQL Injection | 79 | Time-based, Boolean-based, Error-based SQLi |
| XSS | 56 | Reflected, DOM-based, Stored XSS attacks |
| Path Traversal | 50 | Directory traversal, LFI, RFI patterns |
| Command Injection | 55 | Shell, OS command injection patterns |
| LDAP Injection | 10 | LDAP query manipulation |
| SSTI | 10 | Server-Side Template Injection |
| NoSQL Injection | 7 | MongoDB, Redis injection patterns |
| XXE | 8 | XML External Entity attacks |
| XPath Injection | 5 | XPath query manipulation |
| GraphQL Injection | 5 | GraphQL query attacks |
| API Security | 5 | BOLA, authentication bypass |
| Other | 10 | Additional security patterns |
```

#### FR-004.3: e2e/README.md

| File | Section | Current | Target |
|------|---------|---------|--------|
| e2e/README.md | Directory Structure (Line ~37) | 古いパターン数 | 12ファイル構成 |
| e2e/README.md | Test Categories (EN, Line ~56) | Total: 65 | Total: 300 |
| e2e/README.md | テストカテゴリ (JA, Line ~214) | 合計: 65 | 合計: 300 |
| e2e/README.md | Workflow Steps (Line ~145) | 65 patterns | 300 patterns |

#### FR-004.4: docs/*.md Version Updates

以下のドキュメントのバージョン参照を更新すること：

| File | Lines | Current | Target |
|------|-------|---------|--------|
| docs/rules.md | 3 | Version: 1.4.2 | Version: 1.5.0 |
| docs/NGINX_RULES_REFERENCE.md | 5 | Version: 1.4.2 | Version: 1.5.0 |
| docs/installation.md | 12, 15, 19 | v1.4.2 | v1.5.0 |
| docs/QUICK_START_BINARY_INSTALLATION.md | 36, 39, 46, 234, 237, 244 | v1.4.2 | v1.5.0 |
| docs/E2E_REPORT_GUIDE.md | 複数箇所 | 65 patterns, 5 categories | 300 patterns, 12 categories |
| docs/E2E_REPORT_GUIDE_JA.md | 複数箇所 | 65パターン, 5カテゴリ | 300パターン, 12カテゴリ |

**E2E_REPORT_GUIDE.md/JA の詳細更新箇所**:

1. **Overview セクション** (Line 22/20):
   - 「5 categories」→「12 categories」
   - 「65 attack patterns」→「300 attack patterns」

2. **Key Metrics テーブル** (Line 57/55):
   - 「(65)」→「(300)」

3. **Category Breakdown テーブル** (Lines 93-99):
   ```markdown
   # 現在（古い）
   | **SQLI** | 19 | SQL Injection attacks |
   | **XSS** | 11 | Cross-Site Scripting attacks |
   | **PATH** | 20 | Path Traversal attacks |
   | **CMDINJ** | 10 | Command Injection attacks |
   | **OTHER** | 5 | NoSQL/MongoDB injection attacks |

   # 更新後（12カテゴリ）
   | **SQLI** | 79 | SQL Injection attacks |
   | **XSS** | 56 | Cross-Site Scripting attacks |
   | **PATH** | 50 | Path Traversal attacks |
   | **CMDINJ** | 55 | Command Injection attacks |
   | **LDAP** | 10 | LDAP Injection attacks |
   | **SSTI** | 10 | Server-Side Template Injection |
   | **NOSQL** | 7 | NoSQL Injection attacks |
   | **XXE** | 8 | XML External Entity attacks |
   | **XPATH** | 5 | XPath Injection attacks |
   | **GRAPHQL** | 5 | GraphQL Injection attacks |
   | **API** | 5 | API Security attacks |
   | **OTHER** | 10 | Other attack patterns |
   ```

4. **Status Indicators** (Line 103/101):
   - 「Green (65)」→「Green (300)」

5. **Test Categories セクション** (Lines 239-280):
   - 各カテゴリのパターン数を更新
   - 新カテゴリ（LDAP, SSTI, NoSQL, XXE, XPath, GraphQL, API）を追加

> **注意**: `PLUGIN_VERSION=latest`を使用している箇所は更新不要（自動的に最新を取得）

#### FR-004.5: VERSION情報

- plugin/main.go内のバージョン定数が1.5.0であること

---

## 4. Non-Functional Requirements

### NFR-001: Build Reproducibility

- 必ずGitHub Actions Workflowでビルド
- 手動ビルドは禁止
- ローカルビルドは検証用のみ

### NFR-002: Binary Verification

リリースバイナリは以下を満たすこと：

```bash
# Must show ELF 64-bit, not Mach-O
file libfalco-nginx-plugin-linux-amd64.so
# Expected: ELF 64-bit LSB shared object, x86-64

# Size should be approximately 4MB
ls -la libfalco-nginx-plugin-linux-amd64.so
# Expected: ~4MB
```

### NFR-003: Runner Version Stability

ワークフローの安定性を確保するため、バージョン固定のランナーを使用：

```yaml
# RECOMMENDED: バージョン固定（環境の安定性を保証）
runs-on: ubuntu-24.04

# NOT RECOMMENDED: バージョンドリフトのリスク
runs-on: ubuntu-latest  # GitHubが随時更新するため環境が予期せず変更される
```

> **注意**: 公開リポジトリ（Public Repository）ではGitHub-hosted runnerの使用は無料です。
> `ubuntu-latest`の問題は料金ではなく、**バージョンドリフト**（依存ライブラリの非互換、ビルド失敗等）のリスクです。

---

## 5. Past Failure Patterns (Lessons Learned)

> **重要**: 過去に発生した問題パターンを理解し、同じ失敗を繰り返さないこと

### Pattern #1: macOS Binary on Linux

| Item | Description |
|------|-------------|
| Issue | macOSでビルドしたバイナリをLinux用としてリリース |
| Symptom | `file` コマンドで「Mach-O 64-bit」と表示 |
| Prevention | 必ずワークフローでビルド、`file`コマンドで検証 |
| Reference | CLAUDE.md「ビルドとリリースの鉄則」セクション |

### Pattern #2: Manual Release Creation

| Item | Description |
|------|-------------|
| Issue | 手動で`gh release create`を実行 |
| Symptom | 検証されていないバイナリがリリースされる |
| Prevention | 必ずリリースワークフローを使用 |
| Reference | CLAUDE.md「リリースプロセス - 絶対にこれに従うこと」 |

### Pattern #3: ubuntu-latest Version Drift

| Item | Description |
|------|-------------|
| Issue | `ubuntu-latest`はGitHubが随時更新するため、ビルド環境が予期せず変更される |
| Symptom | 依存ライブラリの非互換、ビルド失敗、テスト結果の不安定化 |
| Prevention | バージョン固定（`ubuntu-24.04`）を使用 |
| Reference | GitHub Docs「About GitHub-hosted runners」 |

> **補足**: 公開リポジトリではGitHub-hosted runnerの使用料金は無料です。

### Pattern #4: Rules Syntax Error

| Item | Description |
|------|-------------|
| Issue | バックスラッシュやEC2エラーを含むルール |
| Symptom | Falcoがルールを読み込めない |
| Prevention | ルール検証ステップをワークフローに含める |
| Reference | CLAUDE.md「EC2エラー防止チェックリスト」 |

### Pattern #5: Missing source: nginx

| Item | Description |
|------|-------------|
| Issue | Falcoルールに`source: nginx`がない |
| Symptom | アラートが生成されない |
| Prevention | すべてのルールに`source: nginx`を含める |
| Reference | CLAUDE.md「Falcoルール構文エラー（SDK版）」 |

---

## 6. Reference Documents

### 6.1 Required Reading Before Release

| Document | Path | Purpose |
|----------|------|---------|
| CLAUDE.md | `/CLAUDE.md` | ビルドとリリースの鉄則 |
| Task Completion Checklist | Serena Memory: `task_completion_checklist` | リリースチェックリスト |
| Problem Patterns | Serena Memory: `problem_patterns_key_issues` | 過去の問題パターン |
| E2E Test Memory | Serena Memory: `e2e_test` | E2Eテストの構成 |

### 6.2 Workflow Files

| Workflow | Path | Purpose |
|----------|------|---------|
| Release Workflow | `.github/workflows/release.yml` | リリース作成 |
| E2E Test Workflow | `.github/workflows/e2e-test.yml` | E2E検証 |
| Test Build Workflow | `.github/workflows/test-build.yml` | ビルド検証 |

### 6.3 Changelog

| Document | Path | Purpose |
|----------|------|---------|
| CHANGELOG.md | `/CHANGELOG.md` | 変更履歴（更新必須） |

---

## 7. Acceptance Criteria

### 7.1 Pre-Release

- [ ] すべてのE2Eテストがパス（300パターン）
- [ ] Rule Mapping 100% Match
- [ ] CHANGELOG.md v1.5.0セクション追加
- [ ] ランナーバージョンが固定されていることを確認（ubuntu-24.04推奨）

### 7.2 Release Process

- [ ] リリースワークフロー実行（手動トリガー禁止）
- [ ] バイナリがELF 64-bitであることを確認
- [ ] SHA256チェックサム生成
- [ ] リリースノート生成

### 7.3 Post-Release

- [ ] ダウンロードテスト
- [ ] バイナリ動作確認
- [ ] ルール構文検証
- [ ] GitHub Pagesの更新確認

---

## 8. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| macOSバイナリ混入 | Low | Critical | ワークフローのみ使用、file検証 |
| ルール構文エラー | Low | High | ワークフロー内で事前検証 |
| セルフホストランナー停止 | Low | Medium | 事前に稼働確認 |
| E2Eテスト失敗 | Very Low | Medium | リリース前に最新テスト確認 |

---

## 9. Timeline

| Phase | Task | Duration |
|-------|------|----------|
| 1 | 要件定義書・タスク定義書作成 | 30分 |
| 2 | CHANGELOG.md更新 | 15分 |
| 2.5 | 公開リポジトリREADME更新 | 15分 |
| 3 | 同期確認・検証 | 15分 |
| 4 | リリースワークフロー実行 | 10分 |
| 5 | リリース検証 | 15分 |
| **Total** | | **~100分** |

---

## 10. Approvals

| Role | Name | Status |
|------|------|--------|
| Author | Claude Code | ✅ Drafted |
| Reviewer | User | ⏳ Pending |

---

## 11. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| v1.0.0 | 2026-01-12 | Claude Code | 初版作成 |
| v1.1.0 | 2026-01-12 | Claude Code | FR-003パターン数修正（79/56/50/55等）、Timeline更新（Phase 2.5追加） |
| v1.2.0 | 2026-01-12 | Claude Code | FR-004詳細化：README.md/e2e/README.mdの具体的な更新要件を追加 |
| v1.3.0 | 2026-01-12 | Claude Code | FR-004.4追加：docs/*.mdのバージョン参照更新要件（rules.md, installation.md等） |
| v1.4.0 | 2026-01-12 | Claude Code | FR-004.4追加：E2E_REPORT_GUIDE.md/E2E_REPORT_GUIDE_JA.mdの更新要件 |
| v1.5.0 | 2026-01-12 | Claude Code | FR-004.2/FR-004.4詳細化：テーブル構造の完全な更新要件を追加（5→12カテゴリ） |
| v1.6.0 | 2026-01-12 | Claude Code | NFR-003/Pattern #3修正：公開リポジトリでは料金不要のため、バージョンドリフトリスクに焦点を変更 |

---

*Document Version: v1.6.0*
*Last Updated: 2026-01-12*
