# Release v1.5.0 Task Definition Document

## Document Info

| Item | Value |
|------|-------|
| Version | v1.6.0 |
| Created | 2026-01-12 |
| Updated | 2026-01-12 |
| Status | Draft |
| Parent | RELEASE_V1.5.0_REQUIREMENTS.md |

---

## Overview

このドキュメントは、Falco nginx プラグイン v1.5.0 のリリース作業のタスク定義書です。
各タスクには、参照すべきドキュメント、過去の失敗パターン、検証手順を含みます。

---

## Task Summary

| Task ID | Title | Status | Duration |
|---------|-------|--------|----------|
| TASK-1 | Pre-Release Verification | ⏳ Pending | 15分 |
| TASK-2 | CHANGELOG.md Update | ⏳ Pending | 15分 |
| TASK-2.5 | Public Repo README Updates | ⏳ Pending | 15分 |
| TASK-3 | Source Sync Verification | ⏳ Pending | 10分 |
| TASK-4 | Runner Configuration Check | ⏳ Pending | 5分 |
| TASK-5 | Release Workflow Execution | ⏳ Pending | 10分 |
| TASK-6 | Post-Release Verification | ⏳ Pending | 15分 |
| TASK-7 | Documentation Update | ⏳ Pending | 10分 |

---

## TASK-1: Pre-Release Verification

### 1.1 Purpose

リリース前に、E2Eテストとコード状態を確認する。

### 1.2 Steps

```bash
# Step 1.1: E2Eテスト最新結果確認
gh run list --repo takaosgb3/falco-plugin-nginx --workflow=e2e-test.yml --limit 3

# Step 1.2: E2Eテスト結果詳細確認
gh run view <RUN_ID> --repo takaosgb3/falco-plugin-nginx

# Step 1.3: Rule Mapping統計確認（最新ビルド）
# Allure Report URLで確認

# Step 1.4: 未マージPR確認
gh pr list --repo takaosgb3/falco-plugin-nginx

# Step 1.5: Open Issues確認
gh issue list --repo takaosgb3/falco-plugin-nginx --state open
```

### 1.3 Acceptance Criteria

- [ ] E2Eテスト最新実行が成功
- [ ] Rule Mapping 100% Match（または許容範囲内）
- [ ] 未マージの重要PRがない
- [ ] ブロッキングIssueがない

### 1.4 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| Serena Memory: `e2e_test` | 全体 | E2Eテストの仕組み理解 |
| Serena Memory: `task_completion_checklist` | Release Checklist | チェック項目 |

### 1.5 Past Failure Patterns

なし（事前検証フェーズ）

---

## TASK-2: CHANGELOG.md Update

### 2.1 Purpose

v1.5.0の変更内容をCHANGELOG.mdに追加する。

### 2.2 Content to Add

```markdown
## [v1.5.0] - 2026-01-12 - E2E 300 Patterns Release

### Added
- **300 Attack Patterns**: E2E test coverage expanded from 65 to 300 patterns
  - SQL Injection: 79 patterns
  - XSS: 56 patterns
  - Path Traversal: 50 patterns
  - Command Injection: 55 patterns
  - Emerging Threats: 60 patterns (LDAP, SSTI, NoSQL, XXE, XPath, GraphQL, API Security)
- **Rule Mapping Trend** (Issue #59): Allure Report now shows Rule Mapping trend in Categories Trend graph
- **Rule Mapping Validation** (Issue #53): Automated validation of expected_rule mappings

### Fixed
- **15 Rule Mapping Mismatches** (Issue #56): Resolved all rule name inconsistencies
- **Negative Test Display** (Issue #58): Improved display for expected_detection: false patterns
- **API_BOLA_001 Detection** (Issue #51): Added URL-encoded pattern support

### Technical Details
- Built with Falco Plugin SDK v0.8.1
- Tested with Falco 0.42.1
- E2E tested on GitHub Actions (Run #xxx)
- Full compatibility with nginx combined log format
```

### 2.3 Steps

```bash
# Step 2.1: 現在のCHANGELOG.md確認
head -100 CHANGELOG.md

# Step 2.2: v1.5.0セクション追加（Edit toolを使用）

# Step 2.3: 日本語セクションも追加

# Step 2.4: 変更確認
git diff CHANGELOG.md
```

### 2.4 Acceptance Criteria

- [ ] v1.5.0セクションが英語で追加
- [ ] v1.5.0セクションが日本語で追加
- [ ] 日付が正しい（2026-01-12）
- [ ] すべての新機能・修正が記載

### 2.5 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| CHANGELOG.md | 既存フォーマット | フォーマット確認 |
| Issue #56, #58, #59 | 全体 | 変更内容確認 |

### 2.6 Past Failure Patterns

なし（ドキュメント作業）

---

## TASK-2.5: Public Repo README Updates

### 2.5.1 Purpose

公開リポジトリのREADMEドキュメントを300パターン対応に更新する。

### 2.5.2 Files to Update

| File | Section | Current | Target |
|------|---------|---------|--------|
| README.md | E2E Security Tests (EN) | 65 attack patterns | 300 attack patterns |
| README.md | E2Eセキュリティテスト (JA) | 65攻撃パターン | 300攻撃パターン |
| README.md | Test Coverage Table (EN/JA) | 19/11/20/10/5 | 79/56/50/55/60 |
| e2e/README.md | Directory Structure | 19/11/20/10/5 | 79/56/50/55+others |
| e2e/README.md | Test Categories (EN) | Total: 65 | Total: 300 |
| e2e/README.md | テストカテゴリ (JA) | 合計: 65 | 合計: 300 |
| e2e/README.md | Workflow Steps | 65 patterns | 300 patterns |
| docs/rules.md | Line 3 | Version: 1.4.2 | Version: 1.5.0 |
| docs/NGINX_RULES_REFERENCE.md | Line 5 | Version: 1.4.2 | Version: 1.5.0 |
| docs/installation.md | Lines 12, 15, 19 | v1.4.2 | v1.5.0 |
| docs/QUICK_START_BINARY_INSTALLATION.md | Lines 36, 39, 46, 234, 237, 244 | v1.4.2 | v1.5.0 |
| .github/workflows/e2e-test.yml | Line 488 (environment.properties) | Test.Patterns=100 | Test.Patterns=300 |

> **注意**: docs/E2E_REPORT_GUIDE.md と docs/E2E_REPORT_GUIDE_JA.md の更新詳細は TASK-2.5.5 を参照してください。

### 2.5.3 README.md Updates

**重要**: Test Coverage Tableは単なる数値更新ではなく、**テーブル構造自体の完全な置き換え**が必要。

**英語セクション（Lines 110-120）**:

現在:
```markdown
**Test Coverage** (65 attack patterns):

| Category | Patterns | Description |
|----------|----------|-------------|
| SQL Injection | 19 | Time-based, Boolean-based blind SQLi |
| XSS | 11 | DOM-based, Reflected XSS attacks |
| Path Traversal | 20 | Directory traversal, absolute path access |
| Command Injection | 10 | Shell command injection patterns |
| Other | 5 | NoSQL/MongoDB injection |
```

更新後（12カテゴリに拡大）:
```markdown
**Test Coverage** (300 attack patterns across 12 categories):

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

**日本語セクション（Lines 231-241）**:
同様に12カテゴリのテーブルに置き換え。

### 2.5.4 e2e/README.md Updates

**Directory Structure（Lines 30-52）** - **構造変更必須**:

現在（5ファイル構成）:
```markdown
e2e/
├── README.md           # This file
├── .gitignore          # Git ignore rules
├── k6/
│   └── main.js         # k6 test script
├── patterns/
│   ├── sqli_patterns.json    # SQL Injection patterns (19)
│   ├── xss_patterns.json     # XSS patterns (11)
│   ├── path_patterns.json    # Path Traversal patterns (20)
│   ├── cmdinj_patterns.json  # Command Injection patterns (10)
│   └── other_patterns.json   # Other threats patterns (5)
```

変更後（12ファイル構成）:
```markdown
e2e/
├── README.md           # This file
├── .gitignore          # Git ignore rules
├── k6/
│   └── main.js         # k6 test script
├── patterns/
│   ├── sqli_patterns.json           # SQL Injection patterns (79)
│   ├── xss_patterns.json            # XSS patterns (56)
│   ├── path_patterns.json           # Path Traversal patterns (50)
│   ├── cmdinj_patterns.json         # Command Injection patterns (55)
│   ├── ldap_patterns.json           # LDAP Injection patterns (10)
│   ├── ssti_patterns.json           # SSTI patterns (10)
│   ├── nosql_extended_patterns.json # NoSQL patterns (7)
│   ├── xxe_patterns.json            # XXE patterns (8)
│   ├── xpath_patterns.json          # XPath patterns (5)
│   ├── graphql_patterns.json        # GraphQL patterns (5)
│   ├── api_security_patterns.json   # API Security patterns (5)
│   └── other_patterns.json          # Other patterns (10)
```

**Test Categories Table - EN（Lines 56-63）** - **12カテゴリに拡大**:
```markdown
| Category | Count | Description | Expected Rule |
|----------|-------|-------------|---------------|
| SQLi | 79 | SQL Injection attacks | SQL Injection Rules |
| XSS | 56 | Cross-Site Scripting attacks | XSS Detection Rules |
| Path | 50 | Path Traversal attacks | Path Traversal Rules |
| CmdInj | 55 | Command Injection attacks | Command Injection Rules |
| LDAP | 10 | LDAP Injection attacks | LDAP Injection Rules |
| SSTI | 10 | Server-Side Template Injection | SSTI Detection Rules |
| NoSQL | 7 | NoSQL Injection attacks | NoSQL Injection Rules |
| XXE | 8 | XML External Entity attacks | XXE Detection Rules |
| XPath | 5 | XPath Injection attacks | XPath Injection Rules |
| GraphQL | 5 | GraphQL Injection attacks | GraphQL Injection Rules |
| API | 5 | API Security attacks | API Security Rules |
| Other | 10 | Other attack patterns | Other Detection Rules |
| **Total** | **300** | | |
```

**Test Categories Table - JA（Lines 212-221）** - **12カテゴリに拡大**:
```markdown
| カテゴリ | 数 | 説明 | 期待ルール |
|----------|-------|-------------|---------------|
| SQLi | 79 | SQLインジェクション攻撃 | SQL Injection Rules |
| XSS | 56 | クロスサイトスクリプティング攻撃 | XSS Detection Rules |
| Path | 50 | パストラバーサル攻撃 | Path Traversal Rules |
| CmdInj | 55 | コマンドインジェクション攻撃 | Command Injection Rules |
| LDAP | 10 | LDAPインジェクション攻撃 | LDAP Injection Rules |
| SSTI | 10 | サーバーサイドテンプレートインジェクション | SSTI Detection Rules |
| NoSQL | 7 | NoSQLインジェクション攻撃 | NoSQL Injection Rules |
| XXE | 8 | XML外部エンティティ攻撃 | XXE Detection Rules |
| XPath | 5 | XPathインジェクション攻撃 | XPath Injection Rules |
| GraphQL | 5 | GraphQLインジェクション攻撃 | GraphQL Injection Rules |
| API | 5 | APIセキュリティ攻撃 | API Security Rules |
| Other | 10 | その他の攻撃パターン | Other Detection Rules |
| **合計** | **300** | | |
```

**Workflow Steps（Line 145）**:
```markdown
# 変更前
3. k6 test execution (65 patterns)
# 変更後
3. k6 test execution (300 patterns)
```

### 2.5.5 docs/*.md Version Updates

以下のドキュメントファイルのバージョン参照を v1.4.2 → v1.5.0 に更新する。

**docs/rules.md (Line 3)**:
```markdown
# 変更前
> Version: 1.4.2 | Last Updated: 2025-12-06

# 変更後
> Version: 1.5.0 | Last Updated: 2026-01-12
```

**docs/NGINX_RULES_REFERENCE.md (Line 5)**:
```markdown
# 変更前
> Version: 1.4.2

# 変更後
> Version: 1.5.0
```

**docs/installation.md (Lines 12, 15, 19)**:
```bash
# 変更前
PLUGIN_VERSION=v1.4.2

# 変更後
PLUGIN_VERSION=v1.5.0
```

**docs/QUICK_START_BINARY_INSTALLATION.md (Lines 36, 39, 46, 234, 237, 244)**:
```bash
# 変更前（複数箇所）
PLUGIN_VERSION=v1.4.2

# 変更後
PLUGIN_VERSION=v1.5.0
```

> **注意**: `PLUGIN_VERSION=latest`を使用している箇所は更新不要（自動的に最新を取得）

**docs/E2E_REPORT_GUIDE.md - 複数箇所の更新が必要**:

1. **Overview (Line 22)**:
   ```markdown
   # 変更前
   Each test run executes **65 attack patterns** across 5 categories
   # 変更後
   Each test run executes **300 attack patterns** across 12 categories
   ```

2. **Key Metrics テーブル (Line 57)**:
   ```markdown
   # 変更前
   | **Test Cases** | Total number of test patterns executed (65) |
   # 変更後
   | **Test Cases** | Total number of test patterns executed (300) |
   ```

3. **Category Breakdown テーブル (Lines 93-99)** - **構造変更**:
   ```markdown
   # 変更前（5行）
   | **SQLI** | 19 | SQL Injection attacks |
   | **XSS** | 11 | Cross-Site Scripting attacks |
   | **PATH** | 20 | Path Traversal attacks |
   | **CMDINJ** | 10 | Command Injection attacks |
   | **OTHER** | 5 | NoSQL/MongoDB injection attacks |

   # 変更後（12行）
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

4. **Status Indicators (Line 103)**:
   ```markdown
   # 変更前
   - **Green (65)**: Passed tests
   # 変更後
   - **Green (300)**: Passed tests
   ```

5. **Test Categories セクション (Lines 239-280)** - **大幅な構造変更**:
   - 既存5カテゴリのパターン数を更新（SQLI, XSS, PATH, CMDINJ, OTHER）
   - 新規7カテゴリを追加（LDAP, SSTI, NoSQL, XXE, XPath, GraphQL, API）

**docs/E2E_REPORT_GUIDE_JA.md** - 日本語版の詳細更新箇所：

1. **概要 (Line 20)**:
   ```markdown
   # 変更前
   5つのカテゴリにわたる**65の攻撃パターン**を実行し
   # 変更後
   12のカテゴリにわたる**300の攻撃パターン**を実行し
   ```

2. **主要メトリクス テーブル (Line 55)**:
   ```markdown
   # 変更前
   | **Test Cases** | 実行されたテストパターンの総数（65） |
   # 変更後
   | **Test Cases** | 実行されたテストパターンの総数（300） |
   ```

3. **カテゴリ別内訳 テーブル (Lines 91-97)** - **構造変更**:
   ```markdown
   # 変更前（5行）
   | **SQLI** | 19 | SQLインジェクション攻撃 |
   | **XSS** | 11 | クロスサイトスクリプティング攻撃 |
   | **PATH** | 20 | パストラバーサル攻撃 |
   | **CMDINJ** | 10 | コマンドインジェクション攻撃 |
   | **OTHER** | 5 | NoSQL/MongoDBインジェクション攻撃 |

   # 変更後（12行）
   | **SQLI** | 79 | SQLインジェクション攻撃 |
   | **XSS** | 56 | クロスサイトスクリプティング攻撃 |
   | **PATH** | 50 | パストラバーサル攻撃 |
   | **CMDINJ** | 55 | コマンドインジェクション攻撃 |
   | **LDAP** | 10 | LDAPインジェクション攻撃 |
   | **SSTI** | 10 | サーバーサイドテンプレートインジェクション |
   | **NOSQL** | 7 | NoSQLインジェクション攻撃 |
   | **XXE** | 8 | XML外部エンティティ攻撃 |
   | **XPATH** | 5 | XPathインジェクション攻撃 |
   | **GRAPHQL** | 5 | GraphQLインジェクション攻撃 |
   | **API** | 5 | APIセキュリティ攻撃 |
   | **OTHER** | 10 | その他の攻撃パターン |
   ```

4. **ステータス表示 (Line 101)**:
   ```markdown
   # 変更前
   - **緑色（65）**：成功したテスト
   # 変更後
   - **緑色（300）**：成功したテスト
   ```

5. **テストカテゴリ セクション (Lines 237-278)** - **大幅な構造変更**:
   - 既存5カテゴリのパターン数を更新
   - 新規7カテゴリを日本語で追加（LDAP, SSTI, NoSQL, XXE, XPath, GraphQL, API）

### 2.5.6 Acceptance Criteria

- [ ] README.md英語セクションが300パターン対応
- [ ] README.md日本語セクションが300パターン対応
- [ ] e2e/README.md Directory Structureが更新
- [ ] e2e/README.md Test Categories表が更新
- [ ] e2e/README.md Workflow Stepsが更新
- [ ] docs/rules.md のバージョンが v1.5.0 に更新
- [ ] docs/NGINX_RULES_REFERENCE.md のバージョンが v1.5.0 に更新
- [ ] docs/installation.md のバージョンが v1.5.0 に更新
- [ ] docs/QUICK_START_BINARY_INSTALLATION.md のバージョンが v1.5.0 に更新
- [ ] docs/E2E_REPORT_GUIDE.md が300パターン対応に更新
- [ ] docs/E2E_REPORT_GUIDE_JA.md が300パターン対応に更新
- [ ] 日英両言語で一貫性がある

### 2.5.7 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| e2e/patterns/*.json | 全ファイル | 正確なパターン数確認 |
| RELEASE_V1.5.0_REVIEW_REPORT.md | Issue #1 | 正確な数値参照 |
| RELEASE_V1.5.0_REQUIREMENTS.md | FR-004.4 | docs/*.md更新要件 |

### 2.5.8 Past Failure Patterns

なし（ドキュメント作業）

---

## TASK-3: Source Sync Verification

### 3.1 Purpose

プライベートリポジトリと公開リポジトリのソース同期を確認する。

### 3.2 Steps

```bash
# Step 3.1: 同期スクリプト確認（プライベートリポジトリ）
cd /Users/takaos/lab/falco-nginx-plugin-claude
make check-sync 2>/dev/null || ./scripts/check-sync-status.sh

# Step 3.2: プラグインソースの差分確認
diff -u cmd/plugin-sdk/nginx.go falco-plugin-nginx-public/plugin/main.go | head -50

# Step 3.3: 同期が必要な場合
make sync-public 2>/dev/null || ./scripts/sync-source.sh
```

### 3.3 Acceptance Criteria

- [ ] ソースコードが同期されている
- [ ] インポートパスが正しく変換されている
- [ ] テストがパスする

### 3.4 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| CLAUDE.md | ソースコード管理戦略 | 同期プロセス理解 |
| scripts/sync-source.sh | 全体 | 同期スクリプト |

### 3.5 Past Failure Patterns

| Pattern | Description | Prevention |
|---------|-------------|------------|
| インポートパス不一致 | `falco-nginx-plugin-claude` vs `falco-plugin-nginx` | sync-source.sh使用 |

---

## TASK-4: Runner Configuration Check

### 4.1 Purpose

ワークフローのランナー設定を確認する。

### 4.2 Context

**公開リポジトリ特有の注意点**:
- 公開リポジトリ（falco-plugin-nginx）はユーザーがフォークして使用するため、
  `ubuntu-24.04`などのGitHub提供ランナーを使用することは許容される
- `ubuntu-latest`は非推奨（バージョン変動リスク）
- プライベートリポジトリ（falco-nginx-plugin-claude）では必ずセルフホストランナーを使用

### 4.3 Steps

```bash
# Step 4.1: ubuntu-latest使用確認（禁止）
grep -r "ubuntu-latest" .github/workflows/
# 出力があれば修正が必要

# Step 4.2: 使用されているランナーの確認
grep -r "runs-on:" .github/workflows/
# ubuntu-24.04 は許容される（公開リポジトリの場合）

# Step 4.3: ワークフロー構文の確認
# release.yml が正しく設定されていること
```

### 4.4 Acceptance Criteria

- [ ] `ubuntu-latest`が使用されていない（バージョン固定推奨）
- [ ] 公開リポジトリでは`ubuntu-24.04`が許容される
- [ ] ワークフローが正常に実行可能

### 4.5 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| CLAUDE.md | GitHub Actions使用料金の節約 | 絶対ルール（プライベートリポジトリ向け） |

### 4.6 Past Failure Patterns

| Pattern | Description | Prevention |
|---------|-------------|------------|
| ubuntu-latest使用 | バージョン変動リスク | ubuntu-24.04に固定 |

> **注意**: 「セルフホスト停止」リスクはプライベートリポジトリ（falco-nginx-plugin-claude）のみに該当。公開リポジトリ（falco-plugin-nginx）ではGitHub-hosted runnerを使用するため、この問題は発生しない。

---

## TASK-5: Release Workflow Execution

### 5.1 Purpose

リリースワークフローを実行してv1.5.0をリリースする。

### 5.2 Steps

```bash
# Step 5.1: 変更をコミット・プッシュ
git add -A
git commit -m "docs: Prepare release v1.5.0"
git push origin release-v1.5.0

# Step 5.2: PRを作成してマージ（必要に応じて）
gh pr create --title "Release v1.5.0" --body "..."
gh pr merge --squash

# Step 5.3: リリースワークフロー実行
gh workflow run release.yml \
  -f version=v1.5.0 \
  --repo takaosgb3/falco-plugin-nginx

# Step 5.4: ワークフロー進捗確認
gh run list --workflow=release.yml --repo takaosgb3/falco-plugin-nginx --limit 3

# Step 5.5: 実行詳細確認
gh run view <RUN_ID> --repo takaosgb3/falco-plugin-nginx
```

### 5.3 Acceptance Criteria

- [ ] ワークフローが正常に開始
- [ ] すべてのステップが成功
- [ ] リリースが作成される

### 5.4 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| CLAUDE.md | リリースプロセス | 絶対ルール |
| .github/workflows/release.yml | 全体 | ワークフロー内容 |

### 5.5 Past Failure Patterns

| Pattern | Description | Prevention |
|---------|-------------|------------|
| 手動リリース | 検証されていないバイナリ | 絶対にワークフロー使用 |
| macOSバイナリ | Mach-Oフォーマット | ワークフローのみ使用 |
| 認証エラー | GH_TOKEN未設定 | ワークフロー設定確認 |

> **警告**: 絶対に `gh release create` を直接使用しないこと

---

## TASK-6: Post-Release Verification

### 6.1 Purpose

リリースが正しく作成されたことを検証する。

### 6.2 Steps

```bash
# Step 6.1: リリース確認
gh release view v1.5.0 --repo takaosgb3/falco-plugin-nginx

# Step 6.2: バイナリダウンロード
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v1.5.0/libfalco-nginx-plugin-linux-amd64.so

# Step 6.3: バイナリ形式確認（最重要）
file libfalco-nginx-plugin-linux-amd64.so
# 期待出力: ELF 64-bit LSB shared object, x86-64

# Step 6.4: ファイルサイズ確認
ls -la libfalco-nginx-plugin-linux-amd64.so
# 期待: 約4MB

# Step 6.5: SHA256確認
sha256sum libfalco-nginx-plugin-linux-amd64.so
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v1.5.0/libfalco-nginx-plugin-linux-amd64.so.sha256
cat libfalco-nginx-plugin-linux-amd64.so.sha256

# Step 6.6: ルールファイル確認
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v1.5.0/nginx_rules.yaml
head -50 nginx_rules.yaml
```

### 6.3 Acceptance Criteria

- [ ] リリースページが存在
- [ ] バイナリがELF 64-bit形式
- [ ] ファイルサイズが適切（~4MB）
- [ ] SHA256チェックサムが一致
- [ ] ルールファイルが含まれている
- [ ] リリースノートが正しい

### 6.4 Reference Documents

| Document | Section | Purpose |
|----------|---------|---------|
| CLAUDE.md | ビルドとリリースの鉄則 | 検証項目 |
| Serena Memory: `task_completion_checklist` | Post-Release | 検証チェックリスト |

### 6.5 Past Failure Patterns

| Pattern | Description | Prevention |
|---------|-------------|------------|
| Mach-Oバイナリ | macOSでビルド | file コマンドで必ず確認 |
| サイズ異常 | ビルドエラー | サイズ確認 |
| SHA256不一致 | 破損ファイル | チェックサム確認 |

---

## TASK-7: Documentation Update

### 7.1 Purpose

リリース完了後のドキュメント更新とIssue報告。

### 7.2 Steps

```bash
# Step 7.1: Issue #62（または新規Issue）に完了報告
gh issue comment <ISSUE_ID> --body "..."

# Step 7.2: Serena Memoryの更新
# development_diary_2026_01_12 を更新

# Step 7.3: リリースブランチのクリーンアップ
git checkout main
git branch -d release-v1.5.0
```

### 7.3 Acceptance Criteria

- [ ] Issue/PRに完了報告
- [ ] 開発日記更新
- [ ] ブランチクリーンアップ

---

## Rollback Procedure

リリースに問題があった場合のロールバック手順。

### Step 1: リリース削除

```bash
# ドラフトリリースの場合
gh release delete v1.5.0 --repo takaosgb3/falco-plugin-nginx

# 公開済みの場合（慎重に）
gh release delete v1.5.0 --repo takaosgb3/falco-plugin-nginx -y
```

### Step 2: タグ削除

```bash
git push origin :refs/tags/v1.5.0
```

### Step 3: 問題調査

- ワークフローログ確認
- バイナリの形式確認
- ルール構文確認

### Step 4: 修正後再リリース

- 問題を修正
- TASK-5から再実行

---

## Context Preservation

コンテキストが失われた場合に参照すべき情報。

### Key References

| Topic | Reference |
|-------|-----------|
| リリース手順 | CLAUDE.md「リリースプロセス」 |
| 過去の問題 | CLAUDE.md「過去の問題」 |
| E2Eテスト | Serena Memory: `e2e_test` |
| タスクチェック | Serena Memory: `task_completion_checklist` |
| 問題パターン | Serena Memory: `problem_patterns_key_issues` |

### Current State

```
Branch: release-v1.5.0
Private Repo: /Users/takaos/lab/falco-nginx-plugin-claude
Public Repo: /Users/takaos/lab/falco-nginx-plugin-claude/falco-plugin-nginx-public
Current Version: v1.4.4 (internal) / v1.4.2 (public)
Target Version: v1.5.0
```

### Commands to Resume

```bash
# 現在の状態確認
git status
git log --oneline -5

# E2Eテスト状況確認
gh run list --repo takaosgb3/falco-plugin-nginx --workflow=e2e-test.yml --limit 3

# リリース状況確認
gh release list --repo takaosgb3/falco-plugin-nginx --limit 3
```

---

## Summary

| Task | Purpose | Key Points |
|------|---------|------------|
| TASK-1 | 事前検証 | E2Eテスト、Rule Mapping確認 |
| TASK-2 | CHANGELOG更新 | 英語・日本語両方 |
| TASK-3 | ソース同期 | プライベート→公開 |
| TASK-4 | ランナー確認 | ubuntu-24.04許容 |
| TASK-5 | リリース実行 | ワークフローのみ |
| TASK-6 | リリース検証 | ELF形式確認必須 |
| TASK-7 | 後処理 | ドキュメント更新 |

---

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| v1.0.0 | 2026-01-12 | Claude Code | 初版作成：TASK-1〜TASK-7定義 |
| v1.1.0 | 2026-01-12 | Claude Code | TASK-2.5追加（公開リポジトリREADME更新）、TASK-4にContext追加 |
| v1.2.0 | 2026-01-12 | Claude Code | TASK-2.5にdocs/*.mdバージョン更新を追加（FR-004.4に対応） |
| v1.3.0 | 2026-01-12 | Claude Code | TASK-2.5にE2E_REPORT_GUIDE.md更新を追加（FR-004.4に対応） |
| v1.4.0 | 2026-01-12 | Claude Code | TASK-2.5詳細化：テーブル構造の完全な更新手順を追加（5→12カテゴリ） |
| v1.5.0 | 2026-01-12 | Claude Code | 第6回レビュー対応：Issue #6修正（既存5カテゴリ）、Issue #7追加（JA版詳細行番号）、Issue #8追加（Directory Structure更新手順） |
| v1.6.0 | 2026-01-12 | Claude Code | 第8回レビュー対応：Issue #10修正（Test Categories 6→12カテゴリ）、Issue #12修正（E2E_REPORT_GUIDE重複削除） |
| v1.7.0 | 2026-01-12 | Claude Code | 第9回レビュー対応：Issue #13追加（TASK-2.5.2にe2e-test.yml Test.Patterns更新を追加） |
| v1.8.0 | 2026-01-12 | Claude Code | 第10回レビュー対応：Issue #14修正（TASK-4.6「セルフホスト停止」行削除、公開リポジトリでは不要の注記追加） |

---

*Document Version: v1.8.0*
*Last Updated: 2026-01-12*
