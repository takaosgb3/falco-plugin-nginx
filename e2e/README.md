# E2E Test Suite for falco-plugin-nginx

This directory contains the end-to-end test suite for the Falco nginx plugin.

[English](#overview) | [日本語](#概要)

## Overview

The E2E test suite validates that the Falco nginx plugin correctly detects
security threats in nginx access logs. It uses k6 for load testing with
attack patterns, and Allure for test reporting.

### Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   k6 Load   │────▶│   nginx     │────▶│  access.log │
│   Tester    │     │   Server    │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Allure    │◀────│   Batch     │◀────│   Falco     │
│   Report    │     │   Analyzer  │     │  (plugin)   │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Directory Structure

```
e2e/
├── README.md           # This file
├── .gitignore          # Git ignore rules
├── k6/
│   └── main.js         # k6 test script
├── patterns/
│   ├── sqli_patterns.json           # SQL Injection patterns (138)
│   ├── cmdinj_patterns.json         # Command Injection patterns (98)
│   ├── xss_patterns.json            # XSS patterns (96)
│   ├── path_patterns.json           # Path Traversal patterns (81)
│   ├── ssrf_patterns.json           # SSRF patterns (41)
│   ├── ssti_patterns.json           # SSTI patterns (34)
│   ├── other_patterns.json          # Other patterns (34)
│   ├── crlf_patterns.json           # CRLF Injection patterns (31)
│   ├── api_security_patterns.json   # API Security patterns (30)
│   ├── xpath_patterns.json          # XPath patterns (25)
│   ├── graphql_patterns.json        # GraphQL patterns (25)
│   ├── host_header_patterns.json    # Host Header Injection patterns (21)
│   ├── hpp_patterns.json            # HPP patterns (20)
│   ├── open_redirect_patterns.json  # Open Redirect patterns (20)
│   ├── nosql_extended_patterns.json # NoSQL patterns (20)
│   ├── ldap_patterns.json           # LDAP Injection patterns (20)
│   ├── waf_bypass_patterns.json     # WAF Bypass patterns (18)
│   ├── xxe_patterns.json            # XXE patterns (18)
│   ├── jwt_patterns.json            # JWT Security patterns (15)
│   ├── prototype_pollution_patterns.json # Prototype Pollution patterns (15)
│   ├── http_smuggling_patterns.json # HTTP Smuggling patterns (15)
│   ├── pickle_patterns.json         # Pickle Deserialization patterns (15)
│   ├── info_disclosure_patterns.json # Information Disclosure patterns (10)
│   └── auth_bypass_patterns.json    # Auth Bypass via Path patterns (10)
├── scripts/
│   └── batch_analyzer.py     # Test result analyzer
├── allure/
│   ├── conftest.py           # pytest configuration
│   ├── test_e2e_wrapper.py   # Allure report generator
│   └── requirements.txt      # Python dependencies
└── results/                  # Test results (generated)
    ├── summary.json
    ├── test_ids.json
    └── test-results.json
```

## Test Categories

| Category | Count | Description | Expected Rule |
|----------|-------|-------------|---------------|
| SQLi | 138 | SQL Injection attacks | SQL Injection Rules |
| CmdInj | 98 | Command Injection attacks | Command Injection Rules |
| XSS | 96 | Cross-Site Scripting attacks | XSS Detection Rules |
| Path | 81 | Path Traversal attacks | Path Traversal Rules |
| SSRF | 41 | Server-Side Request Forgery | SSRF Detection Rules |
| SSTI | 34 | Server-Side Template Injection | SSTI Detection Rules |
| Other | 34 | Other attack patterns | Other Detection Rules |
| CRLF | 31 | CRLF Injection attacks | CRLF Injection Rules |
| API | 30 | API Security attacks | API Security Rules |
| XPath | 25 | XPath Injection attacks | XPath Injection Rules |
| GraphQL | 25 | GraphQL Injection attacks | GraphQL Injection Rules |
| Host Header | 21 | Host Header Injection attacks | Host Header Injection Rules |
| HPP | 20 | HTTP Parameter Pollution | HPP Detection Rules |
| Open Redirect | 20 | Open Redirect attacks | Open Redirect Rules |
| NoSQL | 20 | NoSQL Injection attacks | NoSQL Injection Rules |
| LDAP | 20 | LDAP Injection attacks | LDAP Injection Rules |
| WAF Bypass | 18 | WAF Bypass techniques | WAF Bypass Rules |
| XXE | 18 | XML External Entity attacks | XXE Detection Rules |
| JWT | 15 | JWT Security attacks | JWT Security Rules |
| Prototype Pollution | 15 | Prototype Pollution attacks | Prototype Pollution Rules |
| HTTP Smuggling | 15 | HTTP Request Smuggling attacks | HTTP Smuggling Rules |
| Pickle | 15 | Pickle Deserialization attacks | Deserialization Rules |
| Info Disclosure | 10 | Information Disclosure | Information Disclosure Rules |
| Auth Bypass | 10 | Auth Bypass via Path | Auth Bypass Rules |
| **Total** | **850** | | |

## Running Tests

### Via GitHub Actions (Recommended)

```bash
# Trigger E2E test workflow
gh workflow run e2e-test.yml

# Check workflow status
gh run list --workflow=e2e-test.yml

# View results
gh run view <RUN_ID>
```

### Running Tests Locally

#### Prerequisites

- k6 (https://k6.io/)
- Python 3.8+
- Falco with nginx plugin installed
- nginx server running

#### Quick Start

```bash
# Install Python dependencies
pip install -r allure/requirements.txt

# Run k6 tests
k6 run k6/main.js --env TARGET_IP=localhost --env TARGET_PORT=80

# Wait for Falco to process events
sleep 60

# Analyze results
python scripts/batch_analyzer.py \
  --patterns patterns/ \
  --falco-log /var/log/falco/falco.log \
  --test-ids results/test_ids.json \
  --output results/test-results.json

# Generate Allure report
pytest allure/test_e2e_wrapper.py \
  --test-results=results/test-results.json \
  --logs-dir=results/ \
  --alluredir=allure-results

# Open report
allure serve allure-results
```

## Test ID Correlation

Each attack pattern generates a unique test_id for tracking:

```
Format: {PATTERN_ID}-{TIMESTAMP_MS}-{RANDOM_SUFFIX}
Example: SQLI_TIME_001-1732267890123-abc123
```

This ID appears in:
1. nginx access.log (query string)
2. Falco alert output
3. test-results.json

The batch_analyzer.py correlates these IDs to match patterns with detections.

## GitHub Actions Workflow

E2E tests run automatically via GitHub Actions workflow:
- **Trigger**: Manual dispatch (`workflow_dispatch`)
- **Reports**: Published to GitHub Pages
- **Artifacts**: Test results and Allure report retained for 30 days

### Workflow Steps

1. Environment setup (Falco, nginx, k6, Python)
2. Service startup (nginx, Falco with plugin)
3. k6 test execution (850 patterns)
4. Wait for Falco processing (60s)
5. Result analysis (batch_analyzer.py)
6. Allure report generation
7. GitHub Pages deployment

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_IP` | localhost | Target server IP |
| `TARGET_PORT` | 80 | Target server port |
| `BATCH_WAIT_TIME` | 60 | Falco processing wait time (seconds) |
| `MIN_DETECTION_RATE` | 0.95 | Minimum detection rate threshold |

## Allure Report Features

The generated Allure report includes:

- **Test Summary**: Detection rate and statistics
- **Category Breakdown**: Results by attack category
- **Pattern Details**: Individual pattern results with:
  - Expected vs Actual rule match status
  - Detection latency
  - Falco log evidence
- **Attachments**: nginx access.log and falco.log excerpts

## Viewing Results

### GitHub Pages

Latest Allure Report: https://takaosgb3.github.io/falco-plugin-nginx/

Each workflow run creates a new report at:
`https://takaosgb3.github.io/falco-plugin-nginx/{RUN_NUMBER}/`

### Local Viewing

```bash
# Download artifacts from GitHub Actions
gh run download <RUN_ID> -n allure-report-<RUN_ID>

# Serve locally
allure open allure-report-<RUN_ID>
```

---

## 概要

このE2Eテストスイートは、Falco nginxプラグインがnginxアクセスログ内のセキュリティ脅威を正しく検出することを検証します。攻撃パターンの負荷テストにはk6を、テストレポートにはAllureを使用します。

### アーキテクチャ

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   k6 負荷   │────▶│   nginx     │────▶│  access.log │
│   テスター  │     │   サーバー  │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Allure    │◀────│   バッチ    │◀────│   Falco     │
│   レポート  │     │   分析器    │     │  (プラグイン)│
└─────────────┘     └─────────────┘     └─────────────┘
```

## テストカテゴリ

| カテゴリ | 数 | 説明 | 期待ルール |
|----------|-------|-------------|---------------|
| SQLi | 138 | SQLインジェクション攻撃 | SQL Injection Rules |
| CmdInj | 98 | コマンドインジェクション攻撃 | Command Injection Rules |
| XSS | 96 | クロスサイトスクリプティング攻撃 | XSS Detection Rules |
| Path | 81 | パストラバーサル攻撃 | Path Traversal Rules |
| SSRF | 41 | サーバーサイドリクエストフォージェリ | SSRF Detection Rules |
| SSTI | 34 | サーバーサイドテンプレートインジェクション | SSTI Detection Rules |
| Other | 34 | その他の攻撃パターン | Other Detection Rules |
| CRLF | 31 | CRLFインジェクション攻撃 | CRLF Injection Rules |
| API | 30 | APIセキュリティ攻撃 | API Security Rules |
| XPath | 25 | XPathインジェクション攻撃 | XPath Injection Rules |
| GraphQL | 25 | GraphQLインジェクション攻撃 | GraphQL Injection Rules |
| Host Header | 21 | Host Headerインジェクション攻撃 | Host Header Injection Rules |
| HPP | 20 | HTTPパラメータ汚染 | HPP Detection Rules |
| Open Redirect | 20 | オープンリダイレクト攻撃 | Open Redirect Rules |
| NoSQL | 20 | NoSQLインジェクション攻撃 | NoSQL Injection Rules |
| LDAP | 20 | LDAPインジェクション攻撃 | LDAP Injection Rules |
| WAF Bypass | 18 | WAFバイパス手法 | WAF Bypass Rules |
| XXE | 18 | XML外部エンティティ攻撃 | XXE Detection Rules |
| JWT | 15 | JWTセキュリティ攻撃 | JWT Security Rules |
| Prototype Pollution | 15 | プロトタイプ汚染攻撃 | Prototype Pollution Rules |
| HTTP Smuggling | 15 | HTTPリクエストスマグリング攻撃 | HTTP Smuggling Rules |
| Pickle | 15 | Pickle逆シリアル化攻撃 | Deserialization Rules |
| Info Disclosure | 10 | 情報漏洩 | Information Disclosure Rules |
| Auth Bypass | 10 | パスベース認証バイパス | Auth Bypass Rules |
| **合計** | **850** | | |

## テストの実行

### GitHub Actions経由（推奨）

```bash
# E2Eテストワークフローをトリガー
gh workflow run e2e-test.yml

# ワークフローの状態を確認
gh run list --workflow=e2e-test.yml

# 結果を表示
gh run view <RUN_ID>
```

### ローカルでの実行

#### 前提条件

- k6 (https://k6.io/)
- Python 3.8+
- Falco（nginxプラグインインストール済み）
- nginxサーバー起動済み

#### クイックスタート

```bash
# Python依存関係をインストール
pip install -r allure/requirements.txt

# k6テストを実行
k6 run k6/main.js --env TARGET_IP=localhost --env TARGET_PORT=80

# Falcoがイベントを処理するのを待機
sleep 60

# 結果を分析
python scripts/batch_analyzer.py \
  --patterns patterns/ \
  --falco-log /var/log/falco/falco.log \
  --test-ids results/test_ids.json \
  --output results/test-results.json

# Allureレポートを生成
pytest allure/test_e2e_wrapper.py \
  --test-results=results/test-results.json \
  --logs-dir=results/ \
  --alluredir=allure-results

# レポートを開く
allure serve allure-results
```

## 結果の確認

### GitHub Pages

最新のAllure Report: https://takaosgb3.github.io/falco-plugin-nginx/

各ワークフロー実行で新しいレポートが作成されます:
`https://takaosgb3.github.io/falco-plugin-nginx/{RUN_NUMBER}/`

## License

Apache 2.0
