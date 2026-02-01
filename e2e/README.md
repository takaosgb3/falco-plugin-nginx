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
│   ├── sqli_patterns.json           # SQL Injection patterns (124)
│   ├── xss_patterns.json            # XSS patterns (81)
│   ├── path_patterns.json           # Path Traversal patterns (73)
│   ├── cmdinj_patterns.json         # Command Injection patterns (89)
│   ├── ldap_patterns.json           # LDAP Injection patterns (10)
│   ├── ssti_patterns.json           # SSTI patterns (10)
│   ├── nosql_extended_patterns.json # NoSQL patterns (13)
│   ├── xxe_patterns.json            # XXE patterns (8)
│   ├── xpath_patterns.json          # XPath patterns (5)
│   ├── graphql_patterns.json        # GraphQL patterns (5)
│   ├── api_security_patterns.json   # API Security patterns (5)
│   ├── pickle_patterns.json         # Pickle Deserialization patterns (4)
│   ├── prototype_pollution_patterns.json # Prototype Pollution patterns (10)
│   ├── http_smuggling_patterns.json # HTTP Smuggling patterns (10)
│   └── other_patterns.json          # Other patterns (10)
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
| SQLi | 124 | SQL Injection attacks | SQL Injection Rules |
| XSS | 81 | Cross-Site Scripting attacks | XSS Detection Rules |
| Path | 73 | Path Traversal attacks | Path Traversal Rules |
| CmdInj | 89 | Command Injection attacks | Command Injection Rules |
| LDAP | 10 | LDAP Injection attacks | LDAP Injection Rules |
| SSTI | 10 | Server-Side Template Injection | SSTI Detection Rules |
| NoSQL | 13 | NoSQL Injection attacks | NoSQL Injection Rules |
| XXE | 8 | XML External Entity attacks | XXE Detection Rules |
| XPath | 5 | XPath Injection attacks | XPath Injection Rules |
| GraphQL | 5 | GraphQL Injection attacks | GraphQL Injection Rules |
| API | 5 | API Security attacks | API Security Rules |
| Pickle | 4 | Pickle Deserialization attacks | Deserialization Rules |
| Prototype Pollution | 10 | Prototype Pollution attacks | Prototype Pollution Rules |
| HTTP Smuggling | 10 | HTTP Request Smuggling attacks | HTTP Smuggling Rules |
| Other | 10 | Other attack patterns | Other Detection Rules |
| **Total** | **457** | | |

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
3. k6 test execution (457 patterns)
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
| SQLi | 124 | SQLインジェクション攻撃 | SQL Injection Rules |
| XSS | 81 | クロスサイトスクリプティング攻撃 | XSS Detection Rules |
| Path | 73 | パストラバーサル攻撃 | Path Traversal Rules |
| CmdInj | 89 | コマンドインジェクション攻撃 | Command Injection Rules |
| LDAP | 10 | LDAPインジェクション攻撃 | LDAP Injection Rules |
| SSTI | 10 | サーバーサイドテンプレートインジェクション | SSTI Detection Rules |
| NoSQL | 13 | NoSQLインジェクション攻撃 | NoSQL Injection Rules |
| XXE | 8 | XML外部エンティティ攻撃 | XXE Detection Rules |
| XPath | 5 | XPathインジェクション攻撃 | XPath Injection Rules |
| GraphQL | 5 | GraphQLインジェクション攻撃 | GraphQL Injection Rules |
| API | 5 | APIセキュリティ攻撃 | API Security Rules |
| Pickle | 4 | Pickle逆シリアル化攻撃 | Deserialization Rules |
| Prototype Pollution | 10 | プロトタイプ汚染攻撃 | Prototype Pollution Rules |
| HTTP Smuggling | 10 | HTTPリクエストスマグリング攻撃 | HTTP Smuggling Rules |
| Other | 10 | その他の攻撃パターン | Other Detection Rules |
| **合計** | **457** | | |

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
