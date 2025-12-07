# E2E Test Suite for falco-plugin-nginx

This directory contains the end-to-end test suite for the Falco nginx plugin.

## Overview

The E2E test suite validates that the Falco nginx plugin correctly detects
security threats in nginx access logs. It uses k6 for load testing with
attack patterns, and Allure for test reporting.

## Directory Structure

```
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

| Category | Count | Description |
|----------|-------|-------------|
| SQLi | 19 | SQL Injection attacks |
| XSS | 11 | Cross-Site Scripting attacks |
| Path | 20 | Path Traversal attacks |
| CmdInj | 10 | Command Injection attacks |
| Other | 5 | Other threats (MongoDB, etc.) |
| **Total** | **65** | |

## Running Tests Locally

### Prerequisites

- k6 (https://k6.io/)
- Python 3.8+
- Falco with nginx plugin installed
- nginx server running

### Quick Start

```bash
# Install Python dependencies
pip install -r allure/requirements.txt

# Run k6 tests
k6 run k6/main.js

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

## GitHub Actions

E2E tests run automatically via GitHub Actions workflow:
- Trigger: Push to main branch or manual dispatch
- Reports: Published to GitHub Pages

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_IP` | localhost | Target server IP |
| `TARGET_PORT` | 80 | Target server port |
| `BATCH_WAIT_TIME` | 60 | Falco processing wait time (seconds) |
| `MIN_DETECTION_RATE` | 0.95 | Minimum detection rate threshold |

## License

Apache 2.0
