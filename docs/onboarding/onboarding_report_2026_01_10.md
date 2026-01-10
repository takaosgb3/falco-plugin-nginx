# Onboarding Report v19.0.0 - 2026-01-10

## Project Overview

### Falco Nginx Plugin
A Falco plugin providing real-time security monitoring for nginx web servers by parsing access logs and detecting security threats (SQL injection, XSS, directory traversal, command injection, OWASP Top 10).

### Repository Structure
| Repository | Purpose | Path |
|------------|---------|------|
| falco-nginx-plugin-claude | Private development | `/Users/takaos/lab/falco-nginx-plugin-claude` |
| falco-plugin-nginx | Public distribution | `./falco-plugin-nginx-public/` |

---

## Current Status (2026-01-10)

### Project Phase
- **Current Phase**: Phase 4 (Pattern Expansion Complete)
- **Total Patterns**: 300 (100% coverage)
- **Detection Rate**: ~44.62% (improvement target: 80%+)

### Recent Milestones

| Date | Milestone | Issue/PR |
|------|-----------|----------|
| 2026-01-10 | Rule Mapping Validation Complete | Issue #53, PR #54 |
| 2026-01-08 | API_BOLA_001 URL Encoding Fix | Issue #51, PR #52 |
| 2026-01-03 | Phase 4: 300 Patterns | Issue #49, PR #50 |
| 2026-01-03 | Rule Mapping Accuracy 97%+ | Issue #47, PR #48 |

### Latest Commits
```
63ec100a fix(e2e): Issue #53 - Address PR #54 review findings
72676807 refactor(e2e): Issue #53 - Code quality improvements
0305d8a2 feat(e2e): Add rule mapping validation (Issue #53)
c6cf72a3 fix: Add URL-encoded patterns for API_BOLA_001 (Issue #51)
df1f4651 feat: Expand E2E patterns to 300 (Phase 4) - Issue #49
```

---

## Technology Stack

### Core Technologies
| Technology | Version | Purpose |
|------------|---------|---------|
| Go | 1.21+ | Plugin development |
| Falco Plugin SDK | v0.8.1 | Plugin framework |
| Falco | 0.36.0+ | Security engine |
| nginx | 1.18.0+ | Monitored server |

### Quality Tools
| Tool | Purpose |
|------|---------|
| golangci-lint | Go code linting |
| pre-commit | Git hooks |
| markdownlint | Markdown linting |
| shellcheck | Bash linting |

### CI/CD
- **GitHub Actions**: Self-hosted runners (REQUIRED)
- **CRITICAL**: `ubuntu-latest` is PROHIBITED (cost savings)
- **Runner Label**: `[self-hosted, linux, x64, local]`
- **Terraform**: AWS E2E infrastructure
- **Netlify**: Allure report hosting

---

## Key Files and Directories

### Source Code
| Path | Description |
|------|-------------|
| `cmd/plugin-sdk/nginx.go` | Main plugin (SDK version, RECOMMENDED) |
| `pkg/parser/nginx.go` | Log parser implementation |
| `rules/nginx_rules.yaml` | Falco security rules |

### E2E Testing
| Path | Description |
|------|-------------|
| `e2e/patterns/*.json` | 300 attack patterns |
| `e2e/scripts/batch_analyzer.py` | Pattern analysis |
| `e2e/allure/test_e2e_wrapper.py` | Allure test wrapper |

### Configuration
| File | Purpose |
|------|---------|
| `CLAUDE.md` | Development guide |
| `PROBLEM_PATTERNS.md` | Known issues (Pattern #A*) |
| `.golangci.yml` | Linter config |
| `go.mod` | Go dependencies |

---

## Build Commands

### Plugin Build (REQUIRED flags)
```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
  -buildmode=c-shared \
  -o libfalco-nginx-plugin.so \
  cmd/plugin-sdk/nginx.go
```

### Common Make Targets
```bash
make build          # Standard build
make build-sdk      # SDK plugin build (RECOMMENDED)
make test           # Run all tests
make lint           # Run linters
make sync-public    # Sync to public repo
make check-sync     # Verify sync status
```

---

## Extracted Fields (nginx.*)

| Field | Type | Description |
|-------|------|-------------|
| `nginx.remote_addr` | string | Client IP |
| `nginx.method` | string | HTTP method |
| `nginx.path` | string | Request path |
| `nginx.query_string` | string | Query parameters |
| `nginx.request_uri` | string | Full URI |
| `nginx.status` | uint64 | Response status |
| `nginx.headers[key]` | string | HTTP headers (case-insensitive) |
| `nginx.test_id` | string | E2E test ID |
| `nginx.pattern_id` | string | Pattern ID |

---

## Recent Feature: Rule Mapping Validation (Issue #53)

### Implementation Summary
- **PR #54**: Merged 2026-01-10
- **Files Changed**: 12
- **Lines**: +1,036 / -264
- **Tests**: 58 unit tests

### New Components
1. **Pattern Files**: `expected_rule` field added to 300 patterns
2. **batch_analyzer.py**: `normalize_rule_name()`, `compare_rules()`
3. **test_e2e_wrapper.py**: `format_rule_match_status()`
4. **Allure Report**: Rule Mapping section with ✅/❌/⚠️ status

### Review Results (5 Agents)
- Critical Issues: 0
- Important Issues: 6 (follow-up)
- Suggestions: 8

---

## Pending Work

### Immediate Tasks
1. **PR #54 Follow-up**: Error handling and test additions
2. **E2E Verification**: Issues #51, #53 in production
3. **Detection Rate**: Improve from 44.62% to 80%+

### Follow-up Items (Post-Merge)
1. Add error handling to `_load_pattern_file()` (batch_analyzer.py)
2. Add unit tests for `load_all_patterns()` (test_e2e_wrapper.py)
3. Fix docstring contradiction in whitespace test
4. Add reverse substring match test

---

## Important Guidelines

### Git Workflow
- **Main Branch**: `main`
- **Feature Branches**: `feature/issue-XX-description`
- **Commit Format**: `type(scope): description`
- **PR Merge**: Squash merge preferred

### CI/CD Rules
1. **NEVER use `ubuntu-latest`** - Use self-hosted runners
2. **NEVER manual release** - Use GitHub Actions workflows
3. **ALWAYS run quality checks** before PR

### Code Quality
- Run `./scripts/quality-check.sh` before commits
- Follow `CLAUDE.md` guidelines
- Document with PROBLEM_PATTERNS.md for issues

---

## Useful Memories (Serena)

| Memory | Content |
|--------|---------|
| `current_work_context` | Latest session state |
| `development_diary_2026_01_10` | Today's work log |
| `pr54_review_fixes_plan` | PR #54 review details |
| `codebase_structure` | Directory organization |
| `tech_stack_and_tools` | Technology details |
| `problem_patterns_key_issues` | Known issue patterns |

---

## Quick Start for New Session

```bash
# 1. Update main branch
git checkout main && git pull origin main

# 2. Check current status
git status && git log --oneline -5

# 3. View pending issues
gh issue list --state open

# 4. Read relevant memories
# Use Serena: read_memory("current_work_context")
```

---

*Generated: 2026-01-10*
*Version: v19.0.0*
