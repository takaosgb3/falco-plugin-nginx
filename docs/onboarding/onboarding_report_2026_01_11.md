# Onboarding Report v20.0.0 - 2026-01-11

## Project Overview

### Falco Nginx Plugin
A Falco plugin providing real-time security monitoring for nginx web servers by parsing access logs and detecting security threats (SQL injection, XSS, directory traversal, command injection, OWASP Top 10).

### Repository Structure
| Repository | Purpose | Path |
|------------|---------|------|
| falco-nginx-plugin-claude | Private development | `/Users/takaos/lab/falco-nginx-plugin-claude` |
| falco-plugin-nginx | Public distribution | `./falco-plugin-nginx-public/` |

---

## Current Status (2026-01-11)

### Project Phase
- **Current Phase**: Phase 4 (Pattern Expansion Complete)
- **Total Patterns**: 300 (100% coverage)
- **Detection Rate**: ~44.62% (improvement target: 80%+)
- **Active Work**: Issue #56 - Rule Mapping Mismatch Fix

### Recent Milestones

| Date | Milestone | Issue/PR |
|------|-----------|----------|
| 2026-01-11 | Issue #56 Documentation v3.0.0 Complete | Issue #56 |
| 2026-01-10 | Rule Mapping Validation Complete | Issue #53, PR #54 |
| 2026-01-08 | API_BOLA_001 URL Encoding Fix | Issue #51, PR #52 |
| 2026-01-03 | Phase 4: 300 Patterns | Issue #49, PR #50 |

### Latest Commits (Private Repo)
```
83eef7b docs: Update serena memories for 2026-01-08
02b3f1a docs: Add onboarding report v18.0.0 for 2026-01-08
7190999 docs: Add development diary for 2026-01-08
2e87114 docs: Add Pattern #A329 - API_BOLA_001 URL Encoding Detection Failure
eea28fa docs: Add Phase 4 documentation and onboarding reports
```

### Latest Commits (Public Repo)
```
3ff79b83 docs: Add onboarding report v19.0.0 for 2026-01-10
c43cda94 feat(e2e): Add rule mapping validation (Issue #53) (#54)
c6cf72a3 fix: Add URL-encoded patterns for API_BOLA_001 (Issue #51) (#52)
cd1969af style: Remove trailing blank lines from nginx_rules.yaml
df1f4651 feat: Expand E2E patterns to 300 (Phase 4) - Issue #49 (#50)
```

---

## 🔴 Active Work: Issue #56 (Rule Mapping Mismatch)

### Problem Summary
E2E Run #83 detected 15 Rule Mapping Mismatches. Analysis revealed that simply updating `expected_rule` is insufficient - the core issue is **Falco rule priority ordering**.

### User's Key Insight
> 「定義されたルールで検知されるべき」
> If attack patterns are defined with rules to detect them, those rules should be the ones detecting them.

### Problem Classification (MECE Analysis)

| Problem Type | Count | Description | Action Required |
|--------------|-------|-------------|-----------------|
| **A: expected_rule definition error** | 2 | Redis labeled as MongoDB | Fix expected_rule |
| **B: Falco rule priority ordering** | 4 | Generic rule fires before specific | **Add exceptions** |
| **C: expected_rule format mismatch** | 3 | Short name vs output format | Fix format |
| **D: Alternative detection** | 4 | Valid alternative rule fired | Update expected_rule |

### Task Structure (v3.0.0)

```
TASK-A (13 patterns total)
├── TASK-A-1: Falco rule exception additions (4 patterns) ← NEW
│   ├── NOSQL_MONGO_003 → SQLi → MongoDB NoSQL
│   ├── NOSQL_REDIS_001 → XSS → Redis Command Injection
│   ├── API_IDOR_001 → SQLi → API Security
│   └── API_PROTO_001 → Template Injection → API Security
├── TASK-A-2: expected_rule format fixes (5 patterns)
│   └── SSTI_SMARTY_001, API_BOLA_001, API_JWT_001, API_MASS_001, NOSQL_COUCH_001/002
└── TASK-A-3: Alternative detection pattern fixes (6 patterns)
    └── SSTI_THYME_001, SSTI_PEBBLE_001, SSTI_TWIG_001, SSTI_MAKO_001, NOSQL_REDIS_002, NOSQL_MONGO_003
```

### Key Documents Created

| Document | Version | Description |
|----------|---------|-------------|
| ISSUE_56_MISMATCH_ROOT_CAUSE_ANALYSIS.md | v1.0.0 | Root cause analysis of 13 mismatches |
| ISSUE_56_RECOMMENDED_ACTIONS_REQUIREMENTS.md | v3.0.0 | Requirements definition |
| ISSUE_56_TASK_DEFINITION.md | v3.0.0 | Task definition with implementation details |

---

## Technology Stack

### Core Technologies
| Technology | Version | Purpose |
|------------|---------|---------|
| Go | 1.21+ | Plugin development |
| Falco Plugin SDK | v0.8.1 | Plugin framework |
| Falco | 0.36.0+ | Security engine |
| nginx | 1.18.0+ | Monitored server |

### CI/CD
- **GitHub Actions**: Self-hosted runners (REQUIRED)
- **CRITICAL**: `ubuntu-latest` is PROHIBITED (cost savings)
- **Runner Label**: `[self-hosted, linux, x64, local]`

---

## Key Files and Directories

### Source Code
| Path | Description |
|------|-------------|
| `cmd/plugin-sdk/nginx.go` | Main plugin (SDK version) |
| `pkg/parser/nginx.go` | Log parser implementation |
| `rules/nginx_rules.yaml` | Falco security rules |

### E2E Testing
| Path | Description |
|------|-------------|
| `e2e/patterns/*.json` | 300 attack patterns |
| `e2e/scripts/batch_analyzer.py` | Pattern analysis |
| `e2e/allure/test_e2e_wrapper.py` | Allure test wrapper |

### Issue #56 Documentation
| Path | Description |
|------|-------------|
| `claudedocs/ISSUE_56_TASK_DEFINITION.md` | Task definition v3.0.0 |
| `claudedocs/ISSUE_56_RECOMMENDED_ACTIONS_REQUIREMENTS.md` | Requirements v3.0.0 |
| `claudedocs/ISSUE_56_MISMATCH_ROOT_CAUSE_ANALYSIS.md` | Root cause analysis |

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

## Important Patterns

### Pattern #A316: Exception Syntax
```yaml
# Single field MUST use comps: in
exceptions:
  - name: my_exception
    fields: nginx.pattern_id
    comps: in              # ← REQUIRED for single field
    values:
      - PATTERN_A
```

### Pattern #A327: Pre-verification
Before adding exceptions, verify the target rule can actually detect the pattern.

### Pattern #A331: Generic expected_rule Issue
Using generic expected_rule (e.g., "API Security Attack Attempt") causes validation failures due to Falco's prefix-based output format.

---

## Next Steps (Priority Order)

### 🔴 Highest Priority: TASK-A-1 (Exception Additions)

**Steps**:
1. Pattern #A327 pre-verification (confirm target rule detects pattern)
2. Add exceptions to generic rules (Pattern #A316 syntax)
3. E2E test verification

**Target Patterns**:
| Pattern ID | Wrong Rule | Correct Rule |
|------------|------------|--------------|
| NOSQL_MONGO_003 | SQLi | MongoDB NoSQL |
| NOSQL_REDIS_001 | XSS | Redis Command Injection |
| API_IDOR_001 | SQLi | API Security |
| API_PROTO_001 | Template Injection | API Security |

### 🟡 High Priority: TASK-A-2 (Format Fixes)
5 patterns with format mismatch - update expected_rule to Falco output format

### 🟢 Medium Priority: TASK-A-3 (Alternative Detection Fixes)
6 patterns with valid alternative detection - update expected_rule

---

## Open Issues (Public Repo)

| Issue | Title | Priority |
|-------|-------|----------|
| #56 | E2E Tests #83: Rule Mapping Mismatch (15 patterns) - Pattern #A331 | Active |

## Open Issues (Private Repo - Top 5)

| Issue | Title | Priority |
|-------|-------|----------|
| #718 | E2Eテストシステム再構築 | P1-high |
| #705 | Issue #701 Investigation | P2-medium |
| #360 | Phase2-E2E-Sec: 65→125パターン | P1-high |
| #358 | Phase2-E2E-Sec: 攻撃パターンDB構築 | P1-high |
| #357 | Phase1-E2E-Sec: テスト基盤構築 | P1-high |

---

## Useful Memories (Serena)

| Memory | Content |
|--------|---------|
| `current_work_context` | Latest session state |
| `development_diary_2026_01_11` | Today's work log |
| `development_diary_2026_01_10` | Previous work log |
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

# 3. View Issue #56
gh issue view 56 --repo takaosgb3/falco-plugin-nginx

# 4. Read key documents
# - claudedocs/ISSUE_56_TASK_DEFINITION.md
# - claudedocs/ISSUE_56_RECOMMENDED_ACTIONS_REQUIREMENTS.md

# 5. Read relevant memories
# Use Serena: read_memory("current_work_context")
# Use Serena: read_memory("development_diary_2026_01_11")
```

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
```

---

*Generated: 2026-01-11*
*Version: v20.0.0*
