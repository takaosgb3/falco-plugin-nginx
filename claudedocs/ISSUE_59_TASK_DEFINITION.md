# Issue #59 Task Definition v1.1.0

## Document Info
| Item | Value |
|------|-------|
| Issue | [#59](https://github.com/takaosgb3/falco-plugin-nginx/issues/59) |
| Title | E2E Report: Add Rule Mapping Trend graph to Allure Report |
| Priority | P3 (Low) |
| Created | 2026-01-12 |
| Updated | 2026-01-12 |
| Origin | Issue #56 TASK-C |
| **Approach** | **Allure Categories Trend (既存Graphs TRENDと同形式)** |

---

## 1. Background

Issue #56 でRule Mapping Mismatchを15件から0件に改善しました。今後もMismatch率をモニタリングするため、トレンドグラフによる可視化が有用です。

### 1.1 Current State Analysis

現在のE2E環境では:
- ✅ 各テストごとにRule Mapping状態を表示 (`format_rule_match_status()`)
- ✅ Allure標準のトレンドグラフ（pass/fail推移）が動作
- ❌ Rule Mapping統計の集計がない
- ❌ Rule Mapping統計の履歴保存がない
- ❌ Rule Mapping専用のトレンドグラフがない

### 1.2 Rule Mapping Status Types

| Status | Meaning | Ideal State |
|--------|---------|-------------|
| ✅ Match | Expected rule = Matched rule | 高いほど良い |
| ✅ Expected Not Detected | expected_detection: false | 正常（負テスト） |
| ❌ Mismatch | Expected rule ≠ Matched rule | 0が理想 |
| ⚠️ Not Defined | expected_rule未定義 | 減らすべき |

---

## 2. Functional Requirements

### FR-001: Rule Mapping Statistics Calculation

**As a** E2E test operator,
**I want** Rule Mapping statistics to be calculated after each run,
**So that** I can see the overall health of rule mappings.

**Metrics to calculate:**
```json
{
  "run_number": 100,
  "timestamp": "2026-01-12T10:00:00Z",
  "total_patterns": 100,
  "rule_mapping": {
    "match": 95,
    "mismatch": 0,
    "expected_not_detected": 3,
    "not_defined": 2
  },
  "match_rate": 0.95,
  "mismatch_rate": 0.00
}
```

### FR-002: History Data Storage

**As a** system,
**I want** to store Rule Mapping statistics for past N runs,
**So that** trend graphs can be rendered.

**Requirements:**
- Store last 10 runs (configurable via TREND_HISTORY_COUNT)
- Persist in gh-pages branch (e2e-report/history/)
- JSON format for easy parsing

### FR-003: Trend Graph Visualization

**As a** user viewing Allure Report,
**I want** to see a Rule Mapping trend graph,
**So that** I can monitor match rate over time.

**Requirements:**
- Line chart showing Match Rate % over time
- X-axis: Run numbers (last N runs)
- Y-axis: Rate percentage (0-100%)
- Hover to see detailed metrics

---

## 3. Implementation Options Analysis

### Option A: Allure History Feature Extension

**Approach:** Use Allure's built-in history-trend.json mechanism

**Pros:**
- Integrated with Allure ecosystem
- Automatic trend graph rendering

**Cons:**
- Limited customization
- Complex to add custom metrics
- Allure history format is designed for pass/fail only

**Effort:** Medium-High
**Recommendation:** ❌ Not recommended (limited flexibility)

### Option B: Allure Custom Widget

**Approach:** Add custom widget to Allure report

**Pros:**
- Appears in Allure UI
- Can use Chart.js inside widget

**Cons:**
- Requires understanding Allure plugin system
- May break with Allure updates
- Complex deployment

**Effort:** High
**Recommendation:** ❌ Not recommended (complexity vs benefit)

### Option C: Separate Dashboard on GitHub Pages ⭐ RECOMMENDED

**Approach:** Create standalone HTML dashboard alongside Allure Report

**Pros:**
- Full control over visualization
- Simple implementation
- Easy to maintain
- Works independently of Allure
- Can use Chart.js or similar

**Cons:**
- Not integrated into Allure UI (separate page)

**Effort:** Low-Medium
**Recommendation:** ✅ Recommended (best effort/value ratio for P3)

---

## 4. Implementation Plan (Option C)

### 4.1 New Files to Create

```
e2e/
├── scripts/
│   └── generate_trend_data.py     # Calculate and store trend data
├── trend-dashboard/
│   └── index.html                 # Standalone trend dashboard
└── ...
```

### 4.2 Workflow Changes

```yaml
# e2e-test.yml additions

# After step 9 (Analyze test results):
- name: Generate trend data
  run: |
    python e2e/scripts/generate_trend_data.py \
      --results e2e/results/test-results.json \
      --run-number ${{ github.run_number }} \
      --output e2e/trend-data.json

# Modified step 10 (Download history):
- name: Download trend history
  run: |
    # Download existing trend-history.json from gh-pages
    git show gh-pages:e2e-report/history/trend-history.json > trend-history.json || echo "[]" > trend-history.json

# After step 11 (Generate Allure Report):
- name: Generate trend dashboard
  run: |
    # Merge new data into history
    python e2e/scripts/merge_trend_history.py \
      --new-data e2e/trend-data.json \
      --history trend-history.json \
      --output e2e/trend-dashboard/trend-history.json

    # Copy dashboard template
    cp e2e/trend-dashboard/index.html e2e/allure-report/trend/
    cp e2e/trend-dashboard/trend-history.json e2e/allure-report/trend/

# Deploy includes trend dashboard and history
```

### 4.3 Task Breakdown

| Task | Description | Effort |
|------|-------------|--------|
| TASK-1 | Create `generate_trend_data.py` | 1h |
| TASK-2 | Create `merge_trend_history.py` | 0.5h |
| TASK-3 | Create `trend-dashboard/index.html` with Chart.js | 1h |
| TASK-4 | Update `e2e-test.yml` workflow | 0.5h |
| TASK-5 | Test and verify | 0.5h |
| TASK-6 | Documentation | 0.5h |
| **Total** | | **4h** |

---

## 5. Detailed Task Specifications

### TASK-1: generate_trend_data.py

**Purpose:** Calculate Rule Mapping statistics from test-results.json

**Input:** `e2e/results/test-results.json`
**Output:** `e2e/trend-data.json`

```python
#!/usr/bin/env python3
"""Generate trend data from test results"""

def calculate_rule_mapping_stats(test_results: List[Dict]) -> Dict:
    """
    Calculate Rule Mapping statistics from test results

    Returns:
        {
            "match": count,
            "mismatch": count,
            "expected_not_detected": count,
            "not_defined": count,
            "match_rate": float,
            "mismatch_rate": float
        }
    """
    # Logic based on format_rule_match_status() from test_e2e_wrapper.py
```

### TASK-2: merge_trend_history.py

**Purpose:** Merge new run data into history, keep last N runs

**Input:**
- `e2e/trend-data.json` (new data)
- `trend-history.json` (existing history)

**Output:** `e2e/trend-dashboard/trend-history.json`

```python
#!/usr/bin/env python3
"""Merge trend data into history"""

def merge_and_trim(new_data: Dict, history: List[Dict], max_runs: int = 10) -> List[Dict]:
    """
    Append new data to history and keep only last N runs
    """
```

### TASK-3: trend-dashboard/index.html

**Purpose:** Standalone dashboard with Chart.js visualization

**Features:**
- Line chart: Match Rate % over time
- Stacked bar chart: Status breakdown per run
- Table: Detailed metrics per run
- Responsive design
- Dark theme (matches Allure style)

### TASK-4: Workflow Integration

**Changes to e2e-test.yml:**
1. Add step to generate trend data
2. Modify history download to include trend-history.json
3. Add step to generate trend dashboard
4. Update deploy to include trend/ directory

### TASK-5: Testing

- Local test with sample data
- Full E2E workflow run
- Verify trend graph renders correctly
- Verify history accumulates correctly

### TASK-6: Documentation

- Update e2e/README.md with trend dashboard info
- Add link to trend dashboard in Allure Report
- Document configuration options

---

## 6. Acceptance Criteria

- [ ] Rule Mapping統計が各E2E実行後に計算される
- [ ] 過去10回分の統計が履歴として保存される
- [ ] トレンドダッシュボードがGitHub Pagesで公開される
- [ ] Match Rate %の推移がグラフで確認できる
- [ ] ダッシュボードへのリンクがAllure Reportに含まれる

---

## 7. Out of Scope

- Allure UIへの直接統合
- カテゴリ別のトレンド分析
- 自動アラート（Match Rateが低下した場合）

---

## 8. References

- [Issue #59](https://github.com/takaosgb3/falco-plugin-nginx/issues/59)
- [Issue #56](https://github.com/takaosgb3/falco-plugin-nginx/issues/56)
- [test_e2e_wrapper.py](../e2e/allure/test_e2e_wrapper.py)
- [e2e-test.yml](../.github/workflows/e2e-test.yml)
- [Chart.js Documentation](https://www.chartjs.org/docs/latest/)

---

*Document Version: 1.0.0*
*Created: 2026-01-12*
