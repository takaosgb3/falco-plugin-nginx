# Issue #15: E2E XSS Pattern expected_rule MISMATCH

## 概要

Run #22 Allure Report で XSS パターン（11件）において Match Status: MISMATCH が発生している問題の分析と修正タスク定義書。

**作成日**: 2025-12-07
**Issue URL**: https://github.com/takaosgb3/falco-plugin-nginx/issues/15
**分析ブランチ**: `analysis/issue-xss-expected-rule-mismatch`

---

## 問題の概要

### 症状

- Run #22 Allure Report: https://takaosgb3.github.io/falco-plugin-nginx/e2e-report/22/
- **影響パターン数**: 11件（XSS_REFL_001 〜 XSS_REFL_011）
- **症状**: Match Status が MISMATCH

### 根本原因

`e2e/patterns/xss_patterns.json` の `expected_rule` 値が、実際にトリガーされる Falco ルール名と一致していない。

| 設定値 | 実際のルール |
|--------|-------------|
| `DOM-based XSS Attack` | `XSS Filter Bypass Attempt` |

---

## 技術的詳細

### 1. XSS Filter Bypass Attempt がトリガーされる理由

`rules/nginx_rules.yaml:843-872`:
```yaml
- rule: XSS Filter Bypass Attempt
  condition: >-
    (
      nginx.request_uri icontains "script" or  # ← <script> タグにマッチ
      nginx.request_uri contains "%00" or
      ...
    )
```

XSS_REFL_001 のペイロード `<script>alert('XSS')</script>` は `script` を含むため、このルールにマッチする。

### 2. DOM-based XSS Attack がトリガーされない理由

`rules/nginx_rules.yaml:643-666`:
- 条件: `javascript:`, `data:text/html`, `<iframe src=`, `<object data=` など
- `<script>` タグの直接的なパターンは**含まれていない**

### 3. マッチング論理

`e2e/allure/test_e2e_wrapper.py:215-223`:
```python
if expected_lower in actual_lower or actual_lower in expected_lower:
    rule_match_status = "MATCH"
else:
    rule_match_status = "MISMATCH"
```

- `"dom-based xss attack"` ⊄ `"xss filter bypass attempt"` → **MISMATCH**

---

## パターン詳細

| パターンID | ペイロード | 現在の expected_rule | トリガーされるルール |
|-----------|-----------|---------------------|-------------------|
| XSS_REFL_001 | `<script>alert('XSS')</script>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_002 | `<img src=x onerror=alert('XSS')>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_003 | `<svg onload=alert('XSS')>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_004 | `<iframe src=javascript:alert('XSS')>` | DOM-based XSS Attack | 要検証（両方マッチ可能） |
| XSS_REFL_005 | `<body onload=alert('XSS')>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_006 | `<input onfocus=alert('XSS') autofocus>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_007 | `<select onfocus=alert('XSS') autofocus>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_008 | `<textarea onfocus=alert('XSS') autofocus>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_009 | `<keygen onfocus=alert('XSS') autofocus>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_010 | `<video><source onerror=alert('XSS')>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |
| XSS_REFL_011 | `<audio src=x onerror=alert('XSS')>` | DOM-based XSS Attack | XSS Filter Bypass Attempt |

---

## 修正タスク

### Phase 1: 検証

- [ ] Task 1.1: XSS_REFL_004 (`<iframe src=javascript:...`) の実際のトリガールールを確認
- [ ] Task 1.2: 各パターンがトリガーする正確なルール名を E2E ログで確認

### Phase 2: パターンファイル修正

- [ ] Task 2.1: `e2e/patterns/xss_patterns.json` の `expected_rule` を更新
  - XSS_REFL_001,002,003,005-011: `"XSS Filter Bypass Attempt"`
  - XSS_REFL_004: 検証結果に基づく

### Phase 3: テスト

- [ ] Task 3.1: E2E Security Tests ワークフローを実行
- [ ] Task 3.2: Allure Report で MATCH ステータスを確認

---

## 関連情報

### 先行 Issue/PR

| PR/Issue | 内容 | 影響 |
|----------|------|-----|
| PR #13 | SQLi, Path, CMDI, Other の expected_rule 修正（39パターン） | XSS は対象外 |
| PR #14 | 大文字小文字を区別しない比較に修正 | 論理は正しいがXSSのexpected_rule値が間違っている |

### 関連パターン（PROBLEM_PATTERNS.md）

- **Pattern #A254**: Overly Broad Pattern Matching (%28) - 類似の誤検出問題
- **Pattern #A303**: icontains Optimization - XSS ルールの最適化履歴

### 関連ファイル

- `e2e/patterns/xss_patterns.json` - 修正対象
- `rules/nginx_rules.yaml` (行843-872) - XSS Filter Bypass Attempt ルール
- `e2e/allure/test_e2e_wrapper.py` (行215-223) - マッチング論理

---

## 教訓

1. **パターンファイル作成時**: 実際の Falco ルールとペイロードのマッチングを必ず検証する
2. **expected_rule の設定**: ルール名は Falco の実際の出力と完全一致させる
3. **カテゴリ別検証**: 新しいカテゴリ追加時は、必ず E2E テストで MATCH を確認する

---

**最終更新**: 2025-12-07
