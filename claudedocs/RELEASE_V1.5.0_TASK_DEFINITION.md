# Release v1.5.0 Task Definition Document

## Document Info

| Item | Value |
|------|-------|
| Version | v1.0.0 |
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
| セルフホスト停止 | プライベートリポジトリでのワークフロー失敗 | 事前確認 |

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

*Document Version: v1.0.0*
*Last Updated: 2026-01-12*
