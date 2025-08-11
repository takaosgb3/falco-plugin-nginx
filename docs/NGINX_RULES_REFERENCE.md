# Nginx Rules Reference Guide

> **Falco Nginx Plugin セキュリティルール完全解説**
>
> Version: 0.3.1 | Compatible with: Falco Plugin SDK for Go
> Last Updated: 2025-08-11

## 🎯 目次

- [概要](#概要)
- [ルール分類](#ルール分類)
- [セキュリティ攻撃検出ルール](#セキュリティ攻撃検出ルール)
  - [SQL Injection Attack](#sql-injection-attempt)
  - [XSS Attack](#xss-attack-attempt)
  - [Path Traversal Attack](#path-traversal-attempt)
  - [Command Injection Attack](#command-injection-attempt)
  - [Sensitive File Access](#sensitive-file-access-attempt)
- [偵察・スキャン検出ルール](#偵察スキャン検出ルール)
  - [Suspicious User Agent](#suspicious-user-agent)
- [認証攻撃検出ルール](#認証攻撃検出ルール)
  - [Brute Force Attack](#multiple-failed-login-attempts)
- [システム監視ルール](#システム監視ルール)
  - [HTTP Client Error](#http-client-error)
  - [HTTP Server Error](#http-server-error)
  - [Large Response Body](#large-response-body)
- [カスタマイズガイド](#カスタマイズガイド)
- [トラブルシューティング](#トラブルシューティング)

---

## 概要

Falco Nginx Pluginのセキュリティルールは、nginx アクセスログをリアルタイムで監視し、様々なWebアプリケーション攻撃を検出します。全10個のルールは、**MECE（Mutually Exclusive, Collectively Exhaustive）**の原則に基づき、以下の4つのカテゴリーに分類されています：

### ルール分類

| カテゴリー | ルール数 | 重要度 | 目的 |
|-----------|---------|--------|------|
| **セキュリティ攻撃検出** | 5個 | CRITICAL/WARNING | 実際の攻撃を即座に検出・阻止 |
| **偵察・スキャン検出** | 1個 | NOTICE | 攻撃前段階の偵察活動を検出 |
| **認証攻撃検出** | 1個 | NOTICE | ブルートフォース等の認証攻撃 |
| **システム監視** | 3個 | INFO/NOTICE | システムの異常状態を監視 |

---

## セキュリティ攻撃検出ルール

### 🔴 SQL Injection Attempt {#sql-injection-attempt}

> **最重要セキュリティルール** - データベース攻撃を即座に検出

#### 概要
SQLインジェクション攻撃を検出します。攻撃者がWebアプリケーションの入力フィールドに悪意あるSQLコードを挿入し、データベースを不正操作しようとする試みを検知します。

#### 検出パターン

```yaml
condition: >
  (nginx.path contains "' OR" or nginx.query_string contains "' OR") or
  (nginx.path contains "' AND" or nginx.query_string contains "' AND") or
  (nginx.path contains "UNION SELECT" or nginx.query_string contains "UNION SELECT") or
  (nginx.path contains "; DROP" or nginx.query_string contains "; DROP") or
  (nginx.path contains "/*" or nginx.query_string contains "/*") or
  (nginx.path contains "*/" or nginx.query_string contains "*/")
```

#### 検出対象の攻撃手法

| パターン | 攻撃手法 | 例 |
|---------|---------|-----|
| `' OR` | 認証バイパス | `admin' OR '1'='1` |
| `' AND` | 条件変更攻撃 | `user' AND password='pass` |
| `UNION SELECT` | データ抽出攻撃 | `1' UNION SELECT username,password FROM users--` |
| `; DROP` | データ破壊攻撃 | `'; DROP TABLE users;--` |
| `/*`, `*/` | SQLコメント挿入 | `admin'/**/OR/**/1=1--` |

#### アラート情報

- **重要度**: `CRITICAL` 🔴
- **タグ**: `[attack, sql_injection, web]`
- **出力形式**:
```
SQL injection attempt detected
(remote_addr=192.168.1.100 method=POST path=/login query=user=admin' OR '1'='1 status=200 user_agent=Mozilla/5.0...)
```

#### 対応アクション
1. **即座の対応**: 該当IPアドレスからのトラフィックを一時ブロック
2. **調査**: アクセスログで攻撃の詳細パターンを確認
3. **修正**: Webアプリケーションのパラメータ検証を強化

---

### 🟡 XSS Attack Attempt {#xss-attack-attempt}

> **クライアントサイド攻撃検出** - ブラウザ攻撃を防御

#### 概要
クロスサイトスクリプティング（XSS）攻撃を検出します。攻撃者が悪意あるJavaScriptコードをWebページに挿入し、他のユーザーのブラウザで実行させようとする試みを検知します。

#### 検出パターン

```yaml
condition: >
  (nginx.path contains "<script" or nginx.query_string contains "<script") or
  (nginx.path contains "javascript:" or nginx.query_string contains "javascript:") or
  (nginx.path contains "onerror=" or nginx.query_string contains "onerror=") or
  (nginx.path contains "onload=" or nginx.query_string contains "onload=") or
  (nginx.path contains "<iframe" or nginx.query_string contains "<iframe") or
  (nginx.path contains "<object" or nginx.query_string contains "<object")
```

#### 検出対象の攻撃手法

| パターン | 攻撃手法 | 例 |
|---------|---------|-----|
| `&lt;script` | 直接スクリプト挿入 | `&lt;script&gt;alert('XSS')&lt;/script&gt;` |
| `javascript:` | JavaScriptプロトコル | `javascript:alert(document.cookie)` |
| `onerror=` | イベントハンドラ悪用 | `&lt;img src=x onerror=alert(1)&gt;` |
| `onload=` | ロードイベント悪用 | `&lt;body onload=alert('XSS')&gt;` |
| `&lt;iframe` | 外部コンテンツ埋め込み | `&lt;iframe src="javascript:alert(1)"&gt;` |
| `&lt;object` | オブジェクト埋め込み | `&lt;object data="javascript:alert(1)"&gt;` |

#### アラート情報

- **重要度**: `WARNING` 🟡
- **タグ**: `[attack, xss, web]`
- **出力形式**:
```
XSS attack attempt detected
(remote_addr=192.168.1.100 method=GET path=/search query=q=&lt;script&gt;alert(1)&lt;/script&gt; status=200)
```

#### 対応アクション
1. **入力検証**: HTMLタグのエスケープ処理を確認
2. **CSP設定**: Content Security Policyの導入・強化
3. **ログ監視**: 類似パターンの攻撃を継続監視

---

### 🟡 Path Traversal Attempt {#path-traversal-attempt}

> **ファイルシステム攻撃検出** - サーバーファイルへの不正アクセスを防御

#### 概要
パストラバーサル（ディレクトリトラバーサル）攻撃を検出します。攻撃者がWebアプリケーションの脆弱性を利用して、本来アクセスできないサーバー上のファイルにアクセスしようとする試みを検知します。

#### 検出パターン

```yaml
condition: >
  (nginx.path contains "../" or nginx.query_string contains "../") or
  (nginx.path contains "..\\" or nginx.query_string contains "..\\") or
  (nginx.path contains "/etc/" or nginx.query_string contains "/etc/") or
  (nginx.path contains "/proc/" or nginx.query_string contains "/proc/") or
  (nginx.path contains "C:\\" or nginx.query_string contains "C:\\")
```

#### 検出対象の攻撃手法

| パターン | 攻撃手法 | 対象OS | 例 |
|---------|----------|--------|-----|
| `../` | 相対パス攻撃 | Unix/Linux | `../../etc/passwd` |
| `..\\` | 相対パス攻撃 | Windows | `..\\..\\windows\\system32\\config\\sam` |
| `/etc/` | 直接パス指定 | Linux | `/etc/shadow` |
| `/proc/` | プロセス情報アクセス | Linux | `/proc/version` |
| `C:\\` | 絶対パス攻撃 | Windows | `C:\\Windows\\System32\\drivers\\etc\\hosts` |

#### アラート情報

- **重要度**: `WARNING` 🟡
- **タグ**: `[attack, path_traversal, web]`
- **出力形式**:
```
Path traversal attempt detected
(remote_addr=192.168.1.100 method=GET path=/download query=file=../../etc/passwd status=404)
```

#### 対応アクション
1. **ファイルアクセス制限**: ファイルパスの正規化とホワイトリスト検証
2. **権限設定**: Webサーバーの実行権限を最小限に制限
3. **セキュリティ監査**: ファイルアップロード・ダウンロード機能の見直し

---

### 🔴 Command Injection Attempt {#command-injection-attempt}

> **システムコマンド実行攻撃検出** - サーバー乗っ取りを防御

#### 概要
コマンドインジェクション攻撃を検出します。攻撃者がWebアプリケーションの脆弱性を利用して、サーバー上で任意のシステムコマンドを実行しようとする試みを検知します。

#### 検出パターン

```yaml
condition: >
  (nginx.path contains ";ls" or nginx.query_string contains ";ls") or
  (nginx.path contains ";cat" or nginx.query_string contains ";cat") or
  (nginx.path contains "|ls" or nginx.query_string contains "|ls") or
  (nginx.path contains "|cat" or nginx.query_string contains "|cat") or
  (nginx.path contains "&&" or nginx.query_string contains "&&") or
  (nginx.path contains "||" or nginx.query_string contains "||") or
  (nginx.path contains "`" or nginx.query_string contains "`") or
  (nginx.path contains "$(" or nginx.query_string contains "$(")
```

#### 検出対象の攻撃手法

| パターン | 攻撃手法 | 説明 | 例 |
|---------|----------|------|-----|
| `;ls`, `;cat` | コマンド連結 | セミコロンによる追加コマンド実行 | `ping 127.0.0.1;ls -la` |
| `\|ls`, `\|cat` | パイプ攻撃 | パイプによるコマンド実行 | `echo test\|cat /etc/passwd` |
| `&&` | 条件付き実行 | 前コマンド成功時に実行 | `ping google.com && ls` |
| `\|\|` | 条件付き実行 | 前コマンド失敗時に実行 | `false \|\| whoami` |
| `` ` `` | コマンド置換 | バッククォートによる実行 | `` `whoami` `` |
| `$(` | コマンド置換 | 括弧による実行 | `$(uname -a)` |

#### アラート情報

- **重要度**: `CRITICAL` 🔴
- **タグ**: `[attack, command_injection, web]`
- **出力形式**:
```
Command injection attempt detected
(remote_addr=192.168.1.100 method=POST path=/upload query=cmd=ping 127.0.0.1;ls status=500)
```

#### 対応アクション
1. **緊急対応**: 該当IPアドレスを即座にブロック
2. **システム調査**: サーバーのプロセス・ファイルシステムを確認
3. **脆弱性修正**: 入力値のサニタイズとコマンド実行の無効化

---

### 🟡 Sensitive File Access Attempt {#sensitive-file-access-attempt}

> **機密ファイルアクセス検出** - 重要な設定ファイルへのアクセスを監視

#### 概要
機密ファイルや設定ファイルへのアクセス試行を検出します。攻撃者がWebアプリケーションの設定情報や認証情報を含むファイルにアクセスしようとする試みを検知します。

#### 検出パターン

```yaml
condition: >
  nginx.path contains ".git" or
  nginx.path contains ".env" or
  nginx.path contains "wp-config" or
  nginx.path contains ".htaccess" or
  nginx.path contains ".htpasswd"
```

#### 検出対象のファイル種類

| パターン | ファイル種類 | 含まれる情報 | リスク |
|---------|-------------|-------------|-------|
| `.git` | Gitリポジトリ | ソースコード、履歴 | ソースコード漏洩 |
| `.env` | 環境設定ファイル | API KEY、DB接続情報 | 認証情報漏洩 |
| `wp-config` | WordPress設定 | DB認証情報、秘密鍵 | サイト乗っ取り |
| `.htaccess` | Apache設定ファイル | アクセス制御設定 | セキュリティ設定暴露 |
| `.htpasswd` | Basic認証ファイル | ユーザー認証情報 | アカウント情報漏洩 |

#### アラート情報

- **重要度**: `WARNING` 🟡
- **タグ**: `[attack, information_disclosure, web]`
- **出力形式**:
```
Sensitive file access attempt
(remote_addr=192.168.1.100 path=/.env status=404)
```

#### 対応アクション
1. **ファイル保護**: 機密ファイルのWebアクセス制限設定
2. **ディレクトリ構造**: Webルート外への機密ファイル移動
3. **アクセス監視**: 継続的な機密ファイルアクセス監視

---

## 偵察・スキャン検出ルール

### 🔵 Suspicious User Agent {#suspicious-user-agent}

> **攻撃ツール検出** - 自動化された攻撃を事前に検知

#### 概要
既知の攻撃ツールやスキャンツールによるアクセスを検出します。攻撃者が情報収集や脆弱性スキャンに使用する一般的なツールを特定します。

#### 検出パターン

```yaml
condition: >
  nginx.user_agent contains "sqlmap" or
  nginx.user_agent contains "nikto" or
  nginx.user_agent contains "nmap" or
  nginx.user_agent contains "masscan" or
  nginx.user_agent contains "scanner"
```

#### 検出対象ツール

| ツール名 | 種類 | 主な用途 | 危険度 |
|---------|------|---------|--------|
| `sqlmap` | SQLインジェクションツール | DBへの攻撃自動化 | 高 |
| `nikto` | Webスキャンツール | Web脆弱性スキャン | 中 |
| `nmap` | ネットワークスキャンツール | ポート・サービス探索 | 中 |
| `masscan` | 高速ポートスキャンツール | 大量ポートスキャン | 中 |
| `scanner` | 一般的なスキャンツール | 各種脆弱性スキャン | 中 |

#### アラート情報

- **重要度**: `NOTICE` 🔵
- **タグ**: `[reconnaissance, scanner, web]`
- **出力形式**:
```
Suspicious user agent detected
(remote_addr=192.168.1.100 user_agent=sqlmap/1.4.7 path=/ query=)
```

#### 対応アクション
1. **IP監視**: 該当IPアドレスのアクティビティを継続監視
2. **トラフィック制限**: 必要に応じてレート制限を適用
3. **セキュリティ強化**: 検出されたスキャンに対する防御設定

---

## 認証攻撃検出ルール

### 🔵 Multiple Failed Login Attempts {#multiple-failed-login-attempts}

> **ブルートフォース攻撃検出** - パスワード総当たり攻撃を検知

#### 概要
ログインページに対する失敗した認証試行を検出します。攻撃者がパスワードを総当たりで試行するブルートフォース攻撃の単一試行を検知します。

#### 検出パターン

```yaml
condition: >
  nginx.path contains "/login" and
  (nginx.status = 401 or nginx.status = 403)
```

#### 検出条件

| 条件 | 説明 | 目的 |
|------|------|------|
| `nginx.path contains "/login"` | ログインページへのアクセス | 認証エンドポイントの特定 |
| `nginx.status = 401` | 認証が必要（Unauthorized） | 認証失敗の検出 |
| `nginx.status = 403` | アクセス禁止（Forbidden） | アクセス拒否の検出 |

#### アラート情報

- **重要度**: `NOTICE` 🔵
- **タグ**: `[brute_force, authentication, web]`
- **出力形式**:
```
Failed login attempt
(remote_addr=192.168.1.100 path=/login status=401 user_agent=Mozilla/5.0...)
```

#### 対応アクション
1. **頻度分析**: 同一IPからの連続失敗試行を監視
2. **アカウント保護**: 一定回数失敗後のアカウントロック
3. **IP制限**: 異常な試行数のIPアドレスをブロック

---

## システム監視ルール

### 🟢 HTTP Client Error {#http-client-error}

> **クライアントエラー監視** - 4xx系エラーの発生を追跡

#### 概要
HTTP 4xx系のクライアントエラーを監視します。不正なリクエストや存在しないリソースへのアクセスなど、クライアント側の問題によるエラーを記録します。

#### 検出パターン

```yaml
condition: nginx.status >= 400 and nginx.status < 500
```

#### 検出対象ステータスコード

| ステータス | 名称 | 意味 | 一般的な原因 |
|-----------|------|------|-------------|
| 400 | Bad Request | 不正なリクエスト | 構文エラー、不正パラメータ |
| 401 | Unauthorized | 認証が必要 | 認証情報なし・無効 |
| 403 | Forbidden | アクセス禁止 | 権限なし、IP制限 |
| 404 | Not Found | リソースなし | 存在しないページ・ファイル |
| 405 | Method Not Allowed | メソッド不許可 | 無効なHTTPメソッド |

#### アラート情報

- **重要度**: `INFO` 🟢
- **タグ**: `[error, web]`
- **出力形式**:
```
HTTP client error
(remote_addr=192.168.1.100 status=404 path=/nonexistent method=GET)
```

#### 対応アクション
1. **パターン分析**: 頻発する404エラーのパターンを確認
2. **リダイレクト設定**: よくアクセスされる存在しないパスのリダイレクト
3. **監視調整**: 正常な404エラーの除外設定

---

### 🔵 HTTP Server Error {#http-server-error}

> **サーバーエラー監視** - 5xx系エラーでシステム異常を検出

#### 概要
HTTP 5xx系のサーバーエラーを監視します。Webアプリケーションやサーバーの問題による内部エラーを検出し、システムの健全性を監視します。

#### 検出パターン

```yaml
condition: nginx.status >= 500
```

#### 検出対象ステータスコード

| ステータス | 名称 | 意味 | 一般的な原因 |
|-----------|------|------|-------------|
| 500 | Internal Server Error | 内部サーバーエラー | アプリケーション例外、設定エラー |
| 501 | Not Implemented | 未実装 | 対応していない機能の要求 |
| 502 | Bad Gateway | 不正なゲートウェイ | バックエンドサーバーの異常 |
| 503 | Service Unavailable | サービス利用不可 | サーバー過負荷、メンテナンス |
| 504 | Gateway Timeout | ゲートウェイタイムアウト | バックエンド応答遅延 |

#### アラート情報

- **重要度**: `NOTICE` 🔵
- **タグ**: `[error, server, web]`
- **出力形式**:
```
HTTP server error detected
(remote_addr=192.168.1.100 status=500 path=/api/data method=POST)
```

#### 対応アクション
1. **即座の調査**: サーバーログでエラーの詳細を確認
2. **システム監視**: CPU、メモリ、ディスク使用量の確認
3. **スケールアップ**: 必要に応じてリソースの増強

---

### 🟢 Large Response Body {#large-response-body}

> **異常レスポンス検出** - 大容量データ転送の監視

#### 概要
異常に大きなレスポンスボディを検出します。データ漏洩や設定ミス、DoS攻撃などによる大量データ転送を監視します。

#### 検出パターン

```yaml
condition: nginx.bytes_sent > 10485760
```

#### 検出閾値

| 設定値 | サイズ | 用途 |
|--------|-------|------|
| `10485760` | 10MB | 一般的なWebレスポンスの上限 |

#### 想定される原因

| シナリオ | リスク | 対応の緊急度 |
|---------|-------|-----------|
| データダンプ攻撃 | データ漏洩 | 高 |
| ファイルダウンロード | 正常動作 | 低 |
| 設定ミス（エラーページ等） | システム負荷 | 中 |
| DoS攻撃 | リソース枯渇 | 高 |

#### アラート情報

- **重要度**: `INFO` 🟢
- **タグ**: `[anomaly, web]`
- **出力形式**:
```
Large response body detected
(remote_addr=192.168.1.100 size=15728640 path=/download method=GET)
```

#### 対応アクション
1. **内容確認**: 転送されたデータの内容と正当性を確認
2. **レート制限**: 大容量転送に対する制限設定
3. **監視強化**: 該当IPアドレスの継続監視

---

## カスタマイズガイド

### ルールの重要度変更

```yaml
# 例：SQL Injectionを最高警戒レベルに設定
- rule: SQL Injection Attempt
  priority: EMERGENCY  # CRITICAL → EMERGENCY に変更
```

### 検出パターンの追加

```yaml
# 例：新しいSQLインジェクションパターンを追加
condition: >
  # 既存の条件... or
  (nginx.path contains "EXEC(" or nginx.query_string contains "EXEC(")
```

### 除外条件の追加

```yaml
# 例：特定パスを監視対象から除外
condition: >
  # 既存の条件... and
  not nginx.path startswith "/api/health"
```

### カスタムフィールドの活用

```yaml
# 例：リクエスト時間による異常検出
- rule: Slow Response Time
  condition: nginx.request_time > 5000  # 5秒以上
  priority: WARNING
```

---

## トラブルシューティング

### よくある問題

#### 1. ルールが発動しない
- **原因**: フィールド名の間違い、条件の記述ミス
- **解決**: `nginx.` プレフィックスの確認、YAMLファイル構文チェック

#### 2. 大量の誤検知
- **原因**: 閾値設定が厳しすぎる、正常トラフィックとの区別不足
- **解決**: 除外条件の追加、閾値の調整

#### 3. パフォーマンス問題
- **原因**: 複雑な正規表現、大量のルール評価
- **解決**: 条件の最適化、不要ルールの無効化

### デバッグ手順

1. **Falco設定確認**
   ```bash
   sudo falco --dry-run
   ```

2. **ルール構文チェック**
   ```bash
   sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
   ```

3. **ログレベル上げて詳細確認**
   ```yaml
   log_level: DEBUG
   ```

4. **テスト環境での検証**
   ```bash
   # SQLインジェクションテスト
   curl "http://localhost/test?id=1' OR '1'='1"
   ```

---

## 関連リンク

- [Falco公式ドキュメント](https://falco.org/docs/)
- [nginx アクセスログ設定](https://nginx.org/en/docs/http/ngx_http_log_module.html)
- [Falco Plugin SDK](https://github.com/falcosecurity/plugin-sdk-go)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 更新履歴

| バージョン | 日付 | 変更内容 |
|-----------|------|---------|
| 0.3.1 | 2025-08-11 | 初期版リリース、全10ルール定義 |

---

> 📝 **Note**: このドキュメントは Falco Nginx Plugin のセキュリティルールを包括的に解説しています。実際の運用環境では、組織のセキュリティポリシーと要件に応じてルールをカスタマイズしてください。