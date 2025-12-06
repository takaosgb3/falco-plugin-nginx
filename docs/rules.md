# Rule Writing Guide / ルール作成ガイド

> Version: 1.4.2 | Last Updated: 2025-12-06

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

This guide explains how to write custom rules for the Falco nginx plugin.

### Basic Rule Structure

Every nginx plugin rule must have these components:

```yaml
- rule: Rule Name
  desc: Description of what the rule detects
  condition: Detection logic using nginx fields
  output: Alert message with field interpolation
  priority: EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG
  tags: [tag1, tag2]
  source: nginx  # Required for plugin rules
```

### Available Fields

The nginx plugin provides these fields for use in conditions and output:

| Field | Type | Description |
|-------|------|-------------|
| `nginx.remote_addr` | string | Client IP address |
| `nginx.remote_user` | string | Authenticated username |
| `nginx.time_local` | string | Request timestamp |
| `nginx.method` | string | HTTP method (GET, POST, etc.) |
| `nginx.path` | string | Request path without query string |
| `nginx.query_string` | string | Query string parameters |
| `nginx.request_uri` | string | Full URI (path + query string) |
| `nginx.protocol` | string | HTTP protocol version |
| `nginx.status` | number | HTTP response status code |
| `nginx.bytes_sent` | number | Total response size in bytes |
| `nginx.referer` | string | HTTP Referer header |
| `nginx.user_agent` | string | HTTP User-Agent header |
| `nginx.log_path` | string | Log file path |
| `nginx.raw` | string | Raw log line (useful for debugging) |
| `nginx.headers[key]` | string | HTTP header value by key (e.g., `nginx.headers[X-Forwarded-For]`) |

### Condition Operators

#### String Operators
- `contains` - Substring match (case-sensitive)
- `icontains` - Case-insensitive substring match (**recommended for security patterns**)
- `startswith` - Prefix match
- `endswith` - Suffix match
- `=` - Exact match
- `!=` - Not equal

> **Note**: For security detection rules, use `icontains` instead of `contains` to catch attack patterns regardless of case. For example, `nginx.request_uri icontains "' OR"` will match `' or`, `' OR`, and `' Or`.

#### Numeric Operators
- `=`, `!=` - Equality
- `<`, `>`, `<=`, `>=` - Comparison

#### Logical Operators
- `and` - Both conditions must be true
- `or` - Either condition must be true
- `not` - Negation

### Rule Examples

#### Basic Attack Detection

```yaml
- rule: SQL Injection Attempt
  desc: Detects common SQL injection patterns (case-insensitive)
  condition: >
    nginx.request_uri icontains "' OR" or
    nginx.request_uri icontains "UNION SELECT" or
    nginx.request_uri icontains "'; DROP" or
    nginx.request_uri icontains "%27%20OR"
  output: "SQL injection detected (ip=%nginx.remote_addr uri=%nginx.request_uri method=%nginx.method)"
  priority: CRITICAL
  tags: [attack, sql_injection]
  source: nginx
```

> **Best Practice**: Use `icontains` for security detection to catch variations like `' or`, `' OR`, and `' Or`. Also include URL-encoded patterns like `%27` (single quote) and `%3c` (less-than sign).

#### Response-based Detection

```yaml
- rule: Large Data Transfer
  desc: Detects unusually large responses
  condition: nginx.bytes_sent > 104857600  # 100MB
  output: "Large data transfer (ip=%nginx.remote_addr uri=%nginx.request_uri size=%nginx.bytes_sent)"
  priority: WARNING
  tags: [anomaly, data_exfiltration]
  source: nginx
```

#### Status Code Monitoring

```yaml
- rule: High Error Rate
  desc: Detects multiple 5xx errors
  condition: nginx.status >= 500 and nginx.status < 600
  output: "Server error detected (ip=%nginx.remote_addr% uri=%nginx.request_uri% status=%nginx.status%)"
  priority: ERROR
  tags: [availability, error]
  source: nginx
```

#### User Agent Detection

```yaml
- rule: Automated Scanner
  desc: Detects common security scanners
  condition: >
    nginx.user_agent icontains "sqlmap" or
    nginx.user_agent icontains "nikto" or
    nginx.user_agent icontains "nmap"
  output: "Scanner detected (ip=%nginx.remote_addr scanner=%nginx.user_agent)"
  priority: WARNING
  tags: [scanner, reconnaissance]
  source: nginx
```

#### Using HTTP Headers

```yaml
- rule: Suspicious X-Forwarded-For Header
  desc: Detects suspicious patterns in X-Forwarded-For header
  condition: >
    nginx.headers[X-Forwarded-For] icontains "'" or
    nginx.headers[X-Forwarded-For] icontains "<script"
  output: "Suspicious X-Forwarded-For header (ip=%nginx.remote_addr header=%nginx.headers[X-Forwarded-For])"
  priority: WARNING
  tags: [attack, header_injection]
  source: nginx
```

> **Note**: Use `nginx.headers[key]` to access any HTTP request header. Common headers include `X-Forwarded-For`, `Authorization`, `X-Real-IP`, etc.

#### Complex Conditions

```yaml
- rule: Admin Brute Force
  desc: Multiple failed admin login attempts
  condition: >
    nginx.path startswith "/admin" and
    nginx.method = "POST" and
    nginx.status = 401
  output: "Failed admin login (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [authentication, brute_force]
  source: nginx
```

### Best Practices

#### 1. Use Specific Conditions
```yaml
# Good - Specific path check
condition: nginx.path = "/admin/login.php"

# Less efficient - Contains check
condition: nginx.request_uri contains "admin"
```

#### 2. Combine Related Checks
```yaml
# Good - Single rule for related patterns
condition: >
  nginx.request_uri contains "<script" or
  nginx.request_uri contains "javascript:" or
  nginx.request_uri contains "onerror="

# Less efficient - Multiple separate rules
```

#### 3. Use Appropriate Priorities

Falco supports the following priority levels (from highest to lowest):

- **EMERGENCY**: System is unusable
- **ALERT**: Action must be taken immediately
- **CRITICAL**: Active attacks requiring immediate response (SQL injection, RCE)
- **ERROR**: Error conditions (server errors, failures)
- **WARNING**: Suspicious activity (scanners, failed auth)
- **NOTICE**: Anomalies (large transfers, unusual paths)
- **INFO**: Monitoring and informational events
- **DEBUG**: Debug-level messages for development

#### 4. Add Meaningful Tags
Tags help with filtering and reporting:
- `attack` - Active attack attempts
- `reconnaissance` - Information gathering
- `authentication` - Login-related events
- `anomaly` - Unusual but not necessarily malicious
- `compliance` - Regulatory compliance checks

### Testing Rules

#### 1. Validate Syntax
```bash
sudo falco --validate /etc/falco/rules.d/custom-nginx.yaml
```

#### 2. Test with Sample Requests
```bash
# Generate test traffic
curl "http://localhost/test.php?id=' OR '1'='1"

# Check if rule triggered
sudo journalctl -u falco -f | grep "SQL injection"
```

#### 3. Use Debug Output
```yaml
- rule: Debug Test
  desc: Test rule for debugging
  condition: nginx.path = "/debug-test"
  output: "DEBUG: All fields - ip=%nginx.remote_addr% method=%nginx.method% path=%nginx.path% query=%nginx.query_string%"
  priority: DEBUG
  source: nginx
```

### Performance Considerations

#### 1. Order Matters
Place most likely conditions first:
```yaml
# Efficient - Common condition first
condition: nginx.method = "POST" and nginx.path contains "admin"

# Less efficient - Expensive check first
condition: nginx.request_uri regex "complex.*pattern" and nginx.method = "POST"
```

#### 2. Avoid Complex Regex
Use simple string operations when possible:
```yaml
# Preferred
condition: nginx.path endswith ".php"

# Avoid when possible
condition: nginx.path regex ".*\\.php$"
```

#### 3. Limit Output Fields
Only include necessary fields in output:
```yaml
# Good - Relevant fields only
output: "Attack detected (ip=%nginx.remote_addr% uri=%nginx.request_uri%)"

# Verbose - May impact performance
output: "Attack (ip=%nginx.remote_addr% uri=%nginx.request_uri% ua=%nginx.http_user_agent% ref=%nginx.http_referer% status=%nginx.status%)"
```

### Advanced Examples

#### Using Macros for Reusable Patterns
```yaml
# Define reusable macros
- macro: sql_injection_patterns
  condition: >
    nginx.request_uri icontains "' OR" or
    nginx.request_uri icontains "UNION SELECT" or
    nginx.request_uri icontains "%27%20OR"

- macro: xss_patterns
  condition: >
    nginx.request_uri icontains "<script" or
    nginx.request_uri icontains "javascript:" or
    nginx.request_uri icontains "%3Cscript"

# Use macros in rules
- rule: Web Attack Detected
  desc: Detects SQL injection or XSS attacks
  condition: sql_injection_patterns or xss_patterns
  output: "Web attack detected (ip=%nginx.remote_addr uri=%nginx.request_uri)"
  priority: CRITICAL
  tags: [attack, web]
  source: nginx
```

#### Geographic Restrictions
```yaml
- rule: Unauthorized Geographic Access
  desc: Access from unexpected locations
  condition: >
    nginx.path startswith "/internal/" and
    not (nginx.remote_addr startswith "10." or
         nginx.remote_addr startswith "192.168.")
  output: "External access to internal resource (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [access_control, geographic]
  source: nginx
```

### Common Mistakes to Avoid

#### 1. Missing `source: nginx`

```yaml
# ❌ Wrong - Missing source
- rule: My Rule
  condition: nginx.path = "/admin"
  output: "Admin access"
  priority: WARNING

# ✅ Correct - source: nginx is required
- rule: My Rule
  condition: nginx.path = "/admin"
  output: "Admin access"
  priority: WARNING
  source: nginx
```

#### 2. Using `contains` Instead of `icontains`

```yaml
# ❌ Will miss "' or" and "' OR"
condition: nginx.request_uri contains "' OR"

# ✅ Catches all case variations
condition: nginx.request_uri icontains "' OR"
```

#### 3. Forgetting URL-Encoded Patterns

```yaml
# ❌ Only catches unencoded patterns
condition: nginx.request_uri icontains "'"

# ✅ Also catches URL-encoded single quotes
condition: >
  nginx.request_uri icontains "'" or
  nginx.request_uri icontains "%27"
```

#### 4. Using `evt.type=pluginevent`

```yaml
# ❌ Wrong - evt.type is not used for plugin rules
condition: evt.type=pluginevent and nginx.path = "/admin"

# ✅ Correct - Just use nginx fields with source: nginx
condition: nginx.path = "/admin"
```

#### 5. Wrong Field Names

```yaml
# ❌ These field names are WRONG
nginx.http_referer      # Wrong
nginx.http_user_agent   # Wrong
nginx.body_bytes_sent   # Does not exist

# ✅ Correct field names
nginx.referer           # Correct
nginx.user_agent        # Correct
nginx.bytes_sent        # Correct
```

### Troubleshooting Rules

#### Rule Not Firing
1. Check `source: nginx` is present
2. Verify field names are correct (see Available Fields table)
3. Use `icontains` instead of `contains` for case-insensitive matching
4. Test with simpler conditions
5. Check Falco logs for errors

#### Performance Issues
1. Simplify complex conditions
2. Reduce regex usage
3. Limit number of rules
4. Check rule evaluation metrics

### Next Steps

- [Configuration Guide](configuration.md)
- [Performance Tuning](performance.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

---

<a name="japanese"></a>
## 日本語

このガイドでは、Falco nginxプラグインのカスタムルールの作成方法を説明します。

### 基本的なルール構造

すべてのnginxプラグインルールには以下のコンポーネントが必要です：

```yaml
- rule: ルール名
  desc: ルールが検出する内容の説明
  condition: nginxフィールドを使用した検出ロジック
  output: フィールド補間を含むアラートメッセージ
  priority: EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG
  tags: [tag1, tag2]
  source: nginx  # プラグインルールには必須
```

### 利用可能なフィールド

nginxプラグインは条件と出力で使用できる以下のフィールドを提供します：

| フィールド | 型 | 説明 |
|-------|------|-------------|
| `nginx.remote_addr` | string | クライアントIPアドレス |
| `nginx.remote_user` | string | 認証されたユーザー名 |
| `nginx.time_local` | string | リクエストタイムスタンプ |
| `nginx.method` | string | HTTPメソッド（GET、POSTなど） |
| `nginx.path` | string | クエリ文字列を除いたリクエストパス |
| `nginx.query_string` | string | クエリ文字列パラメータ |
| `nginx.request_uri` | string | 完全なURI（パス＋クエリ文字列） |
| `nginx.protocol` | string | HTTPプロトコルバージョン |
| `nginx.status` | number | HTTPレスポンスステータスコード |
| `nginx.bytes_sent` | number | 総レスポンスサイズ（バイト） |
| `nginx.referer` | string | HTTP Refererヘッダー |
| `nginx.user_agent` | string | HTTP User-Agentヘッダー |
| `nginx.log_path` | string | ログファイルパス |
| `nginx.raw` | string | 生のログ行（デバッグに有用） |
| `nginx.headers[key]` | string | キー指定のHTTPヘッダー値（例：`nginx.headers[X-Forwarded-For]`） |

### 条件演算子

#### 文字列演算子
- `contains` - 部分文字列マッチ（大文字小文字を区別）
- `icontains` - 大文字小文字を区別しない部分文字列マッチ（**セキュリティパターンに推奨**）
- `startswith` - 前方一致
- `endswith` - 後方一致
- `=` - 完全一致
- `!=` - 不一致

> **注意**: セキュリティ検出ルールでは、大文字小文字の違いを検出するために`contains`ではなく`icontains`を使用してください。例えば、`nginx.request_uri icontains "' OR"`は`' or`、`' OR`、`' Or`すべてにマッチします。

#### 数値演算子
- `=`, `!=` - 等価性
- `<`, `>`, `<=`, `>=` - 比較

#### 論理演算子
- `and` - 両方の条件が真
- `or` - いずれかの条件が真
- `not` - 否定

### ルールの例

#### 基本的な攻撃検出

```yaml
- rule: SQL Injection Attempt
  desc: 一般的なSQLインジェクションパターンを検出（大文字小文字区別なし）
  condition: >
    nginx.request_uri icontains "' OR" or
    nginx.request_uri icontains "UNION SELECT" or
    nginx.request_uri icontains "'; DROP" or
    nginx.request_uri icontains "%27%20OR"
  output: "SQLインジェクションを検出 (ip=%nginx.remote_addr uri=%nginx.request_uri method=%nginx.method)"
  priority: CRITICAL
  tags: [attack, sql_injection]
  source: nginx
```

> **ベストプラクティス**: `icontains`を使用してセキュリティ検出を行うことで、`' or`、`' OR`、`' Or`などのバリエーションを検出できます。また、`%27`（シングルクォート）や`%3c`（小なり記号）などのURLエンコードパターンも含めてください。

#### レスポンスベースの検出

```yaml
- rule: Large Data Transfer
  desc: 異常に大きなレスポンスを検出
  condition: nginx.bytes_sent > 104857600  # 100MB
  output: "大量データ転送 (ip=%nginx.remote_addr uri=%nginx.request_uri size=%nginx.bytes_sent)"
  priority: WARNING
  tags: [anomaly, data_exfiltration]
  source: nginx
```

#### ステータスコード監視

```yaml
- rule: High Error Rate
  desc: 複数の5xxエラーを検出
  condition: nginx.status >= 500 and nginx.status < 600
  output: "サーバーエラーを検出 (ip=%nginx.remote_addr% uri=%nginx.request_uri% status=%nginx.status%)"
  priority: ERROR
  tags: [availability, error]
  source: nginx
```

#### ユーザーエージェント検出

```yaml
- rule: Automated Scanner
  desc: 一般的なセキュリティスキャナーを検出
  condition: >
    nginx.user_agent icontains "sqlmap" or
    nginx.user_agent icontains "nikto" or
    nginx.user_agent icontains "nmap"
  output: "スキャナーを検出 (ip=%nginx.remote_addr scanner=%nginx.user_agent)"
  priority: WARNING
  tags: [scanner, reconnaissance]
  source: nginx
```

#### HTTPヘッダーの使用

```yaml
- rule: Suspicious X-Forwarded-For Header
  desc: X-Forwarded-Forヘッダー内の疑わしいパターンを検出
  condition: >
    nginx.headers[X-Forwarded-For] icontains "'" or
    nginx.headers[X-Forwarded-For] icontains "<script"
  output: "疑わしいX-Forwarded-Forヘッダー (ip=%nginx.remote_addr header=%nginx.headers[X-Forwarded-For])"
  priority: WARNING
  tags: [attack, header_injection]
  source: nginx
```

> **注意**: `nginx.headers[key]`を使用して任意のHTTPリクエストヘッダーにアクセスできます。一般的なヘッダーには`X-Forwarded-For`、`Authorization`、`X-Real-IP`などがあります。

#### 複雑な条件

```yaml
- rule: Admin Brute Force
  desc: 複数の管理者ログイン失敗試行
  condition: >
    nginx.path startswith "/admin" and
    nginx.method = "POST" and
    nginx.status = 401
  output: "管理者ログイン失敗 (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [authentication, brute_force]
  source: nginx
```

### ベストプラクティス

#### 1. 特定の条件を使用
```yaml
# 良い - 特定のパスチェック
condition: nginx.path = "/admin/login.php"

# 効率が悪い - containsチェック
condition: nginx.request_uri contains "admin"
```

#### 2. 関連するチェックを結合
```yaml
# 良い - 関連パターンの単一ルール
condition: >
  nginx.request_uri contains "<script" or
  nginx.request_uri contains "javascript:" or
  nginx.request_uri contains "onerror="

# 効率が悪い - 複数の個別ルール
```

#### 3. 適切な優先度を使用

Falcoは以下の優先度レベルをサポートしています（高い順）：

- **EMERGENCY**: システムが使用不能
- **ALERT**: 即座の対応が必要
- **CRITICAL**: 即時対応が必要なアクティブな攻撃（SQLインジェクション、RCE）
- **ERROR**: エラー状態（サーバーエラー、障害）
- **WARNING**: 疑わしい活動（スキャナー、認証失敗）
- **NOTICE**: 異常（大量転送、異常なパス）
- **INFO**: 監視および情報イベント
- **DEBUG**: 開発用デバッグレベルメッセージ

#### 4. 意味のあるタグを追加
タグはフィルタリングとレポートに役立ちます：
- `attack` - アクティブな攻撃試行
- `reconnaissance` - 情報収集
- `authentication` - ログイン関連イベント
- `anomaly` - 異常だが必ずしも悪意があるとは限らない
- `compliance` - 規制コンプライアンスチェック

### ルールのテスト

#### 1. 構文の検証
```bash
sudo falco --validate /etc/falco/rules.d/custom-nginx.yaml
```

#### 2. サンプルリクエストでテスト
```bash
# テストトラフィックを生成
curl "http://localhost/test.php?id=' OR '1'='1"

# ルールがトリガーされたか確認
sudo journalctl -u falco -f | grep "SQL injection"
```

#### 3. デバッグ出力を使用
```yaml
- rule: Debug Test
  desc: デバッグ用テストルール
  condition: nginx.path = "/debug-test"
  output: "DEBUG: 全フィールド - ip=%nginx.remote_addr% method=%nginx.method% path=%nginx.path% query=%nginx.query_string%"
  priority: DEBUG
  source: nginx
```

### パフォーマンスの考慮事項

#### 1. 順序が重要
最も可能性の高い条件を最初に配置：
```yaml
# 効率的 - 一般的な条件が最初
condition: nginx.method = "POST" and nginx.path contains "admin"

# 効率が悪い - 高価なチェックが最初
condition: nginx.request_uri regex "complex.*pattern" and nginx.method = "POST"
```

#### 2. 複雑な正規表現を避ける
可能な場合は単純な文字列操作を使用：
```yaml
# 推奨
condition: nginx.path endswith ".php"

# 可能な限り避ける
condition: nginx.path regex ".*\\.php$"
```

#### 3. 出力フィールドを制限
必要なフィールドのみを出力に含める：
```yaml
# 良い - 関連フィールドのみ
output: "攻撃を検出 (ip=%nginx.remote_addr uri=%nginx.request_uri)"

# 冗長 - パフォーマンスに影響する可能性
output: "攻撃 (ip=%nginx.remote_addr uri=%nginx.request_uri ua=%nginx.user_agent ref=%nginx.referer status=%nginx.status)"
```

### 高度な例

#### 再利用可能なパターンのためのマクロ使用
```yaml
# 再利用可能なマクロを定義
- macro: sql_injection_patterns
  condition: >
    nginx.request_uri icontains "' OR" or
    nginx.request_uri icontains "UNION SELECT" or
    nginx.request_uri icontains "%27%20OR"

- macro: xss_patterns
  condition: >
    nginx.request_uri icontains "<script" or
    nginx.request_uri icontains "javascript:" or
    nginx.request_uri icontains "%3Cscript"

# ルールでマクロを使用
- rule: Web Attack Detected
  desc: SQLインジェクションまたはXSS攻撃を検出
  condition: sql_injection_patterns or xss_patterns
  output: "Web攻撃を検出 (ip=%nginx.remote_addr uri=%nginx.request_uri)"
  priority: CRITICAL
  tags: [attack, web]
  source: nginx
```

#### 地理的制限
```yaml
- rule: Unauthorized Geographic Access
  desc: 予期しない場所からのアクセス
  condition: >
    nginx.path startswith "/internal/" and
    not (nginx.remote_addr startswith "10." or
         nginx.remote_addr startswith "192.168.")
  output: "内部リソースへの外部アクセス (ip=%nginx.remote_addr% path=%nginx.path%)"
  priority: WARNING
  tags: [access_control, geographic]
  source: nginx
```

### よくある間違いを避ける

#### 1. `source: nginx`の欠落

```yaml
# ❌ 間違い - sourceがない
- rule: My Rule
  condition: nginx.path = "/admin"
  output: "管理者アクセス"
  priority: WARNING

# ✅ 正しい - source: nginxは必須
- rule: My Rule
  condition: nginx.path = "/admin"
  output: "管理者アクセス"
  priority: WARNING
  source: nginx
```

#### 2. `icontains`ではなく`contains`を使用

```yaml
# ❌ "' or"や"' OR"を見逃す
condition: nginx.request_uri contains "' OR"

# ✅ すべての大文字小文字の組み合わせを検出
condition: nginx.request_uri icontains "' OR"
```

#### 3. URLエンコードパターンの考慮漏れ

```yaml
# ❌ エンコードされていないパターンのみ検出
condition: nginx.request_uri icontains "'"

# ✅ URLエンコードされたシングルクォートも検出
condition: >
  nginx.request_uri icontains "'" or
  nginx.request_uri icontains "%27"
```

#### 4. `evt.type=pluginevent`の使用

```yaml
# ❌ 間違い - evt.typeはプラグインルールでは使用しない
condition: evt.type=pluginevent and nginx.path = "/admin"

# ✅ 正しい - source: nginxでnginxフィールドを使用するだけ
condition: nginx.path = "/admin"
```

#### 5. 間違ったフィールド名

```yaml
# ❌ これらのフィールド名は間違い
nginx.http_referer      # 間違い
nginx.http_user_agent   # 間違い
nginx.body_bytes_sent   # 存在しない

# ✅ 正しいフィールド名
nginx.referer           # 正しい
nginx.user_agent        # 正しい
nginx.bytes_sent        # 正しい
```

### ルールのトラブルシューティング

#### ルールが発火しない
1. `source: nginx`が存在することを確認
2. フィールド名が正しいことを確認（利用可能なフィールドの表を参照）
3. 大文字小文字を区別しないマッチングには`contains`ではなく`icontains`を使用
4. より単純な条件でテスト
5. Falcoログでエラーを確認

#### パフォーマンスの問題
1. 複雑な条件を簡素化
2. 正規表現の使用を削減
3. ルール数を制限
4. ルール評価メトリクスを確認

### 次のステップ

- [設定ガイド](configuration.md)
- [パフォーマンスチューニング](performance.md)
- [トラブルシューティングガイド](TROUBLESHOOTING.md)