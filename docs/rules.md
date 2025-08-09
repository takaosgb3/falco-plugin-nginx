# Rule Writing Guide / ルール作成ガイド

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
  priority: CRITICAL|WARNING|NOTICE|INFORMATIONAL|DEBUG
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
| `nginx.body_bytes_sent` | number | Response body size in bytes |
| `nginx.bytes_sent` | number | Total response size |
| `nginx.http_referer` | string | Referer header |
| `nginx.http_user_agent` | string | User-Agent header |
| `nginx.request_length` | number | Request size |
| `nginx.request_time` | number | Request processing time |
| `nginx.upstream_response_time` | number | Upstream response time |
| `nginx.log_path` | string | Log file path |

### Condition Operators

#### String Operators
- `contains` - Substring match
- `startswith` - Prefix match
- `endswith` - Suffix match
- `=` - Exact match
- `!=` - Not equal

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
  desc: Detects common SQL injection patterns
  condition: >
    nginx.request_uri contains "' OR" or
    nginx.request_uri contains "UNION SELECT" or
    nginx.request_uri contains "'; DROP"
  output: "SQL injection detected (ip=%nginx.remote_addr% uri=%nginx.request_uri% method=%nginx.method%)"
  priority: CRITICAL
  tags: [attack, sql_injection]
  source: nginx
```

#### Response-based Detection

```yaml
- rule: Large Data Transfer
  desc: Detects unusually large responses
  condition: nginx.body_bytes_sent > 104857600  # 100MB
  output: "Large data transfer (ip=%nginx.remote_addr% uri=%nginx.request_uri% size=%nginx.body_bytes_sent%)"
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
    nginx.http_user_agent contains "sqlmap" or
    nginx.http_user_agent contains "nikto" or
    nginx.http_user_agent contains "nmap"
  output: "Scanner detected (ip=%nginx.remote_addr% scanner=%nginx.http_user_agent%)"
  priority: WARNING
  tags: [scanner, reconnaissance]
  source: nginx
```

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
- **CRITICAL**: Active attacks (SQL injection, RCE)
- **WARNING**: Suspicious activity (scanners, failed auth)
- **NOTICE**: Anomalies (large transfers, unusual paths)
- **INFORMATIONAL**: Monitoring (specific user agents)

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

#### Rate Limiting Detection
```yaml
- rule: Potential DDoS Attack
  desc: High request rate from single IP
  condition: nginx.request_time < 0.01  # Very fast requests
  output: "High request rate (ip=%nginx.remote_addr% time=%nginx.request_time%ms)"
  priority: WARNING
  tags: [ddos, rate_limit]
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

### Troubleshooting Rules

#### Rule Not Firing
1. Check `source: nginx` is present
2. Verify field names are correct
3. Test with simpler conditions
4. Check Falco logs for errors

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
  priority: CRITICAL|WARNING|NOTICE|INFORMATIONAL|DEBUG
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
| `nginx.body_bytes_sent` | number | レスポンスボディサイズ（バイト） |
| `nginx.bytes_sent` | number | 総レスポンスサイズ |
| `nginx.http_referer` | string | Refererヘッダー |
| `nginx.http_user_agent` | string | User-Agentヘッダー |
| `nginx.request_length` | number | リクエストサイズ |
| `nginx.request_time` | number | リクエスト処理時間 |
| `nginx.upstream_response_time` | number | アップストリームレスポンス時間 |
| `nginx.log_path` | string | ログファイルパス |

### 条件演算子

#### 文字列演算子
- `contains` - 部分文字列マッチ
- `startswith` - 前方一致
- `endswith` - 後方一致
- `=` - 完全一致
- `!=` - 不一致

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
  desc: 一般的なSQLインジェクションパターンを検出
  condition: >
    nginx.request_uri contains "' OR" or
    nginx.request_uri contains "UNION SELECT" or
    nginx.request_uri contains "'; DROP"
  output: "SQLインジェクションを検出 (ip=%nginx.remote_addr% uri=%nginx.request_uri% method=%nginx.method%)"
  priority: CRITICAL
  tags: [attack, sql_injection]
  source: nginx
```

#### レスポンスベースの検出

```yaml
- rule: Large Data Transfer
  desc: 異常に大きなレスポンスを検出
  condition: nginx.body_bytes_sent > 104857600  # 100MB
  output: "大量データ転送 (ip=%nginx.remote_addr% uri=%nginx.request_uri% size=%nginx.body_bytes_sent%)"
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
    nginx.http_user_agent contains "sqlmap" or
    nginx.http_user_agent contains "nikto" or
    nginx.http_user_agent contains "nmap"
  output: "スキャナーを検出 (ip=%nginx.remote_addr% scanner=%nginx.http_user_agent%)"
  priority: WARNING
  tags: [scanner, reconnaissance]
  source: nginx
```

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
- **CRITICAL**: アクティブな攻撃（SQLインジェクション、RCE）
- **WARNING**: 疑わしい活動（スキャナー、認証失敗）
- **NOTICE**: 異常（大量転送、異常なパス）
- **INFORMATIONAL**: 監視（特定のユーザーエージェント）

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
output: "攻撃を検出 (ip=%nginx.remote_addr% uri=%nginx.request_uri%)"

# 冗長 - パフォーマンスに影響する可能性
output: "攻撃 (ip=%nginx.remote_addr% uri=%nginx.request_uri% ua=%nginx.http_user_agent% ref=%nginx.http_referer% status=%nginx.status%)"
```

### 高度な例

#### レート制限検出
```yaml
- rule: Potential DDoS Attack
  desc: 単一IPからの高リクエストレート
  condition: nginx.request_time < 0.01  # 非常に高速なリクエスト
  output: "高リクエストレート (ip=%nginx.remote_addr% time=%nginx.request_time%ms)"
  priority: WARNING
  tags: [ddos, rate_limit]
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

### ルールのトラブルシューティング

#### ルールが発火しない
1. `source: nginx`が存在することを確認
2. フィールド名が正しいことを確認
3. より単純な条件でテスト
4. Falcoログでエラーを確認

#### パフォーマンスの問題
1. 複雑な条件を簡素化
2. 正規表現の使用を削減
3. ルール数を制限
4. ルール評価メトリクスを確認

### 次のステップ

- [設定ガイド](configuration.md)
- [パフォーマンスチューニング](performance.md)
- [トラブルシューティングガイド](TROUBLESHOOTING.md)