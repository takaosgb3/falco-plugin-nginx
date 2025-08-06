# Configuration Guide / 設定ガイド

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

This guide covers all configuration options for the Falco nginx plugin.

### Basic Configuration

The minimal configuration in `/etc/falco/falco.yaml`:

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

### Configuration Options

#### Log Paths

Monitor multiple nginx log files:

```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/custom-site.log
    - /srv/nginx/logs/access.log
```

#### Buffer Size

Adjust buffer size for high-traffic environments:

```yaml
init_config:
  buffer_size: 16384  # Default: 8192 bytes
```

Buffer size recommendations:
- Low traffic (< 100 req/sec): 8192 (default)
- Medium traffic (100-1000 req/sec): 16384
- High traffic (> 1000 req/sec): 32768

#### Batch Processing

Configure event batching:

```yaml
init_config:
  max_batch_size: 1000    # Events per batch (default: 500)
  batch_timeout: 500      # Milliseconds (default: 200)
```

#### Event Channel

Configure internal event channel:

```yaml
init_config:
  event_channel_size: 10000  # Default: 5000
```

#### Watch Interval

File monitoring interval:

```yaml
init_config:
  watch_interval: 5  # Seconds (default: 1)
```

### Log Format Support

The plugin supports these nginx log formats:

#### Combined (Default)
```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

#### Custom Format
```yaml
init_config:
  log_format: combined  # or "common", "json"
```

### Advanced Configuration

#### Large Response Threshold

Set threshold for large response detection:

```yaml
init_config:
  large_response_threshold: 10485760  # 10MB in bytes
```

#### Maximum File Size

Limit maximum log file size to process:

```yaml
init_config:
  max_file_size: 1073741824  # 1GB in bytes
```

### Log Rotation

Set up log rotation to prevent disk space issues:

```bash
# Download and run setup script
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

Manual logrotate configuration (`/etc/logrotate.d/nginx-falco`):

```
/var/log/nginx/*.log {
    daily
    size 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
    endscript
}
```

### Rule Configuration

#### Custom Rules

Add custom rules in `/etc/falco/rules.d/custom-nginx.yaml`:

```yaml
- rule: Custom Attack Pattern
  desc: Detect custom attack pattern
  condition: nginx.request_uri contains "custom-pattern"
  output: "Custom attack detected (ip=%nginx.client_ip%)"
  priority: WARNING
  tags: [custom]
  source: nginx
```

#### Rule Priorities

- EMERGENCY: System unusable
- ALERT: Immediate action required
- CRITICAL: Critical conditions (attacks)
- ERROR: Error conditions
- WARNING: Warning conditions
- NOTICE: Normal but significant
- INFO: Informational
- DEBUG: Debug-level messages

### Performance Optimization

#### For High-Traffic Sites

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 32768
      max_batch_size: 2000
      batch_timeout: 1000
      event_channel_size: 20000
```

#### For Low-Latency Requirements

```yaml
init_config:
  buffer_size: 8192
  max_batch_size: 100
  batch_timeout: 50
  watch_interval: 1
```

### Monitoring Configuration

Enable metrics collection:

```yaml
init_config:
  enable_metrics: true
  metrics_interval: 60  # Seconds
```

### Next Steps

- [Performance Tuning Guide](performance.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Rule Writing Guide](rules.md)

---

<a name="japanese"></a>
## 日本語

このガイドでは、Falco nginxプラグインのすべての設定オプションについて説明します。

### 基本設定

`/etc/falco/falco.yaml`での最小限の設定：

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

### 設定オプション

#### ログパス

複数のnginxログファイルを監視：

```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log
    - /var/log/nginx/custom-site.log
    - /srv/nginx/logs/access.log
```

#### バッファサイズ

高トラフィック環境向けにバッファサイズを調整：

```yaml
init_config:
  buffer_size: 16384  # デフォルト: 8192バイト
```

バッファサイズの推奨値：
- 低トラフィック（< 100 req/秒）: 8192（デフォルト）
- 中トラフィック（100-1000 req/秒）: 16384
- 高トラフィック（> 1000 req/秒）: 32768

#### バッチ処理

イベントバッチングの設定：

```yaml
init_config:
  max_batch_size: 1000    # バッチあたりのイベント数（デフォルト: 500）
  batch_timeout: 500      # ミリ秒（デフォルト: 200）
```

#### イベントチャンネル

内部イベントチャンネルの設定：

```yaml
init_config:
  event_channel_size: 10000  # デフォルト: 5000
```

#### 監視間隔

ファイル監視間隔：

```yaml
init_config:
  watch_interval: 5  # 秒（デフォルト: 1）
```

### ログフォーマットのサポート

プラグインは以下のnginxログフォーマットをサポートしています：

#### Combined（デフォルト）
```nginx
log_format combined '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';
```

#### カスタムフォーマット
```yaml
init_config:
  log_format: combined  # または "common", "json"
```

### 高度な設定

#### 大きなレスポンスのしきい値

大きなレスポンス検出のしきい値を設定：

```yaml
init_config:
  large_response_threshold: 10485760  # 10MBバイト
```

#### 最大ファイルサイズ

処理する最大ログファイルサイズを制限：

```yaml
init_config:
  max_file_size: 1073741824  # 1GBバイト
```

### ログローテーション

ディスク容量の問題を防ぐためにログローテーションを設定：

```bash
# セットアップスクリプトをダウンロードして実行
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

手動logrotate設定（`/etc/logrotate.d/nginx-falco`）：

```
/var/log/nginx/*.log {
    daily
    size 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
    endscript
}
```

### ルール設定

#### カスタムルール

`/etc/falco/rules.d/custom-nginx.yaml`にカスタムルールを追加：

```yaml
- rule: Custom Attack Pattern
  desc: カスタム攻撃パターンを検出
  condition: nginx.request_uri contains "custom-pattern"
  output: "カスタム攻撃を検出 (ip=%nginx.client_ip%)"
  priority: WARNING
  tags: [custom]
  source: nginx
```

#### ルールの優先度

- EMERGENCY: システム使用不可
- ALERT: 即座の対応が必要
- CRITICAL: 重大な状態（攻撃）
- ERROR: エラー状態
- WARNING: 警告状態
- NOTICE: 正常だが重要
- INFO: 情報
- DEBUG: デバッグレベルのメッセージ

### パフォーマンス最適化

#### 高トラフィックサイト向け

```yaml
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
      buffer_size: 32768
      max_batch_size: 2000
      batch_timeout: 1000
      event_channel_size: 20000
```

#### 低レイテンシ要件向け

```yaml
init_config:
  buffer_size: 8192
  max_batch_size: 100
  batch_timeout: 50
  watch_interval: 1
```

### 監視設定

メトリクス収集を有効化：

```yaml
init_config:
  enable_metrics: true
  metrics_interval: 60  # 秒
```

### 次のステップ

- [パフォーマンスチューニングガイド](performance.md)
- [トラブルシューティングガイド](troubleshooting.md)
- [ルール作成ガイド](rules.md)