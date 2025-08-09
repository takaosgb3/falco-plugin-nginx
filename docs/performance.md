# Performance Tuning Guide / パフォーマンスチューニングガイド

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

This guide helps you optimize the Falco nginx plugin for your environment.

### Quick Performance Check

Monitor plugin performance:

```bash
# Check CPU and memory usage
ps aux | grep falco

# Monitor event processing rate
sudo journalctl -u falco -f | grep -E "events/sec|dropped"
```

### Buffer Size Tuning

Buffer size affects memory usage and processing efficiency.

#### Impact Analysis

| Buffer Size | Memory per File | CPU Usage | Event Latency | Recommendation |
|------------|----------------|-----------|---------------|----------------|
| 8KB (default) | 8KB | 0.8% | 1.2ms | < 100 req/sec |
| 16KB | 16KB | 0.7% | 1.4ms | 100-1000 req/sec |
| 32KB | 32KB | 0.6% | 1.8ms | 1000-10000 req/sec |
| 64KB | 64KB | 0.6% | 2.5ms | > 10000 req/sec |

#### Configuration

```yaml
plugins:
  - name: nginx
    init_config:
      buffer_size: 16384  # 16KB for medium traffic
```

#### Memory Calculation

```
Total Memory = Base Memory + (buffer_size × number_of_log_files)
```

Example with 10 log files:
- 8KB buffer: ~45MB + 80KB = ~45MB total
- 16KB buffer: ~45MB + 160KB = ~46MB total
- 32KB buffer: ~45MB + 320KB = ~48MB total

### Batch Processing Optimization

#### High Throughput Configuration

For maximum throughput:

```yaml
init_config:
  max_batch_size: 2000    # Process more events per batch
  batch_timeout: 1000     # Wait longer to fill batches
  event_channel_size: 20000  # Larger event queue
```

#### Low Latency Configuration

For minimal detection delay:

```yaml
init_config:
  max_batch_size: 100     # Smaller batches
  batch_timeout: 50       # Shorter timeout
  event_channel_size: 5000   # Standard queue
```

### System Resource Optimization

#### CPU Optimization

1. **Reduce regex complexity** in rules:
```yaml
# Less efficient
condition: nginx.request_uri regex ".*(\\.php|\\.(asp|aspx|jsp)).*"

# More efficient
condition: nginx.request_uri endswith ".php" or nginx.request_uri endswith ".asp"
```

2. **Use specific conditions**:
```yaml
# Less efficient
condition: nginx.request_uri contains "admin"

# More efficient
condition: nginx.request_uri startswith "/admin/"
```

#### Memory Optimization

1. **Limit monitored files**:
```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log  # Only monitor active logs
```

2. **Set file size limits**:
```yaml
init_config:
  max_file_size: 536870912  # 512MB limit
```

### Log Rotation Impact

Proper log rotation prevents performance degradation:

```bash
# Install optimized rotation
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

Key settings:
- Rotate at 100MB or daily
- Compress old logs
- Keep 14 days of history

### Benchmarking

#### Simple Load Test

```bash
# Generate test traffic
for i in {1..1000}; do
  curl -s http://localhost/ > /dev/null &
done
wait

# Check processing metrics
sudo journalctl -u falco --since "1 minute ago" | grep -c "nginx"
```

#### Performance Metrics

Monitor these key metrics:

1. **Event Processing Rate**
```bash
# Count events per minute
sudo journalctl -u falco --since "1 minute ago" | grep -c "output:"
```

2. **Drop Rate**
```bash
# Check for dropped events
sudo journalctl -u falco | grep -i "drop"
```

3. **Latency**
```bash
# Time between log entry and alert
# Compare nginx log timestamp with Falco alert timestamp
```

### Optimization Checklist

- [ ] Choose appropriate buffer size for traffic volume
- [ ] Configure batch processing for your latency requirements
- [ ] Implement log rotation to prevent large file issues
- [ ] Optimize rules for efficiency
- [ ] Monitor only necessary log files
- [ ] Set reasonable file size limits
- [ ] Test performance under expected load

### Troubleshooting Performance Issues

#### High CPU Usage

1. Check rule efficiency
2. Reduce buffer size
3. Increase batch timeout
4. Limit monitored files

#### High Memory Usage

1. Reduce buffer size
2. Limit event channel size
3. Enable log rotation
4. Check for memory leaks

#### Dropped Events

1. Increase buffer size
2. Increase event channel size
3. Optimize rules
4. Add more CPU resources

### Container Environments

For Kubernetes/Docker:

```yaml
resources:
  limits:
    memory: 512Mi
    cpu: 500m
  requests:
    memory: 256Mi
    cpu: 100m
```

### Next Steps

- [Configuration Guide](configuration.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [Rule Writing Guide](rules.md)

---

<a name="japanese"></a>
## 日本語

このガイドは、Falco nginxプラグインを環境に合わせて最適化する方法を説明します。

### クイックパフォーマンスチェック

プラグインのパフォーマンスを監視：

```bash
# CPUとメモリ使用量を確認
ps aux | grep falco

# イベント処理レートを監視
sudo journalctl -u falco -f | grep -E "events/sec|dropped"
```

### バッファサイズチューニング

バッファサイズはメモリ使用量と処理効率に影響します。

#### 影響分析

| バッファサイズ | ファイルあたりメモリ | CPU使用率 | イベントレイテンシ | 推奨環境 |
|------------|----------------|-----------|---------------|----------------|
| 8KB（デフォルト） | 8KB | 0.8% | 1.2ms | < 100 req/秒 |
| 16KB | 16KB | 0.7% | 1.4ms | 100-1000 req/秒 |
| 32KB | 32KB | 0.6% | 1.8ms | 1000-10000 req/秒 |
| 64KB | 64KB | 0.6% | 2.5ms | > 10000 req/秒 |

#### 設定

```yaml
plugins:
  - name: nginx
    init_config:
      buffer_size: 16384  # 中程度のトラフィック向け16KB
```

#### メモリ計算

```
総メモリ = ベースメモリ + (buffer_size × ログファイル数)
```

10個のログファイルの例：
- 8KBバッファ: ~45MB + 80KB = 約45MB合計
- 16KBバッファ: ~45MB + 160KB = 約46MB合計
- 32KBバッファ: ~45MB + 320KB = 約48MB合計

### バッチ処理の最適化

#### 高スループット設定

最大スループット向け：

```yaml
init_config:
  max_batch_size: 2000    # バッチあたりのイベント数を増加
  batch_timeout: 1000     # バッチを満たすまでの待機時間を延長
  event_channel_size: 20000  # より大きなイベントキュー
```

#### 低レイテンシ設定

最小検出遅延向け：

```yaml
init_config:
  max_batch_size: 100     # 小さなバッチ
  batch_timeout: 50       # 短いタイムアウト
  event_channel_size: 5000   # 標準キュー
```

### システムリソースの最適化

#### CPU最適化

1. **ルール内の正規表現を簡素化**：
```yaml
# 効率が悪い
condition: nginx.request_uri regex ".*(\\.php|\\.(asp|aspx|jsp)).*"

# 効率的
condition: nginx.request_uri endswith ".php" or nginx.request_uri endswith ".asp"
```

2. **特定の条件を使用**：
```yaml
# 効率が悪い
condition: nginx.request_uri contains "admin"

# 効率的
condition: nginx.request_uri startswith "/admin/"
```

#### メモリ最適化

1. **監視ファイルを制限**：
```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log  # アクティブなログのみ監視
```

2. **ファイルサイズ制限を設定**：
```yaml
init_config:
  max_file_size: 536870912  # 512MB制限
```

### ログローテーションの影響

適切なログローテーションでパフォーマンス低下を防止：

```bash
# 最適化されたローテーションをインストール
wget https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/scripts/setup-log-rotation.sh
sudo ./setup-log-rotation.sh
```

主要設定：
- 100MBまたは日次でローテーション
- 古いログを圧縮
- 14日間の履歴を保持

### ベンチマーク

#### シンプルな負荷テスト

```bash
# テストトラフィックを生成
for i in {1..1000}; do
  curl -s http://localhost/ > /dev/null &
done
wait

# 処理メトリクスを確認
sudo journalctl -u falco --since "1 minute ago" | grep -c "nginx"
```

#### パフォーマンスメトリクス

これらの主要メトリクスを監視：

1. **イベント処理レート**
```bash
# 分あたりのイベント数をカウント
sudo journalctl -u falco --since "1 minute ago" | grep -c "output:"
```

2. **ドロップレート**
```bash
# ドロップされたイベントを確認
sudo journalctl -u falco | grep -i "drop"
```

3. **レイテンシ**
```bash
# ログエントリからアラートまでの時間
# nginxログのタイムスタンプとFalcoアラートのタイムスタンプを比較
```

### 最適化チェックリスト

- [ ] トラフィック量に適したバッファサイズを選択
- [ ] レイテンシ要件に合わせてバッチ処理を設定
- [ ] 大きなファイル問題を防ぐためログローテーションを実装
- [ ] 効率的なルールに最適化
- [ ] 必要なログファイルのみ監視
- [ ] 妥当なファイルサイズ制限を設定
- [ ] 想定負荷でのパフォーマンステスト

### パフォーマンス問題のトラブルシューティング

#### 高CPU使用率

1. ルールの効率を確認
2. バッファサイズを削減
3. バッチタイムアウトを増加
4. 監視ファイルを制限

#### 高メモリ使用率

1. バッファサイズを削減
2. イベントチャンネルサイズを制限
3. ログローテーションを有効化
4. メモリリークを確認

#### イベントドロップ

1. バッファサイズを増加
2. イベントチャンネルサイズを増加
3. ルールを最適化
4. CPUリソースを追加

### コンテナ環境

Kubernetes/Docker向け：

```yaml
resources:
  limits:
    memory: 512Mi
    cpu: 500m
  requests:
    memory: 256Mi
    cpu: 100m
```

### 次のステップ

- [設定ガイド](configuration.md)
- [トラブルシューティングガイド](TROUBLESHOOTING.md)
- [ルール作成ガイド](rules.md)