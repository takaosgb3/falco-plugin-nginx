# Troubleshooting Guide / トラブルシューティングガイド

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

This guide helps diagnose and resolve common issues with the Falco nginx plugin.

### Quick Diagnosis

```bash
# Check Falco status
sudo systemctl status falco-nginx

# Check if plugin is loaded
sudo falco --list-plugins | grep nginx

# View recent logs
sudo journalctl -u falco-nginx -n 100

# Test in debug mode
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v
```

### Common Issues

#### Plugin Not Loading

**Symptoms:**
- Plugin doesn't appear in `falco --list-plugins`
- Error: "Unable to load plugin"

**Solutions:**

1. **Check file permissions:**
```bash
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Should be: -rw-r--r-- 1 root root
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

2. **Verify library dependencies:**
```bash
ldd /usr/share/falco/plugins/libfalco-nginx-plugin.so
# Check for "not found" errors
```

3. **Check Falco configuration:**
```bash
# Validate configuration
sudo falco --validate /etc/falco/falco.yaml

# Check plugin section exists
grep -A5 "plugins:" /etc/falco/falco.yaml
```

#### No Alerts Generated

**Symptoms:**
- No alerts when testing attacks
- Plugin loads but seems inactive

**Solutions:**

1. **Verify nginx logs exist:**
```bash
ls -la /var/log/nginx/access.log
# If missing, check nginx configuration
grep access_log /etc/nginx/nginx.conf
```

2. **Check log permissions:**
```bash
# Falco needs read access
sudo chmod 644 /var/log/nginx/access.log
sudo usermod -a -G adm falco
sudo systemctl restart falco-nginx
```

3. **Verify rules are loaded:**
```bash
ls -la /etc/falco/rules.d/nginx_rules.yaml
# Check for syntax errors
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

4. **Test with simple rule:**
```yaml
# /etc/falco/rules.d/test-nginx.yaml
- rule: Test nginx Access
  desc: Test rule for any nginx access
  condition: nginx.request_uri != ""
  output: "Test: nginx access detected"
  priority: INFO
  source: nginx
```

#### Permission Denied Errors

**Symptoms:**
- "Permission denied" in logs
- "Failed to open log file"

**Solutions:**

1. **Fix log file permissions:**
```bash
# Option 1: Add falco to adm group
sudo usermod -a -G adm falco

# Option 2: Adjust log permissions
sudo chmod 644 /var/log/nginx/*.log
```

2. **SELinux (if enabled):**
```bash
# Check SELinux status
getenforce

# Allow Falco to read logs
sudo setsebool -P daemons_enable_cluster_mode 1
# Or set to permissive temporarily
sudo setenforce 0
```

3. **AppArmor (if enabled):**
```bash
# Set Falco to complain mode
sudo aa-complain /usr/bin/falco
```

#### Falco Service Won't Start

**Symptoms:**
- `systemctl start falco` fails
- Exit code errors

**Solutions:**

1. **Check kernel module issues:**
```bash
# Try plugin-only mode
sudo /usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
```

2. **Use appropriate service:**
```bash
# If kernel module fails, use modern BPF
sudo systemctl stop falco
sudo systemctl start falco-modern-bpf
```

3. **Check port conflicts:**
```bash
# Default Falco gRPC port
sudo lsof -i :5060
```

#### High Resource Usage

**Symptoms:**
- High CPU or memory usage
- System slowdown

**Solutions:**

1. **Reduce buffer size:**
```yaml
init_config:
  buffer_size: 8192  # Reduce from larger values
```

2. **Limit monitored files:**
```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log  # Only essential logs
```

3. **Optimize rules:**
   - Remove unnecessary rules
   - Use specific conditions
   - Avoid complex regex

#### Rules Not Triggering

**Symptoms:**
- Attacks don't generate alerts
- Rules seem incorrect

**Solutions:**

1. **Check rule syntax:**
```bash
# Validate rules file
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

2. **Verify source attribute:**
```yaml
# All nginx rules must have:
source: nginx
```

3. **Test with curl:**
```bash
# SQL injection test
curl -v "http://localhost/test.php?id=' OR '1'='1"

# Check exact log format
tail -n 1 /var/log/nginx/access.log
```

#### Log Rotation Issues

**Symptoms:**
- Falco stops reading after rotation
- Old logs not being processed

**Solutions:**

1. **Ensure proper rotation config:**
```bash
# Check logrotate configuration
cat /etc/logrotate.d/nginx

# Should include:
postrotate
    kill -USR1 $(cat /var/run/nginx.pid)
endscript
```

2. **Manual rotation test:**
```bash
sudo logrotate -f /etc/logrotate.d/nginx
# Monitor Falco behavior
sudo journalctl -u falco-nginx -f
```

### Debug Commands

#### Verbose Logging

```bash
# Run Falco in foreground with debug output
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v

# Increase log verbosity
sudo sed -i 's/log_level: info/log_level: debug/' /etc/falco/falco.yaml
sudo systemctl restart falco-nginx
```

#### Test Individual Components

```bash
# Test plugin loading only
sudo falco --list-plugins

# Test rule loading only
sudo falco --list

# Dry run mode
sudo falco -c /etc/falco/falco.yaml --dry-run
```

#### Performance Debugging

```bash
# Check event processing
sudo journalctl -u falco-nginx -f | grep -E "events/sec|throughput"

# Monitor system resources
top -p $(pgrep falco)

# Check for dropped events
sudo journalctl -u falco | grep -i drop
```

### Getting Help

1. **Check logs first:**
   - System logs: `/var/log/syslog`
   - Falco logs: `journalctl -u falco`
   - nginx logs: `/var/log/nginx/error.log`

2. **Collect diagnostic info:**
```bash
# System info
uname -a
falco --version
nginx -v

# Plugin info
ls -la /usr/share/falco/plugins/
cat /etc/falco/falco.yaml | grep -A10 plugins:
```

3. **Report issues:**
   - GitHub Issues: https://github.com/takaosgb3/falco-plugin-nginx/issues
   - Include diagnostic info
   - Provide reproduction steps

### Next Steps

- [Configuration Guide](configuration.md)
- [Performance Tuning](performance.md)
- [Installation Guide](installation.md)

---

<a name="japanese"></a>
## 日本語

このガイドは、Falco nginxプラグインの一般的な問題の診断と解決を支援します。

### クイック診断

```bash
# Falcoのステータスを確認
sudo systemctl status falco-nginx

# プラグインがロードされているか確認
sudo falco --list-plugins | grep nginx

# 最近のログを表示
sudo journalctl -u falco-nginx -n 100

# デバッグモードでテスト
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v
```

### よくある問題

#### プラグインがロードされない

**症状:**
- `falco --list-plugins`にプラグインが表示されない
- エラー: "Unable to load plugin"

**解決方法:**

1. **ファイル権限を確認:**
```bash
ls -la /usr/share/falco/plugins/libfalco-nginx-plugin.so
# 以下のようになっているべき: -rw-r--r-- 1 root root
sudo chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so
```

2. **ライブラリ依存関係を確認:**
```bash
ldd /usr/share/falco/plugins/libfalco-nginx-plugin.so
# "not found"エラーを確認
```

3. **Falco設定を確認:**
```bash
# 設定を検証
sudo falco --validate /etc/falco/falco.yaml

# プラグインセクションが存在するか確認
grep -A5 "plugins:" /etc/falco/falco.yaml
```

#### アラートが生成されない

**症状:**
- 攻撃をテストしてもアラートが出ない
- プラグインはロードされるが非アクティブに見える

**解決方法:**

1. **nginxログが存在することを確認:**
```bash
ls -la /var/log/nginx/access.log
# 存在しない場合、nginx設定を確認
grep access_log /etc/nginx/nginx.conf
```

2. **ログ権限を確認:**
```bash
# Falcoには読み取りアクセスが必要
sudo chmod 644 /var/log/nginx/access.log
sudo usermod -a -G adm falco
sudo systemctl restart falco-nginx
```

3. **ルールがロードされていることを確認:**
```bash
ls -la /etc/falco/rules.d/nginx_rules.yaml
# 構文エラーを確認
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

4. **シンプルなルールでテスト:**
```yaml
# /etc/falco/rules.d/test-nginx.yaml
- rule: Test nginx Access
  desc: nginxアクセスのテストルール
  condition: nginx.request_uri != ""
  output: "テスト: nginxアクセスを検出"
  priority: INFO
  source: nginx
```

#### 権限拒否エラー

**症状:**
- ログに"Permission denied"
- "Failed to open log file"

**解決方法:**

1. **ログファイル権限を修正:**
```bash
# オプション1: falcoをadmグループに追加
sudo usermod -a -G adm falco

# オプション2: ログ権限を調整
sudo chmod 644 /var/log/nginx/*.log
```

2. **SELinux（有効な場合）:**
```bash
# SELinuxステータスを確認
getenforce

# Falcoにログ読み取りを許可
sudo setsebool -P daemons_enable_cluster_mode 1
# または一時的にpermissiveに設定
sudo setenforce 0
```

3. **AppArmor（有効な場合）:**
```bash
# Falcoをcomplainモードに設定
sudo aa-complain /usr/bin/falco
```

#### Falcoサービスが起動しない

**症状:**
- `systemctl start falco`が失敗
- 終了コードエラー

**解決方法:**

1. **カーネルモジュールの問題を確認:**
```bash
# プラグイン専用モードを試す
sudo /usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
```

2. **適切なサービスを使用:**
```bash
# カーネルモジュールが失敗する場合、modern BPFを使用
sudo systemctl stop falco
sudo systemctl start falco-modern-bpf
```

3. **ポート競合を確認:**
```bash
# デフォルトのFalco gRPCポート
sudo lsof -i :5060
```

#### 高リソース使用率

**症状:**
- 高いCPUまたはメモリ使用率
- システムの遅延

**解決方法:**

1. **バッファサイズを削減:**
```yaml
init_config:
  buffer_size: 8192  # より大きな値から削減
```

2. **監視ファイルを制限:**
```yaml
init_config:
  log_paths:
    - /var/log/nginx/access.log  # 必須ログのみ
```

3. **ルールを最適化:**
   - 不要なルールを削除
   - 特定の条件を使用
   - 複雑な正規表現を避ける

#### ルールがトリガーされない

**症状:**
- 攻撃してもアラートが生成されない
- ルールが正しくないように見える

**解決方法:**

1. **ルール構文を確認:**
```bash
# ルールファイルを検証
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml
```

2. **source属性を確認:**
```yaml
# すべてのnginxルールには以下が必要:
source: nginx
```

3. **curlでテスト:**
```bash
# SQLインジェクションテスト
curl -v "http://localhost/test.php?id=' OR '1'='1"

# 正確なログフォーマットを確認
tail -n 1 /var/log/nginx/access.log
```

#### ログローテーションの問題

**症状:**
- ローテーション後にFalcoが読み取りを停止
- 古いログが処理されない

**解決方法:**

1. **適切なローテーション設定を確保:**
```bash
# logrotate設定を確認
cat /etc/logrotate.d/nginx

# 以下が含まれているべき:
postrotate
    kill -USR1 $(cat /var/run/nginx.pid)
endscript
```

2. **手動ローテーションテスト:**
```bash
sudo logrotate -f /etc/logrotate.d/nginx
# Falcoの動作を監視
sudo journalctl -u falco-nginx -f
```

### デバッグコマンド

#### 詳細ログ

```bash
# デバッグ出力でFalcoをフォアグラウンドで実行
sudo falco -c /etc/falco/falco.yaml --disable-source syscall -v

# ログの詳細度を上げる
sudo sed -i 's/log_level: info/log_level: debug/' /etc/falco/falco.yaml
sudo systemctl restart falco-nginx
```

#### 個別コンポーネントのテスト

```bash
# プラグインロードのみテスト
sudo falco --list-plugins

# ルールロードのみテスト
sudo falco --list

# ドライランモード
sudo falco -c /etc/falco/falco.yaml --dry-run
```

#### パフォーマンスデバッグ

```bash
# イベント処理を確認
sudo journalctl -u falco-nginx -f | grep -E "events/sec|throughput"

# システムリソースを監視
top -p $(pgrep falco)

# ドロップされたイベントを確認
sudo journalctl -u falco | grep -i drop
```

### ヘルプを得る

1. **まずログを確認:**
   - システムログ: `/var/log/syslog`
   - Falcoログ: `journalctl -u falco`
   - nginxログ: `/var/log/nginx/error.log`

2. **診断情報を収集:**
```bash
# システム情報
uname -a
falco --version
nginx -v

# プラグイン情報
ls -la /usr/share/falco/plugins/
cat /etc/falco/falco.yaml | grep -A10 plugins:
```

3. **問題を報告:**
   - GitHub Issues: https://github.com/takaosgb3/falco-plugin-nginx/issues
   - 診断情報を含める
   - 再現手順を提供

### 次のステップ

- [設定ガイド](configuration.md)
- [パフォーマンスチューニング](performance.md)
- [インストールガイド](installation.md)