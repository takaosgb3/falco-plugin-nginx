# 🎉 Successful Setup Guide / セットアップ成功ガイド

[English](#english) | [日本語](#日本語)

## English

This document records the confirmed working setup for Falco nginx plugin as of 2025-08-05.

### ✅ Confirmed Working Environment

- **OS**: Ubuntu 22.04 LTS (AWS EC2)
- **Falco**: 0.41.3
- **nginx**: 1.18.0
- **PHP**: 8.1
- **Plugin**: libfalco-nginx-plugin.so (SDK version)

### ✅ Working Configuration

#### 1. Falco Configuration (`/etc/falco/falco.yaml`)

```yaml
rules_files:
#  - /etc/falco/falco_rules.yaml  # Commented out to avoid container plugin dependency
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

stdout_output:
  enabled: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

#### 2. Service Configuration (`/etc/systemd/system/falco-nginx.service`)

```ini
[Unit]
Description=Falco nginx Plugin Monitor
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### 3. Working Rules (`/etc/falco/rules.d/nginx_rules_simple.yaml`)

```yaml
- rule: Test nginx
  desc: Test rule for nginx plugin
  condition: nginx.method = "GET"
  output: "GET request detected from nginx"
  priority: NOTICE
  source: nginx
```

### ✅ Verification Steps

1. **Check Service Status**:
   ```bash
   sudo systemctl status falco-nginx.service
   # Should show: Active: active (running)
   ```

2. **Check Plugin Loading**:
   ```bash
   sudo falco --list-plugins | grep nginx
   # Should show: Name: nginx
   ```

3. **Monitor Logs**:
   ```bash
   sudo journalctl -u falco-nginx.service -f
   # Should show: "GET request detected from nginx" messages
   ```

### ✅ Important Notes

- The `--disable-source syscall` flag is required to run plugin-only mode
- Default falco_rules.yaml must be disabled to avoid container plugin dependency
- Priority values must be uppercase: CRITICAL, WARNING, NOTICE, INFORMATIONAL
- Output strings should be on a single line to avoid YAML parsing errors

---

## 日本語

このドキュメントは、2025年8月5日時点で確認されたFalco nginxプラグインの動作確認済みセットアップを記録しています。

### ✅ 動作確認済み環境

- **OS**: Ubuntu 22.04 LTS (AWS EC2)
- **Falco**: 0.41.3
- **nginx**: 1.18.0
- **PHP**: 8.1
- **プラグイン**: libfalco-nginx-plugin.so (SDK版)

### ✅ 動作する設定

#### 1. Falco設定 (`/etc/falco/falco.yaml`)

```yaml
rules_files:
#  - /etc/falco/falco_rules.yaml  # containerプラグイン依存を避けるためコメントアウト
  - /etc/falco/rules.d

json_output: true
json_include_output_property: true
log_level: info

stdout_output:
  enabled: true

load_plugins: [nginx]

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
```

#### 2. サービス設定 (`/etc/systemd/system/falco-nginx.service`)

```ini
[Unit]
Description=Falco nginx Plugin Monitor
After=network.target nginx.service

[Service]
Type=simple
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

#### 3. 動作するルール (`/etc/falco/rules.d/nginx_rules_simple.yaml`)

```yaml
- rule: Test nginx
  desc: Test rule for nginx plugin
  condition: nginx.method = "GET"
  output: "GET request detected from nginx"
  priority: NOTICE
  source: nginx
```

### ✅ 確認手順

1. **サービス状態の確認**:
   ```bash
   sudo systemctl status falco-nginx.service
   # Active: active (running) と表示されるはず
   ```

2. **プラグインロードの確認**:
   ```bash
   sudo falco --list-plugins | grep nginx
   # Name: nginx と表示されるはず
   ```

3. **ログの監視**:
   ```bash
   sudo journalctl -u falco-nginx.service -f
   # "GET request detected from nginx" メッセージが表示されるはず
   ```

### ✅ 重要な注意点

- プラグイン専用モードで実行するには `--disable-source syscall` フラグが必要
- containerプラグイン依存を避けるため、デフォルトのfalco_rules.yamlは無効化する必要がある
- priority値は大文字である必要がある: CRITICAL, WARNING, NOTICE, INFORMATIONAL
- YAMLパースエラーを避けるため、output文字列は1行にする必要がある