# EC2でのeBPF有効化ガイド

## 問題

EC2インスタンスでFalcoをインストールした際、カーネルモジュールがロードできず、nginxプラグインのみのモードになってしまうことがあります。

```
Mode: nginx monitoring only (kernel module not loaded)
```

## 原因

1. **EC2のカーネル制限**: EC2インスタンスではカーネルモジュールのロードが制限されています
2. **eBPFの未設定**: FalcoはeBPFをサポートしていますが、自動的には有効化されません

## 解決方法

### 方法1: install.sh v1.0.1を使用（推奨）

最新版のinstall.shは自動的にeBPFを検出して有効化します：

```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

インストーラーは以下の順序で試行します：
1. カーネルモジュール
2. Modern eBPF（カーネル5.8以上）
3. Legacy eBPF（カーネル4.14以上）
4. プラグインのみモード（フォールバック）

### 方法2: 手動でeBPFを有効化

既にインストール済みの場合：

```bash
# Modern eBPF を有効化（カーネル5.8以上）
sudo mkdir -p /etc/systemd/system/falco.service.d
sudo tee /etc/systemd/system/falco.service.d/modern-bpf.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --modern-bpf
EOF

# サービスを再起動
sudo systemctl daemon-reload
sudo systemctl restart falco

# 確認
sudo journalctl -u falco -n 20
```

### 方法3: Legacy eBPFを使用（古いカーネル）

カーネル4.14-5.7の場合：

```bash
# Legacy eBPF を有効化
sudo mkdir -p /etc/systemd/system/falco.service.d
sudo tee /etc/systemd/system/falco.service.d/bpf.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --bpf
EOF

# サービスを再起動
sudo systemctl daemon-reload
sudo systemctl restart falco
```

## カーネルバージョンの確認

```bash
# カーネルバージョンを確認
uname -r

# eBPFサポート状況
# 5.8以上: Modern eBPF対応
# 4.14-5.7: Legacy eBPF対応
# 4.14未満: eBPF非対応（プラグインのみ）
```

## 動作確認

eBPFが有効化されているか確認：

```bash
# ステータス確認
sudo systemctl status falco

# ログで確認
sudo journalctl -u falco | grep -E "(BPF|ebpf|driver)"

# 両方の監視が動作しているかテスト
# 1. nginxログ監視
curl "http://localhost/test.php?q=%27%20OR%20%271%27%3D%271"

# 2. システムコール監視（eBPFが有効な場合のみ）
cat /etc/shadow 2>/dev/null
```

## トラブルシューティング

### eBPFが起動しない場合

1. **BTFサポートの確認**:
```bash
ls /sys/kernel/btf/vmlinux
```
存在しない場合、カーネルがBTFをサポートしていません。

2. **必要なパッケージのインストール**:
```bash
sudo apt-get update
sudo apt-get install -y linux-headers-$(uname -r)
```

3. **Falcoドライバーのビルド**:
```bash
sudo falco-driver-loader
```

### EC2での推奨設定

EC2では以下の順序で試すことを推奨：

1. **Amazon Linux 2023 / Ubuntu 22.04**: Modern eBPF（`--modern-bpf`）
2. **Amazon Linux 2 / Ubuntu 20.04**: Legacy eBPF（`--bpf`）
3. **古いAMI**: プラグインのみモード（`--disable-source syscall`）

## まとめ

- EC2ではカーネルモジュールの代わりにeBPFを使用
- v1.0.1のinstall.shは自動的にeBPFを検出・有効化
- カーネルバージョンに応じて適切なeBPFモードを選択
- eBPFにより、システムコールとnginxログの両方を監視可能