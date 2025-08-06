# Release Process for Falco nginx Plugin / Falco nginxプラグインのリリースプロセス

[English](#english) | [日本語](#japanese)

<a name="english"></a>
## English

### ⚠️ Critical: Binary Platform Requirements

**IMPORTANT**: Plugin binaries MUST be built for Linux x86_64. macOS binaries (Mach-O format) will NOT work on Linux servers.

### Prerequisites

1. **Self-hosted runner** configured on Linux x86_64
2. **GitHub CLI** (`gh`) installed and authenticated
3. **Go 1.22+** on the build environment

### Release Process

#### Option 1: GitHub Actions (Recommended)

1. **Trigger the workflow**:
```bash
gh workflow run build-release.yml -f version=v0.4.3
```

2. **Monitor the build**:
```bash
gh run list --workflow=build-release.yml --limit=1
gh run watch
```

3. **Verify the release**:
```bash
gh release view v0.4.3
```

#### Option 2: Manual Release (Emergency Only)

If GitHub Actions is unavailable, use a Linux environment:

1. **Build on Linux**:
```bash
# SSH to a Linux server or use Docker
cd cmd/plugin-sdk
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o libfalco-nginx-plugin-linux-amd64.so
```

2. **Verify binary format**:
```bash
file libfalco-nginx-plugin-linux-amd64.so
# MUST show: ELF 64-bit LSB shared object, x86-64
# NOT: Mach-O 64-bit
```

3. **Create checksums**:
```bash
sha256sum libfalco-nginx-plugin-linux-amd64.so > checksums.txt
sha256sum ../../rules/nginx_rules.yaml >> checksums.txt
```

4. **Create release**:
```bash
gh release create v0.4.3 \
  libfalco-nginx-plugin-linux-amd64.so \
  ../../rules/nginx_rules.yaml \
  checksums.txt \
  --title "Release v0.4.3" \
  --notes "Fixed Linux binary format"
```

### Verification Steps

After ANY release:

1. **Download and check binary**:
```bash
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.4.3/libfalco-nginx-plugin-linux-amd64.so
file libfalco-nginx-plugin-linux-amd64.so
# MUST show: ELF 64-bit LSB shared object
```

2. **Test installation**:
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

### Common Mistakes to Avoid

❌ **Building on macOS without cross-compilation**
❌ **Uploading without verifying binary format**
❌ **Skipping the `file` command verification**

---

<a name="japanese"></a>
## 日本語

### ⚠️ 重要: バイナリプラットフォーム要件

**重要**: プラグインバイナリは必ずLinux x86_64用にビルドする必要があります。macOSバイナリ（Mach-O形式）はLinuxサーバーでは動作しません。

### 前提条件

1. Linux x86_64で構成された**セルフホストランナー**
2. **GitHub CLI** (`gh`) がインストールされ認証済み
3. ビルド環境に**Go 1.22以上**

### リリースプロセス

#### オプション1: GitHub Actions（推奨）

1. **ワークフローをトリガー**:
```bash
gh workflow run build-release.yml -f version=v0.4.3
```

2. **ビルドを監視**:
```bash
gh run list --workflow=build-release.yml --limit=1
gh run watch
```

3. **リリースを確認**:
```bash
gh release view v0.4.3
```

#### オプション2: 手動リリース（緊急時のみ）

GitHub Actionsが利用できない場合、Linux環境を使用：

1. **Linuxでビルド**:
```bash
# LinuxサーバーにSSHまたはDockerを使用
cd cmd/plugin-sdk
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o libfalco-nginx-plugin-linux-amd64.so
```

2. **バイナリ形式を確認**:
```bash
file libfalco-nginx-plugin-linux-amd64.so
# 必ず表示される: ELF 64-bit LSB shared object, x86-64
# 表示されてはいけない: Mach-O 64-bit
```

3. **チェックサムを作成**:
```bash
sha256sum libfalco-nginx-plugin-linux-amd64.so > checksums.txt
sha256sum ../../rules/nginx_rules.yaml >> checksums.txt
```

4. **リリースを作成**:
```bash
gh release create v0.4.3 \
  libfalco-nginx-plugin-linux-amd64.so \
  ../../rules/nginx_rules.yaml \
  checksums.txt \
  --title "Release v0.4.3" \
  --notes "Linuxバイナリ形式を修正"
```

### 検証手順

すべてのリリース後：

1. **バイナリをダウンロードして確認**:
```bash
wget https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.4.3/libfalco-nginx-plugin-linux-amd64.so
file libfalco-nginx-plugin-linux-amd64.so
# 必ず表示される: ELF 64-bit LSB shared object
```

2. **インストールをテスト**:
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

### 避けるべき一般的な間違い

❌ **クロスコンパイルなしでmacOSでビルド**
❌ **バイナリ形式を確認せずにアップロード**
❌ **`file`コマンドでの確認をスキップ**