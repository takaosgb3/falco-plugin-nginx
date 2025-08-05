# Building the Falco Nginx Plugin

This guide explains how to build the Falco nginx plugin from source.

## Prerequisites

- Go 1.22 or higher
- Make
- gcc (for CGO)
- Linux x86_64 (for production builds)

### macOS Development Note

While development can be done on macOS, the final plugin binary must be built on Linux x86_64 for use with Falco. The plugin uses CGO and produces a shared library (.so file) that is platform-specific.

For macOS developers:
1. You can write and test code on macOS
2. Use Docker or a Linux VM for final builds
3. Or use GitHub Actions for automated Linux builds

## Quick Build

### On Linux
```bash
# Clone the repository
git clone https://github.com/takaosgb3/falco-plugin-nginx.git
cd falco-plugin-nginx

# Build the plugin
make build
```

### On macOS (using Docker)
```bash
# Clone the repository
git clone https://github.com/takaosgb3/falco-plugin-nginx.git
cd falco-plugin-nginx

# Build Linux binary using Docker
make docker-build
```

The plugin binary will be created at `build/plugin/libfalco-nginx-plugin.so`.

## Build Commands

### Standard Build
```bash
make build
```

### Clean Build Directory
```bash
make clean
```

### Install to System
```bash
make install
```
This installs the plugin to `/usr/share/falco/plugins/`.

### Generate Checksum
```bash
make checksum
```

## Build for Different Architectures

Currently, only Linux x86_64 is officially supported. For other architectures, you may need to modify the build flags.

## Troubleshooting

### Missing Dependencies
If you encounter missing dependencies:
```bash
go mod download
go mod tidy
```

### CGO Errors
Ensure you have gcc installed:
```bash
sudo apt-get install build-essential  # Debian/Ubuntu
sudo yum install gcc                   # RHEL/CentOS
```

### Permission Errors
The `make install` command requires sudo privileges to copy files to system directories.

## Development

For development, you can build and test locally:
```bash
# Build
make build

# Run Falco with the local plugin
sudo falco --disable-source syscall \
  -c /etc/falco/falco.yaml \
  --plugin-path ./build/plugin/libfalco-nginx-plugin.so
```

## Version Management

The plugin version is defined in the Makefile. To update:
```bash
# Edit Makefile
VERSION := 0.3.2  # Update this line
```

---

# Falco Nginx プラグインのビルド

このガイドでは、Falco nginxプラグインをソースからビルドする方法を説明します。

## 前提条件

- Go 1.22以上
- Make
- gcc（CGO用）
- Linux x86_64（本番ビルド用）

### macOS開発時の注意

macOSで開発は可能ですが、Falcoで使用する最終的なプラグインバイナリはLinux x86_64でビルドする必要があります。プラグインはCGOを使用し、プラットフォーム固有の共有ライブラリ（.soファイル）を生成します。

macOS開発者向け：
1. macOSでコードの記述とテストが可能
2. 最終ビルドにはDockerまたはLinux VMを使用
3. またはGitHub Actionsで自動Linux ビルドを利用

## クイックビルド

### Linuxの場合
```bash
# リポジトリをクローン
git clone https://github.com/takaosgb3/falco-plugin-nginx.git
cd falco-plugin-nginx

# プラグインをビルド
make build
```

### macOSの場合（Dockerを使用）
```bash
# リポジトリをクローン
git clone https://github.com/takaosgb3/falco-plugin-nginx.git
cd falco-plugin-nginx

# DockerでLinuxバイナリをビルド
make docker-build
```

プラグインバイナリは `build/plugin/libfalco-nginx-plugin.so` に作成されます。

## ビルドコマンド

### 標準ビルド
```bash
make build
```

### ビルドディレクトリのクリーン
```bash
make clean
```

### システムへのインストール
```bash
make install
```
プラグインを `/usr/share/falco/plugins/` にインストールします。

### チェックサム生成
```bash
make checksum
```

## 異なるアーキテクチャ向けのビルド

現在、Linux x86_64のみが公式にサポートされています。他のアーキテクチャでは、ビルドフラグの変更が必要な場合があります。

## トラブルシューティング

### 依存関係の不足
依存関係が不足している場合：
```bash
go mod download
go mod tidy
```

### CGOエラー
gccがインストールされていることを確認：
```bash
sudo apt-get install build-essential  # Debian/Ubuntu
sudo yum install gcc                   # RHEL/CentOS
```

### 権限エラー
`make install` コマンドはシステムディレクトリへのコピーにsudo権限が必要です。

## 開発

開発時は、ローカルでビルドとテストが可能です：
```bash
# ビルド
make build

# ローカルプラグインでFalcoを実行
sudo falco --disable-source syscall \
  -c /etc/falco/falco.yaml \
  --plugin-path ./build/plugin/libfalco-nginx-plugin.so
```

## バージョン管理

プラグインのバージョンはMakefileで定義されています。更新するには：
```bash
# Makefileを編集
VERSION := 0.3.2  # この行を更新
```