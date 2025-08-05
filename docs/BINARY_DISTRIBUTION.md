# Binary Distribution Guidelines / バイナリ配布ガイドライン

[English](#english) | [日本語](#日本語)

## English

This document explains the licensing and distribution model for the Falco nginx plugin.

## Distribution Model

This repository follows an **open-source distribution model**:

- **What we provide**: Source code, pre-compiled binaries, documentation, and configuration files
- **Build from source**: You can build the plugin yourself using the provided source code
- **Pre-built binaries**: Available for quick deployment without compilation
- **Why this model**: Promotes transparency, community contributions, and ease of deployment

## Licensing

### Our License

The Falco nginx plugin is distributed under the **Apache License 2.0**.

This means you can:
- ✅ Use the plugin in production
- ✅ Modify the source code
- ✅ Distribute the plugin
- ✅ Include in commercial products
- ✅ Create derivative works

### Third-Party Components

Our plugin includes code from these open-source projects:

| Component | License | Usage |
|-----------|---------|-------|
| Falco Plugin SDK for Go | Apache 2.0 | Core plugin framework |
| Go standard library | BSD-style | Runtime and utilities |
| fsnotify | BSD-3-Clause | File monitoring |

### Your Obligations

When distributing our plugin:

1. **Include our LICENSE file**
2. **Include our NOTICE file** (for attribution)
3. **Preserve copyright notices**
4. **State any significant changes** (if you modify the source)

## Best Practices for Distribution

### 1. Security Verification

Always verify binary integrity:

```bash
# Download SHA256 checksum
curl -O https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.1/libfalco-nginx-plugin.so.sha256

# Verify binary
sha256sum -c libfalco-nginx-plugin.so.sha256
```

### 2. Version Management

- Pin to specific versions in production
- Test updates in staging first
- Keep SHA256 checksums for audit trails

### 3. Building from Source

To build your own binary:

```bash
git clone https://github.com/takaosgb3/falco-plugin-nginx
cd falco-plugin-nginx
make build
```

### 4. Documentation

When using our plugin:
- Link back to this repository
- Document which version you're using
- Include our troubleshooting guide

## FAQ

**Q: Can I use this plugin in commercial products?**
A: Yes, the Apache 2.0 license allows commercial use.

**Q: Do I need to open-source my Falco rules?**
A: No, your custom rules remain your property.

**Q: Can I contribute to the project?**
A: Yes! See our [Contributing Guide](../CONTRIBUTING.md).

**Q: How do I report security issues?**
A: Please report security vulnerabilities privately to the maintainers.

## Support

- **Issues**: [GitHub Issues](https://github.com/takaosgb3/falco-plugin-nginx/issues)
- **Contributions**: [Contributing Guide](../CONTRIBUTING.md)
- **Updates**: Watch this repository for new releases

---

## 日本語

このドキュメントでは、Falco nginxプラグインのライセンスと配布モデルについて説明します。

## 配布モデル

このリポジトリは**オープンソース配布モデル**に従っています：

- **提供内容**: ソースコード、ビルド済みバイナリ、ドキュメント、設定ファイル
- **ソースからのビルド**: 提供されたソースコードを使用してプラグインを自分でビルドできます
- **ビルド済みバイナリ**: コンパイルせずに迅速にデプロイするために利用可能
- **このモデルの理由**: 透明性、コミュニティの貢献、デプロイの容易さを促進

## ライセンス

### 私たちのライセンス

Falco nginxプラグインは**Apache License 2.0**の下で配布されています。

これにより以下が可能です：
- ✅ プロダクション環境での使用
- ✅ ソースコードの変更
- ✅ プラグインの配布
- ✅ 商用製品への組み込み
- ✅ 派生作品の作成

### サードパーティコンポーネント

私たちのプラグインには以下のオープンソースプロジェクトのコードが含まれています：

| コンポーネント | ライセンス | 用途 |
|--------------|----------|------|
| Falco Plugin SDK for Go | Apache 2.0 | コアプラグインフレームワーク |
| Go標準ライブラリ | BSDスタイル | ランタイムとユーティリティ |
| fsnotify | BSD-3-Clause | ファイル監視 |

### あなたの義務

私たちのプラグインを配布する際：

1. **LICENSEファイルを含める**
2. **NOTICEファイルを含める**（帰属のため）
3. **著作権表示を保持する**
4. **重要な変更を明記する**（ソースを変更した場合）

## 配布のベストプラクティス

### 1. セキュリティ検証

常にバイナリの整合性を確認：

```bash
# SHA256チェックサムをダウンロード
curl -O https://github.com/takaosgb3/falco-plugin-nginx/releases/download/v0.3.1/libfalco-nginx-plugin.so.sha256

# バイナリを検証
sha256sum -c libfalco-nginx-plugin.so.sha256
```

### 2. バージョン管理

- プロダクション環境では特定のバージョンに固定
- ステージング環境で更新を先にテスト
- 監査証跡のためSHA256チェックサムを保持

### 3. ソースからのビルド

独自のバイナリをビルドするには：

```bash
git clone https://github.com/takaosgb3/falco-plugin-nginx
cd falco-plugin-nginx
make build
```

### 4. ドキュメント

私たちのプラグインを使用する際：
- このリポジトリへのリンクを含める
- 使用しているバージョンを文書化
- トラブルシューティングガイドを含める

## FAQ

**Q: このプラグインを商用製品で使用できますか？**
A: はい、Apache 2.0ライセンスは商用利用を許可しています。

**Q: 私のFalcoルールをオープンソースにする必要がありますか？**
A: いいえ、カスタムルールはあなたの所有物のままです。

**Q: プロジェクトに貢献できますか？**
A: はい！[貢献ガイド](../CONTRIBUTING.md)をご覧ください。

**Q: セキュリティ問題をどのように報告すればよいですか？**
A: セキュリティの脆弱性は、メンテナーに非公開で報告してください。

## サポート

- **問題**: [GitHub Issues](https://github.com/takaosgb3/falco-plugin-nginx/issues)
- **貢献**: [貢献ガイド](../CONTRIBUTING.md)
- **更新**: 新しいリリースについてこのリポジトリをウォッチ