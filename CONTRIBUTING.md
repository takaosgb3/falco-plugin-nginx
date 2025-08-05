# Contributing to Falco Nginx Plugin / Falco Nginx プラグインへの貢献

[English](#english) | [日本語](#日本語)

## English

Thank you for your interest in contributing to the Falco nginx plugin! This guide will help you get started.

## How to Contribute

1. **Fork the Repository**
   - Fork the repository on GitHub
   - Clone your fork locally

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow the coding standards
   - Add tests for new features
   - Update documentation as needed

4. **Test Your Changes**
   ```bash
   make test
   make build
   ```

5. **Submit a Pull Request**
   - Push your changes to your fork
   - Create a pull request with a clear description

## Development Setup

### Prerequisites
- Go 1.22+
- Make
- gcc (for CGO)
- Falco 0.36.0+ (for testing)

### Building
```bash
make build
```

### Testing
```bash
make test
```

## Code Style

- Follow standard Go formatting (`go fmt`)
- Use meaningful variable and function names
- Add comments for exported functions
- Keep functions small and focused

## Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting PR
- Test with actual nginx logs when possible

## Documentation

- Update README.md if adding new features
- Add inline documentation for complex logic
- Update CHANGELOG.md with your changes

## Reporting Issues

- Use GitHub Issues to report bugs
- Include Falco version and plugin version
- Provide steps to reproduce
- Include relevant log excerpts

## Questions?

Feel free to open an issue for questions or discussions.

---

# Falco Nginx プラグインへの貢献

Falco nginxプラグインへの貢献に興味を持っていただきありがとうございます！このガイドが参考になれば幸いです。

## 貢献方法

1. **リポジトリをフォーク**
   - GitHubでリポジトリをフォーク
   - フォークをローカルにクローン

2. **ブランチを作成**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **変更を加える**
   - コーディング規約に従う
   - 新機能にはテストを追加
   - 必要に応じてドキュメントを更新

4. **変更をテスト**
   ```bash
   make test
   make build
   ```

5. **プルリクエストを送信**
   - フォークに変更をプッシュ
   - 明確な説明付きでプルリクエストを作成

## 開発環境のセットアップ

### 前提条件
- Go 1.22+
- Make
- gcc（CGO用）
- Falco 0.36.0+（テスト用）

### ビルド
```bash
make build
```

### テスト
```bash
make test
```

## コードスタイル

- 標準的なGoフォーマットに従う（`go fmt`）
- 意味のある変数名と関数名を使用
- エクスポートされた関数にはコメントを追加
- 関数は小さく、焦点を絞って作成

## テスト

- 新機能には単体テストを作成
- PR送信前にすべてのテストが通過することを確認
- 可能な限り実際のnginxログでテスト

## ドキュメント

- 新機能を追加する場合はREADME.mdを更新
- 複雑なロジックにはインラインドキュメントを追加
- 変更内容をCHANGELOG.mdに記録

## 問題の報告

- バグ報告にはGitHub Issuesを使用
- Falcoバージョンとプラグインバージョンを含める
- 再現手順を提供
- 関連するログの抜粋を含める

## 質問がありますか？

質問や議論のためにイシューを開くことをお気軽にどうぞ。