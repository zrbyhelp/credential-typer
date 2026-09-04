# 贡献指南

## 开始之前

请先搜索已有 issue，并说明你使用的 Windows、.NET、Flutter 和 Android 版本。涉及协议或密码学的改动，请先开 issue 讨论兼容性和迁移方案。

## 提交前检查

```powershell
dotnet format desktop/CredentialTyper.sln --verify-no-changes
dotnet test desktop/CredentialTyper.sln -c Release
cd app
flutter analyze --no-fatal-infos
flutter test
```

如果本机没有 `dotnet format` 或 Android SDK，可至少运行对应平台的测试并在 PR 中注明未执行的项目。

## Pull Request 约定

- 一个 PR 聚焦一个主题，描述用户可见变化和安全影响。
- 不要提交构建目录、日志、截图、个人保险库、配对记录或密钥。
- 协议字段、Noise 状态机和明文生命周期的改动必须附测试，并同步更新 `PROTOCOL.md`。
- UI 文案保持中英文可读，错误提示不得泄露密码或私钥内容。

## AI 辅助提交约定

凡由 AI 辅助完成的提交，必须同步更新根目录 `CHANGELOG.md`；如果变更可供用户下载，
还要在 `docs/RELEASING.md` 和对应 GitHub Release 中记录版本、变更、已知限制及产物校验和。
