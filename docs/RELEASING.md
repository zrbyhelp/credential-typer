# 发布清单

1. 更新版本号：`app/pubspec.yaml` 的 marketing version 与 Android `versionCode`；桌面端更新 `CredentialTyper.App.csproj` 的版本属性和窗口标题。
2. 运行完整测试：`dotnet test desktop/CredentialTyper.sln -c Release`、`flutter analyze`、`flutter test`。
3. 构建 Windows 单文件和 Android APK，确认产物来自本次构建，不复用旧文件。
4. 计算 SHA-256：

   ```powershell
   Get-FileHash .\app-release.apk -Algorithm SHA256
   Get-FileHash .\凭据填充器.exe -Algorithm SHA256
   ```

5. 在 GitHub 创建版本标签（例如 `v1.1.0`），上传 ZIP/APK 和对应 `.sha256` 文件，发布说明包含支持平台、已知限制和升级步骤。
6. 发布后在干净的 Windows 和 Android 设备上完成一次扫码配对、填充、重启和重连验证。

不要提交 `app/build`、`.dart_tool`、`desktop/**/bin`、`desktop/**/obj`、本地配对记录、保险库或任何私钥。仓库根目录的 `.gitignore` 已覆盖常见构建产物；发布二进制应放在 GitHub Releases，不要直接塞进 Git 历史。
