# Credential Typer

跨设备凭据填充器：在手机上保存账号密码，通过局域网加密连接，把选中的凭据注入 Windows 当前焦点输入框。

> 项目处于早期版本（v1）。请在使用前阅读[安全说明](SECURITY.md)。主密码没有找回机制，忘记后保险库无法恢复。

## 功能

- 手机端 Flutter 保险库：Argon2id 派生密钥，XChaCha20-Poly1305 逐条目加密。
- Windows 桌面端：系统托盘、二维码配对、焦点字段上下文、SendInput/WM_CHAR 双路径注入。
- 端到端 Noise 加密：首次配对使用 IK，后续连接使用 KK；X25519 + ChaCha20-Poly1305 + SHA-256。
- 密码以字节帧传输和注入，发送后立即清零，不写入日志、剪贴板或磁盘。
- 支持账号导入、搜索同步、断线 KK 重连，以及不依赖 .NET 安装的 Windows 单文件发布。

## 仓库结构

```text
app/       Flutter 手机端（Android / iOS 工程）
desktop/   .NET 8 Windows 桌面端、CLI 与测试
PROTOCOL.md  Noise 握手和应用帧协议（两端必须保持一致）
docs/      构建、发布和开发说明
```

## 快速开始

### Windows 桌面端

要求：Windows 10/11、.NET 8 SDK。构建并启动托盘应用：

```powershell
dotnet run --project desktop/CredentialTyper.App/CredentialTyper.App.csproj
```

也可以使用 CLI 进行诊断或联调：

```powershell
dotnet run --project desktop/CredentialTyper.Cli -- selftest
dotnet run --project desktop/CredentialTyper.Cli -- diagnose
dotnet run --project desktop/CredentialTyper.Cli -- serve
```

`serve` 会显示二维码文本和桌面指纹。手机首次配对时扫码并在两端目视核对指纹；配对后即可在手机点击“填账号/填密码”。完整流程见 [docs/USAGE.md](docs/USAGE.md)。

### 手机端

要求：Flutter 3.19+（当前验证版本 3.47.2）、Android SDK 或 Xcode。

```powershell
cd app
flutter pub get
flutter test
flutter build apk --release
```

APK 输出在 `app/build/app/outputs/flutter-apk/app-release.apk`。版本号位于 `app/pubspec.yaml`，发布前请递增 Android `versionCode`。

## 从源码发布

Windows 单文件发布（目标机器无需安装 .NET）：

```powershell
dotnet publish desktop/CredentialTyper.App/CredentialTyper.App.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

发布检查清单、校验和与 GitHub Release 流程见 [docs/RELEASING.md](docs/RELEASING.md)。

## 测试

```powershell
dotnet test desktop/CredentialTyper.sln -c Release
cd app; flutter analyze --no-fatal-infos; flutter test
```

Noise 官方向量测试确保 Dart 与 C# 实现逐字节互通；桌面测试还覆盖注入路径、帧编码和会话重连。

## 安全模型与限制

- 配对仅应在可信局域网进行，并始终核对手机与桌面显示的公钥指纹。
- 主密码忘记即数据永久丢失；请使用应用内加密备份并安全保管。
- 桌面注入受 Windows UIPI、目标程序完整性级别和安全软件影响；遇到失败可运行 `ct diagnose` 或打开“注入自检”。
- 项目不承诺替代专业密码管理器，也不提供云同步或远程访问。

协议细节和安全不变量记录在 [PROTOCOL.md](PROTOCOL.md)。发现安全问题请遵循 [SECURITY.md](SECURITY.md)，不要直接公开发布利用细节。

## 参与贡献

欢迎提交 issue 和 pull request。提交前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，并确保没有提交构建目录、个人保险库、私钥或日志。

## License

本项目以 [MIT License](LICENSE) 发布。
