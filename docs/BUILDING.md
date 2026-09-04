# 构建与开发

## 工具链

- .NET SDK 8（Windows Desktop workload）
- Flutter 3.19+ / Dart 3.3+
- Android SDK 35+（构建 Android APK）
- JDK 17 或 21（Android Gradle）

## 桌面端

还原、编译和测试：

```powershell
dotnet restore desktop/CredentialTyper.sln
dotnet build desktop/CredentialTyper.sln -c Release
dotnet test desktop/CredentialTyper.sln -c Release
```

主要项目：`CredentialTyper.Transport`（协议/Noise）、`CredentialTyper.Core`（注入和桌面服务）、`CredentialTyper.App`（WinForms 托盘 UI）、`CredentialTyper.Cli`（诊断与联调）。

## 手机端

```powershell
cd app
flutter pub get
flutter analyze --no-fatal-infos
flutter test
flutter build apk --release
```

`mobile_scanner` 当前固定到已修复 CameraX 初始化异常的提交；升级前请在真实设备上验证扫码页。

## 互通测试

`app/test/noise_vectors_test.dart` 与 `desktop/CredentialTyper.Transport.Tests/NoiseVectorTests.cs` 使用同一组官方 Noise 向量。修改协议、密码学或帧格式时，必须同时更新两端并运行两套测试。
