# 凭据填充器 · 手机端（Flutter）

当前发布版本：`1.1.0`（Android `versionCode 4`）。本版本包含相机初始化崩溃保护、手动连接码预览和桌面搜索同步。

手机保险库 + Noise 加密传输，向已配对 PC 的当前焦点输入框注入账号/密码。
与桌面 C# 端（`../desktop`）按 [`../PROTOCOL.md`](../PROTOCOL.md) 同一协议实现，可互通。

## 结构

```
lib/
  noise/        Noise 传输层（IK 配对 / KK 重连，X25519+ChaCha20Poly1305+SHA256）
                —— 与 desktop/CredentialTyper.Transport 字节对齐
  crypto/       保险库静态加密（Argon2id→KEK→DEK，XChaCha20-Poly1305 逐条目）
  vault/        账户模型 + 保险库仓库（解锁后内存持 DEK，密码按需解密为字节）
  transport/    身份密钥（Keystore/Keychain）、配对记录、TCP 客户端
  state/        AppState / ConnectionManager（会话、收 ctx、发 fill、断线重连）
  ui/           创建/解锁/账户列表/详情/编辑/扫码配对
test/
  noise_vectors_test.dart  官方 cacophony 向量，与桌面 NoiseVectorTests.cs 完全一致
  vault_crypto_test.dart   KEK/封装/AAD/二维码往返
```

## 本机环境（已装好，2026-09-03）

- Flutter 3.47.2 → `E:\sdk\flutter`（已入用户 PATH）
- Android SDK 36 → `C:\Users\Administrator\AppData\Local\Android\sdk`（`ANDROID_HOME` 已设）
- JDK 21 → `C:\Program Files\Java\jdk-21.0.10`
- `flutter doctor` 全绿；平台目录已由 `flutter create .` 生成，相机/网络权限已配

构建 APK：

```bash
cd /e/ZRRK/credential-typer/app && E:/sdk/flutter/bin/flutter.bat build apk --release
```

产物：`build/app/outputs/flutter-apk/app-release.apk`。发布前请用 `aapt2 dump badging` 确认
`versionCode 4`，并计算 SHA-256 后再上传 GitHub Release；不要把旧的同名 APK 交给用户。

本版本将 `mobile_scanner` 固定到上游相机初始化错误回调修复提交
`e3afeba728897b9a508eb9a558b2aa54a8291d1b`。若重新生成 `pubspec.lock`，请确认该 Git
提交仍在 `package_config.json` 中。

配对页显示的旧版 `EndOfStream` 原文来自早期 APK；当前版本会将握手断开转换为简短的
网络/二维码提示。换电脑时请先退出旧桌面托盘进程、在新桌面端点击二维码刷新，再用
`1.1.0 (versionCode 4)` 手机包扫码。

### Windows 特有的坑（已修，别回退）

1. `cryptography` 包也导出 `CipherState` —— `lib/noise/symmetric_state.dart` 导入时
   `hide CipherState`，删掉会撞名编译失败。
2. Kotlin 增量缓存易被文件锁（杀毒扫描）破坏，报
   `Could not close incremental caches` —— `android/gradle.properties` 里的
   `kotlin.incremental=false` 就是治这个的。
3. Gradle 官方源在本网络极慢，wrapper 的 zip 已手动从腾讯镜像
   （`mirrors.cloud.tencent.com/gradle/`）下到 `~/.gradle/wrapper/dists`。
   升级 Gradle 版本时同样操作。

## 验证互通（已通过 ✅）

```bash
flutter test
```

**全部通过**（本机已验证）。其中 `noise_vectors_test.dart` 用与桌面 `NoiseVectorTests.cs`
**完全相同**的官方向量断言 IK/KK 每条握手消息的密文与 `handshake_hash`——
全中 = Dart 移植与 C# 字节级一致，两端握手可互通。

随后端到端联调：
1. PC 上 `dotnet run --project CredentialTyper.Cli -- serve`，出二维码文本
   （真机可另写个显示二维码的小页面；联调阶段可用任意二维码生成器把该文本转成码）。
2. 手机 App 首次设主密码 → 加账户 → 右上角扫码配对 → 核对指纹 → PC 上点接受。
3. PC 聚焦记事本/浏览器输入框 → 手机点「填账号 / 填密码（+回车）」→ 内容注入到该框。
4. 杀掉 App 重开 → 自动 KK 重连。

## 安全不变量（见 PROTOCOL.md §7）

- 主密码忘记 = 数据永久丢失，无找回。
- 密码在手机侧以字节形式按需解密，发送后即清零；UI 不显示明文密码。
- 桌面侧明文生命周期严格：解密 → 注入 → 清零（`fill` 走二进制帧，绝不进 string）。
- 静态私钥不出设备；配对必须目视核对指纹。

## 已知取舍（v1）

- 新增/编辑账户时，密码经 Flutter `TextField`（Dart `String`）录入 —— 这是平台文本框
  的固有限制；保存后即封装并清空控件。**发送与桌面注入路径**全程用可清零字节，是铁律的
  核心防线。后续可用平台安全键盘/自定义输入控件进一步收紧录入环节。
