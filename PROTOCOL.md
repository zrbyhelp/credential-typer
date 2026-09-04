# Credential Typer 线路协议 v1

手机（发起方 initiator）与桌面（响应方 responder）之间的通信规范。
两端**必须**按本文件实现，任何一处不一致都会握手失败。

## 0. 密码学套件

- 曲线：**X25519**（.NET 用 NSec，Dart 用 `cryptography` 包 `X25519`）
- AEAD：**ChaCha20-Poly1305**（.NET 内置 `ChaCha20Poly1305`，Dart `Chacha20.poly1305Aead`）
- 哈希：**SHA-256**（两端内置）
- Noise 协议名：
  - 配对：`Noise_IK_25519_ChaChaPoly_SHA256`
  - 重连：`Noise_KK_25519_ChaChaPoly_SHA256`
- Prologue：ASCII 字符串 `"credential-typer/v1"`（两端一致 MixHash 进去）

Noise 术语沿用规范：`s`=静态密钥，`e`=临时密钥，`es/se/ss/ee`=对应 DH。
IK 消息模式：
```
<- s              (预消息：发起方已通过二维码知道响应方 s)
-> e, es, s, ss   (msg1)
<- e, ee, se      (msg2)
```
KK 消息模式：
```
-> s              (预消息)
<- s              (预消息)
-> e, es, ss      (msg1)
<- e, ee, se      (msg2)
```

## 1. 身份密钥

- 桌面持久化一对 X25519 静态密钥 `Sd`。私钥用 DPAPI（`ProtectedData`，CurrentUser）加密落盘。
- 手机持久化一对 X25519 静态密钥 `Sp`。私钥进 Android Keystore / iOS Keychain。
- 配对成功后，双方各自存下对端的静态**公钥**（明文即可，公钥不敏感）。

## 2. 配对（扫码）

桌面显示二维码，内容是 UTF-8 JSON 再 base64url：

```json
{
  "v": 1,
  "spub": "<桌面静态公钥 32 字节 base64url>",
  "host": ["192.168.1.20"],        // 桌面所有 LAN IPv4，手机逐个尝试
  "port": 47820,
  "code": "<一次性配对码 16 字节 base64url>"
}
```

- 二维码有效期 3 分钟，超时桌面重新生成 `code`。
- 手机扫码 → 拿到 `spub`（把它作为 IK 预消息里的响应方 `s`，即**对桌面身份的 pin**）。
- 手机连 TCP，跑 **Noise_IK** 握手，`code` 作为 prologue 的一部分附加：
  实际 prologue = `"credential-typer/v1" || code(16B)`，两端都 MixHash。
  这样只有拿到当前二维码的手机能完成握手，且 MITM 无法冒充桌面（IK 会用 `spub` 认证）。
- 握手 msg1 里手机把自己的静态公钥 `Sp` 加密送达；桌面解出后**在界面显示 `Sp` 的指纹**
  （SHA-256 前 8 字节，分组显示如 `A1B2 C3D4 …`），用户在手机上核对一致后点确认，配对落库。
- 配对落库 = 双方互存对端静态公钥 + 一个配对记录 id。

## 2.5 连接前导

TCP 连上后，手机**先发 1 字节**告诉桌面这条连接的类型，桌面据此选握手模式：

| 字节 | 含义 | 握手 |
|---|---|---|
| `0x01` | 配对 | Noise_IK |
| `0x02` | 重连 | Noise_KK |

前导之后即是 2 字节分帧的握手消息（§4 的分帧）。

## 3. 重连（配对之后，每次连接）

- 手机在 LAN 内直接连上次的 `host:port`（可缓存；连不上再走一次扫码）。
- 跑 **Noise_KK** 握手，双方预消息都是对方已存的静态公钥。
- 任一方发现对端静态公钥与库里不符 → 立即断开（防冒充）。
- 握手完成后进入加密会话，`code` 不再需要。

## 4. 加密会话与分帧

握手完成后 Noise 产出两个 `CipherState`（发送/接收各一），nonce 从 0 单调递增。

每条应用消息：

```
[2 字节 大端 长度 N] [N 字节 Noise 密文]
```

- 长度上限 16384，超过视为异常断开。
- 密文 = ChaCha20-Poly1305(明文帧, nonce=计数器, ad=空)。
- nonce 到达 2^64-1 前必须重握手（实际到不了，留作断言）。

## 5. 应用消息（二进制帧，会话内加密传输）

解密后的明文帧，**第 1 字节是消息类型 tag**，其后是该类型的 body：

| tag | 方向 | 含义 | body |
|---|---|---|---|
| `0x01` | 桌面→手机 | `ctx` 焦点上下文 | UTF-8 JSON |
| `0x02` | 手机→桌面 | `ping` 心跳 | 空 |
| `0x03` | 桌面→手机 | `pong` 心跳应答 | 空 |
  | `0x04` | 手机→桌面 | `fill` 注入 | `[1 字节 flags][UTF-8 明文密码字节…]` |
  | `0x05` | 桌面→手机 | `accountImport` 账号导入 | 二进制长度前缀字段（名称、账号、网站、备注、密码字节） |
  | `0x06` | 桌面→手机 | `filterSync` 搜索同步 | `[version][u16 长度][UTF-8 搜索词]` |

`accountImport` body 的第 1 字节为版本 `0x01`，随后是 6 个大端 `u16` 长度，依次对应名称、账号、网站、备注、标签 JSON、密码；总帧长不得超过 16384 字节。

**为什么 `fill` 不用 JSON**：JSON 解析必然把 `text` 字段实体化成不可变的
`string`（.NET/Dart 皆然），无法清零，违反「密码绝不进 string」的铁律。
因此 `fill` 用裸二进制：解密得到的整帧就是可清零的 `byte[]`，密码字节原地送注入器、
用完 `ZeroMemory`，全程不构造 `string`。

- `ctx`（tag `0x01`）body 是 JSON，非敏感，排序提示用：
  ```json
  { "app": "chrome.exe", "title": "登录 - Chrome",
    "field": { "kind": "password", "name": "请输入密码" } }
  ```
  `kind` ∈ `password | text | other | none`。
- `fill`（tag `0x04`）body：第 1 字节 flags，bit0=`enter`（置 1 则注入完补一个回车，
  用于"账号+回车""密码+回车登录"）；其余字节是 UTF-8 明文密码，长度即帧长减 2。
  **body 是敏感数据**，桌面解密后原地注入、立即清零，绝不落盘/日志/剪贴板。

## 6. 注入语义（桌面端）

- 收到 `fill` → 解析出 UTF-8 明文字节 → 用 `FocusedControlOf` 拿当前焦点子控件
  → 先试 `Injector`（SendInput），返回值不足则降级 `MessageInjector`（WM_CHAR）
  → `enter=true` 再补一个回车 → 清零缓冲。
- 桌面不判断该填账号还是密码；手机点哪个就发哪个 `fill`。

## 7. 安全不变量（两端共同遵守）

- 主密码忘记 = 数据永久丢失，无找回。
- 账号明文只在手机保险库解密后短暂存在于内存，发送时即时加密。
- 桌面侧明文凭据生命周期严格为：解密 → 注入 → 清零。
- 静态私钥不出设备；公钥交换只通过扫码这条带外可信信道 pin 桌面身份。
- 配对时必须做指纹可视核对，不可跳过。
