import 'dart:convert';
import 'dart:typed_data';

/// RFC 4648 base64url（无填充）。与桌面 `Base64Url.cs` 一致：
/// 二维码 / JSON 里承载二进制公钥、配对码用。
class Base64Url {
  static String encode(List<int> data) =>
      base64Url.encode(data).replaceAll('=', '');

  static Uint8List decode(String s) {
    final pad = (4 - s.length % 4) % 4;
    return base64Url.decode(s + ('=' * pad));
  }
}
