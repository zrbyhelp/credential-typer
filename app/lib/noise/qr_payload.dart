import 'dart:convert';
import 'dart:typed_data';

import 'base64url.dart';
import 'protocol.dart';

/// 二维码内容：桌面身份公钥 + LAN 地址 + 一次性配对码。
/// 序列化为 UTF-8 JSON 再 base64url。对应桌面 `QrPayload.cs`。
class QrPayload {
  final int version;
  final String sPub; // 桌面静态公钥 base64url
  final List<String> host; // 桌面所有 LAN IPv4
  final int port;
  final String code; // 一次性配对码 base64url

  const QrPayload({
    required this.version,
    required this.sPub,
    required this.host,
    required this.port,
    required this.code,
  });

  Uint8List get sPubBytes => Base64Url.decode(sPub);
  Uint8List get codeBytes => Base64Url.decode(code);

  static QrPayload fromQrText(String qr) {
    // QR scanners and clipboard managers may add line breaks, a BOM, or
    // zero-width spaces.  They are not part of the base64url payload.
    final cleaned = qr.replaceAll(
      RegExp(r'[\u0000-\u0020\u00a0\u200b\u200c\u200d\ufeff]'),
      '',
    );
    if (cleaned.isEmpty) throw const FormatException('连接码为空');

    late final Map<String, dynamic> map;
    try {
      final jsonBytes = Base64Url.decode(cleaned);
      final decoded = jsonDecode(utf8.decode(jsonBytes));
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('连接码格式错误');
      }
      map = decoded;
    } on FormatException {
      rethrow;
    } catch (_) {
      throw const FormatException('连接码格式错误');
    }

    final version = (map['v'] as num?)?.toInt() ?? 0;
    final sPub = map['spub'] as String? ?? '';
    final code = map['code'] as String? ?? '';
    final hosts = (map['host'] as List<dynamic>? ?? const [])
        .map((e) => e.toString().trim())
        .where((e) => e.isNotEmpty)
        .toSet()
        .toList();
    final port = (map['port'] as num?)?.toInt() ?? 0;

    if (version != Protocol.version) {
      throw FormatException('不支持的连接码版本：$version');
    }
    if (hosts.isEmpty) throw const FormatException('连接码缺少电脑地址');
    if (port < 1 || port > 65535) throw const FormatException('连接码端口无效');

    try {
      if (Base64Url.decode(sPub).length != Protocol.publicKeyLen ||
          Base64Url.decode(code).length != Protocol.pairingCodeLen) {
        throw const FormatException('连接码指纹或配对码无效');
      }
    } catch (_) {
      throw const FormatException('连接码指纹或配对码无效');
    }

    return QrPayload(
      version: version,
      sPub: sPub,
      host: hosts,
      port: port,
      code: code,
    );
  }

  String toQrText() {
    final json = jsonEncode({
      'v': version,
      'spub': sPub,
      'host': host,
      'port': port,
      'code': code,
    });
    return Base64Url.encode(utf8.encode(json));
  }
}
