import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// 协议级常量与派生工具，两端必须一致。对应桌面 `Protocol.cs`。
class Protocol {
  static const int version = 1;

  /// Prologue 基串，两端 MixHash。配对时其后附加 16 字节一次性配对码。
  static const String prologueBase = 'credential-typer/v1';

  static const int pairingCodeLen = 16;
  static const int publicKeyLen = 32;

  /// 连接前导：TCP 连上后手机先发 1 字节。
  static const int modePair = 0x01; // 走 Noise_IK
  static const int modeReconnect = 0x02; // 走 Noise_KK

  /// 重连（KK）prologue：仅基串。
  static Uint8List reconnectPrologue() =>
      Uint8List.fromList(ascii.encode(prologueBase));

  /// 配对（IK）prologue：基串 || 配对码。
  static Uint8List pairingPrologue(List<int> code) {
    final b = ascii.encode(prologueBase);
    return Uint8List(b.length + code.length)
      ..setAll(0, b)
      ..setAll(b.length, code);
  }

  static Uint8List newPairingCode() {
    final rng = Random.secure();
    return Uint8List.fromList(
        List<int>.generate(pairingCodeLen, (_) => rng.nextInt(256)));
  }

  /// 静态公钥指纹：SHA-256 前 8 字节，分 4 组每组 4 位十六进制。
  /// 配对时两端各自算、用户目视核对，防中间人。例：A1B2 C3D4 E5F6 0708
  static Future<String> fingerprint(List<int> publicKey) async {
    final hash = (await Sha256().hash(publicKey)).bytes;
    final sb = StringBuffer();
    for (int i = 0; i < 8; i++) {
      sb.write(hash[i].toRadixString(16).toUpperCase().padLeft(2, '0'));
      if (i.isOdd && i != 7) sb.write(' ');
    }
    return sb.toString();
  }
}
