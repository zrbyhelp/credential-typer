import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// X25519 密钥对。私钥即 32 字节种子（与 BouncyCastle 的原始私钥语义一致：
/// 私钥不做二次哈希，clamp 在标量乘内部完成 —— 两端对同一私钥得到同一公钥/同一 DH 结果）。
class DhKeyPair {
  final Uint8List privateKey; // 32 字节种子
  final Uint8List publicKey; // 32 字节
  const DhKeyPair(this.privateKey, this.publicKey);
}

/// X25519：生成密钥对、做原始 DH（Noise 的 MixKey 需要 32 字节原始结果）。
/// 对应桌面 `Dh.cs`。
class Dh {
  static final X25519 _x = X25519();

  static Future<DhKeyPair> generate() async {
    final kp = await _x.newKeyPair();
    return _materialize(kp);
  }

  /// 从 32 字节私钥种子重建密钥对（对应 `Dh.FromPrivate`）。
  static Future<DhKeyPair> fromPrivate(List<int> seed32) async {
    final kp = await _x.newKeyPairFromSeed(List<int>.from(seed32));
    return _materialize(kp);
  }

  static Future<DhKeyPair> _materialize(SimpleKeyPair kp) async {
    final priv = await kp.extractPrivateKeyBytes();
    final pub = await kp.extractPublicKey();
    return DhKeyPair(Uint8List.fromList(priv), Uint8List.fromList(pub.bytes));
  }

  /// DH(本地私钥, 对端公钥) → 32 字节共享秘密（对应 `Dh.Agree`）。
  static Future<Uint8List> agree(
      List<int> localPrivate, List<int> remotePublic) async {
    final kp = await _x.newKeyPairFromSeed(List<int>.from(localPrivate));
    final secret = await _x.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(remotePublic, type: KeyPairType.x25519),
    );
    final bytes = await secret.extractBytes();
    return Uint8List.fromList(bytes);
  }
}
