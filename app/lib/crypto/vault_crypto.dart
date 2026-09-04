import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Argon2id 参数（存进保险库头，便于日后升级强度）。
class KdfParams {
  final int memory; // KiB
  final int iterations;
  final int parallelism;
  const KdfParams({
    this.memory = 19456, // 19 MiB，OWASP 对 Argon2id 的移动端推荐
    this.iterations = 2,
    this.parallelism = 1,
  });

  Map<String, dynamic> toJson() =>
      {'mem': memory, 'iter': iterations, 'par': parallelism};

  factory KdfParams.fromJson(Map<String, dynamic> m) => KdfParams(
        memory: (m['mem'] as num).toInt(),
        iterations: (m['iter'] as num).toInt(),
        parallelism: (m['par'] as num).toInt(),
      );
}

/// 保险库静态加密：
///   主密码 --Argon2id(salt)--> KEK
///   KEK 封装随机 DEK
///   DEK 用 XChaCha20-Poly1305 逐条目封装元数据 / 密码
///
/// 全部只用于手机本机落盘（不参与与桌面的互通），故用 24 字节随机 nonce 的 XChaCha，
/// 免去 nonce 计数管理，最安全。密文布局 = nonce(24) || ct || tag(16)。
class VaultCrypto {
  static final Xchacha20 _aead = Xchacha20.poly1305Aead();
  static const int nonceLen = 24;
  static const int macLen = 16;

  static Future<Uint8List> deriveKek(
      List<int> passwordBytes, List<int> salt, KdfParams p) async {
    final algo = Argon2id(
      parallelism: p.parallelism,
      memory: p.memory,
      iterations: p.iterations,
      hashLength: 32,
    );
    final key = await algo.deriveKey(
      secretKey: SecretKey(passwordBytes),
      nonce: salt,
    );
    return Uint8List.fromList(await key.extractBytes());
  }

  static Future<Uint8List> seal(
    List<int> key,
    List<int> plaintext, {
    List<int> aad = const [],
  }) async {
    final nonce = _aead.newNonce();
    final box = await _aead.encrypt(
      plaintext,
      secretKey: SecretKey(key),
      nonce: nonce,
      aad: aad,
    );
    return Uint8List(nonce.length + box.cipherText.length + macLen)
      ..setAll(0, nonce)
      ..setAll(nonce.length, box.cipherText)
      ..setAll(nonce.length + box.cipherText.length, box.mac.bytes);
  }

  /// 解封。MAC 不符（主密码错 / 数据被篡改）会抛异常。
  static Future<Uint8List> open(
    List<int> key,
    Uint8List blob, {
    List<int> aad = const [],
  }) async {
    if (blob.length < nonceLen + macLen) {
      throw const FormatException('密文过短');
    }
    final nonce = blob.sublist(0, nonceLen);
    final mac = blob.sublist(blob.length - macLen);
    final ct = blob.sublist(nonceLen, blob.length - macLen);
    final box = SecretBox(ct, nonce: nonce, mac: Mac(mac));
    final pt = await _aead.decrypt(box, secretKey: SecretKey(key), aad: aad);
    return Uint8List.fromList(pt);
  }

  static Uint8List randomBytes(int n) {
    final algo = SecretKeyData.random(length: n);
    return Uint8List.fromList(algo.bytes);
  }
}
