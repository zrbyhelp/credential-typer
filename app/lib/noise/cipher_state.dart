import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Noise 的 CipherState：ChaCha20-Poly1305 + 单调递增 nonce。
/// Noise 的 96 位 nonce = 前 4 字节 0 || 小端 uint64 计数器。
/// 对应桌面 `CipherState.cs`，密文布局 = ct || 16 字节 tag。
class CipherState {
  static final Chacha20 _aead = Chacha20.poly1305Aead();

  Uint8List? _k; // 32 字节；null = 无密钥（明文透传）
  int _n = 0;

  void initializeKey(Uint8List? key) {
    _k = key;
    _n = 0;
  }

  bool get hasKey => _k != null;

  Future<Uint8List> encryptWithAd(List<int> ad, List<int> plaintext) async {
    if (_k == null) return Uint8List.fromList(plaintext);

    final box = await _aead.encrypt(
      plaintext,
      secretKey: SecretKey(_k!),
      nonce: _nonce(_n),
      aad: ad,
    );
    _n++;

    final out = Uint8List(box.cipherText.length + 16);
    out.setAll(0, box.cipherText);
    out.setAll(box.cipherText.length, box.mac.bytes);
    return out;
  }

  Future<Uint8List> decryptWithAd(List<int> ad, Uint8List ciphertext) async {
    if (_k == null) return Uint8List.fromList(ciphertext);
    if (ciphertext.length < 16) {
      throw const FormatException('密文短于认证标签长度');
    }

    final ctLen = ciphertext.length - 16;
    final box = SecretBox(
      ciphertext.sublist(0, ctLen),
      nonce: _nonce(_n),
      mac: Mac(ciphertext.sublist(ctLen)),
    );
    final pt = await _aead.decrypt(box, secretKey: SecretKey(_k!), aad: ad);
    _n++;
    return Uint8List.fromList(pt);
  }

  static Uint8List _nonce(int n) {
    final nonce = Uint8List(12); // 前 4 字节保持 0
    ByteData.sublistView(nonce).setUint64(4, n, Endian.little);
    return nonce;
  }
}
