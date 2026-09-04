import 'dart:convert';
import 'dart:typed_data';
// cryptography 包自己也导出一个 CipherState，与本项目的类名冲突，隐藏掉。
import 'package:cryptography/cryptography.dart' hide CipherState;

import 'cipher_state.dart';

/// Noise 的 SymmetricState：链式密钥 ck + 握手哈希 h + 一个 CipherState。
/// 对应桌面 `SymmetricState.cs`。
class SymmetricState {
  static const int _hashLen = 32;

  Uint8List _ck = Uint8List(_hashLen);
  Uint8List _h = Uint8List(_hashLen);
  final CipherState _cs = CipherState();

  Future<void> initializeSymmetric(String protocolName) async {
    final name = Uint8List.fromList(ascii.encode(protocolName));
    if (name.length <= _hashLen) {
      _h = Uint8List(_hashLen); // 不足 32 字节补 0
      _h.setAll(0, name);
    } else {
      _h = Uint8List.fromList((await Sha256().hash(name)).bytes);
    }
    _ck = Uint8List.fromList(_h);
    _cs.initializeKey(null);
  }

  Future<void> mixKey(List<int> inputKeyMaterial) async {
    final (ck, tempK) = await _hkdf2(_ck, inputKeyMaterial);
    _ck = ck;
    _cs.initializeKey(tempK);
  }

  Future<void> mixHash(List<int> data) async {
    final buf = Uint8List(_h.length + data.length)
      ..setAll(0, _h)
      ..setAll(_h.length, data);
    _h = Uint8List.fromList((await Sha256().hash(buf)).bytes);
  }

  Uint8List get handshakeHash => _h;

  Future<Uint8List> encryptAndHash(List<int> plaintext) async {
    final ct = await _cs.encryptWithAd(_h, plaintext);
    await mixHash(ct);
    return ct;
  }

  Future<Uint8List> decryptAndHash(Uint8List ciphertext) async {
    final pt = await _cs.decryptWithAd(_h, ciphertext);
    await mixHash(ciphertext);
    return pt;
  }

  /// 握手结束，派生收发两个 CipherState。发起方用 (c1=发, c2=收)。
  Future<(CipherState, CipherState)> split() async {
    final (k1, k2) = await _hkdf2(_ck, const <int>[]);
    final c1 = CipherState()..initializeKey(k1);
    final c2 = CipherState()..initializeKey(k2);
    return (c1, c2);
  }

  // Noise 版 HKDF，输出 2 段：temp_key=HMAC(ck, ikm)；o1=HMAC(temp_key,0x01)；
  // o2=HMAC(temp_key, o1||0x02)。
  static Future<(Uint8List, Uint8List)> _hkdf2(
      List<int> ck, List<int> ikm) async {
    final tempKey = await _hmac(ck, ikm);
    final o1 = await _hmac(tempKey, const [0x01]);
    final o2 = await _hmac(tempKey, [...o1, 0x02]);
    return (o1, o2);
  }

  static Future<Uint8List> _hmac(List<int> key, List<int> data) async {
    final mac =
        await Hmac.sha256().calculateMac(data, secretKey: SecretKey(key));
    return Uint8List.fromList(mac.bytes);
  }
}
