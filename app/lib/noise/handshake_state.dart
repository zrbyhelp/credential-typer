import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'cipher_state.dart';
import 'dh.dart';
import 'symmetric_state.dart';

enum NoisePattern { ik, kk }

/// 握手最后一条消息产出的收发 CipherState 对。
class TransportPair {
  final CipherState send;
  final CipherState recv;
  const TransportPair(this.send, this.recv);
}

/// Noise 握手状态机，支持 IK（配对）与 KK（重连）。
/// 只实现这两种模式所需 token：e s ee es se ss。对应桌面 `HandshakeState.cs`。
class HandshakeState {
  static const int _dhLen = 32;

  final SymmetricState _ss = SymmetricState();
  final bool _initiator;

  DhKeyPair _s; // 本地静态
  DhKeyPair? _e; // 本地临时
  Uint8List? _rs; // 对端静态公钥
  Uint8List? _re; // 对端临时公钥

  /// 仅测试用：注入固定临时私钥以复现 Noise 官方向量。生产保持 null（每次随机）。
  Uint8List? fixedEphemeralPrivate;

  final Queue<List<String>> _messagePatterns;

  HandshakeState._(this._initiator, this._s, this._rs, this._messagePatterns);

  /// 异步构造（InitializeSymmetric / MixHash 需要 SHA-256）。
  static Future<HandshakeState> create({
    required NoisePattern pattern,
    required bool initiator,
    required List<int> prologue,
    required DhKeyPair localStatic,
    Uint8List? remoteStatic,
  }) async {
    final patterns = Queue<List<String>>.of(pattern == NoisePattern.ik
        ? const [
            ['e', 'es', 's', 'ss'], // msg1 发起方
            ['e', 'ee', 'se'], // msg2 响应方
          ]
        : const [
            ['e', 'es', 'ss'], // msg1 发起方
            ['e', 'ee', 'se'], // msg2 响应方
          ]);

    final hs = HandshakeState._(initiator, localStatic, remoteStatic, patterns);

    final name = pattern == NoisePattern.ik
        ? 'Noise_IK_25519_ChaChaPoly_SHA256'
        : 'Noise_KK_25519_ChaChaPoly_SHA256';

    await hs._ss.initializeSymmetric(name);
    await hs._ss.mixHash(prologue);

    // 预消息：按 -> 行（发起方静态）、<- 行（响应方静态）顺序 MixHash。
    Uint8List? preInit;
    Uint8List? preResp;
    switch (pattern) {
      case NoisePattern.ik:
        // 只有 "<- s"
        preResp = initiator ? hs._rs : hs._s.publicKey;
        break;
      case NoisePattern.kk:
        // "-> s" 然后 "<- s"
        preInit = initiator ? hs._s.publicKey : hs._rs;
        preResp = initiator ? hs._rs : hs._s.publicKey;
        break;
    }
    if (preInit != null) await hs._ss.mixHash(preInit);
    if (preResp != null) await hs._ss.mixHash(preResp);

    return hs;
  }

  Uint8List get remoteStaticPublic {
    final rs = _rs;
    if (rs == null) throw StateError('对端静态公钥尚未获得');
    return rs;
  }

  Uint8List get handshakeHash => _ss.handshakeHash;

  /// 写一条握手消息；若是最后一条，返回派生的收发 CipherState。
  Future<(Uint8List, TransportPair?)> writeMessage(List<int> payload) async {
    final tokens = _messagePatterns.removeFirst();
    final buffer = BytesBuilder();

    for (final token in tokens) {
      switch (token) {
        case 'e':
          _e = fixedEphemeralPrivate == null
              ? await Dh.generate()
              : await Dh.fromPrivate(fixedEphemeralPrivate!);
          buffer.add(_e!.publicKey);
          await _ss.mixHash(_e!.publicKey);
          break;
        case 's':
          buffer.add(await _ss.encryptAndHash(_s.publicKey));
          break;
        default:
          await _ss.mixKey(await _dhToken(token));
          break;
      }
    }

    buffer.add(await _ss.encryptAndHash(payload));
    final transport = _messagePatterns.isEmpty ? await _finish() : null;
    return (buffer.toBytes(), transport);
  }

  /// 读一条握手消息；若是最后一条，返回派生的收发 CipherState。
  Future<(Uint8List, TransportPair?)> readMessage(Uint8List message) async {
    final tokens = _messagePatterns.removeFirst();
    int offset = 0;

    for (final token in tokens) {
      switch (token) {
        case 'e':
          _re = Uint8List.sublistView(message, offset, offset + _dhLen);
          offset += _dhLen;
          await _ss.mixHash(_re!);
          break;
        case 's':
          const len = _dhLen + 16; // 握手中传 s 时已有密钥，带 16 字节 tag
          _rs = await _ss.decryptAndHash(
              Uint8List.sublistView(message, offset, offset + len));
          offset += len;
          break;
        default:
          await _ss.mixKey(await _dhToken(token));
          break;
      }
    }

    final payload =
        await _ss.decryptAndHash(Uint8List.sublistView(message, offset));
    final transport = _messagePatterns.isEmpty ? await _finish() : null;
    return (payload, transport);
  }

  Future<Uint8List> _dhToken(String token) {
    switch (token) {
      case 'ee':
        return Dh.agree(_e!.privateKey, _re!);
      case 'ss':
        return Dh.agree(_s.privateKey, _rs!);
      case 'es':
        return _initiator
            ? Dh.agree(_e!.privateKey, _rs!)
            : Dh.agree(_s.privateKey, _re!);
      case 'se':
        return _initiator
            ? Dh.agree(_s.privateKey, _re!)
            : Dh.agree(_e!.privateKey, _rs!);
      default:
        throw StateError('未知 DH token: $token');
    }
  }

  // 发起方：先发后收 → (send=c1, recv=c2)；响应方相反。
  Future<TransportPair> _finish() async {
    final (c1, c2) = await _ss.split();
    return _initiator ? TransportPair(c1, c2) : TransportPair(c2, c1);
  }

  static Uint8List prologue(String baseStr, List<int> extra) {
    final b = ascii.encode(baseStr);
    return Uint8List(b.length + extra.length)
      ..setAll(0, b)
      ..setAll(b.length, extra);
  }
}
