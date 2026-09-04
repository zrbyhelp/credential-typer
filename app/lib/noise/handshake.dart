import 'dart:typed_data';

import 'byte_channel.dart';
import 'dh.dart';
import 'frame.dart';
import 'handshake_state.dart';
import 'protocol.dart';
import 'session.dart';

/// 把 HandshakeState 跑在一条 ByteChannel 上，握手成功后产出 Session。
/// 手机是发起方（initiator）。对应桌面 `Handshake.cs` 的 Initiator* 方法。
class Handshake {
  /// 配对：手机作 IK 发起方。已从二维码知道桌面静态公钥 [remoteStatic]。
  static Future<Session> initiatorPair(
    ByteChannel ch,
    DhKeyPair localStatic,
    Uint8List remoteStatic,
    Uint8List pairingCode,
  ) async {
    final hs = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: true,
      prologue: Protocol.pairingPrologue(pairingCode),
      localStatic: localStatic,
      remoteStatic: remoteStatic,
    );

    final (msg1, _) = await hs.writeMessage(const <int>[]);
    await Frame.write(ch, msg1);

    final msg2 = await Frame.read(ch);
    final (_, transport) = await hs.readMessage(msg2);

    final t = transport!;
    return Session(ch, t.send, t.recv);
  }

  /// 重连：手机作 KK 发起方，双方静态公钥都已知。
  static Future<Session> initiatorReconnect(
    ByteChannel ch,
    DhKeyPair localStatic,
    Uint8List remoteStatic,
  ) async {
    final hs = await HandshakeState.create(
      pattern: NoisePattern.kk,
      initiator: true,
      prologue: Protocol.reconnectPrologue(),
      localStatic: localStatic,
      remoteStatic: remoteStatic,
    );

    final (msg1, _) = await hs.writeMessage(const <int>[]);
    await Frame.write(ch, msg1);

    final msg2 = await Frame.read(ch);
    final (_, transport) = await hs.readMessage(msg2);

    final t = transport!;
    return Session(ch, t.send, t.recv);
  }
}
