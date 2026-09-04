import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../noise/byte_channel.dart';
import '../noise/dh.dart';
import '../noise/handshake.dart';
import '../noise/protocol.dart';
import '../noise/qr_payload.dart';
import '../noise/session.dart';

/// TCP 连接 + Noise 握手的发起端。手机作 initiator。
class TcpClient {
  /// 依次尝试 [hosts]，只有在 TCP 连接和 [handshake] 都成功后才返回。
  ///
  /// 旧实现只把 TCP connect 成功当作“地址可用”。当二维码里包含多个
  /// 网卡地址（例如 WSL/虚拟网卡）时，首个地址可能连到了错误的服务，
  /// 对端随即关闭连接，手机就会在握手读第二帧时得到 EndOfStream，且不会
  /// 再尝试二维码中的下一个地址。这里把完整握手纳入每个候选地址的重试
  /// 范围，并在失败后及时销毁 socket，避免半开的连接干扰下一次尝试。
  static Future<T> _connectAny<T>(
    List<String> hosts,
    int port,
    Future<T> Function(ByteChannel channel) handshake, {
    Duration perHostTimeout = const Duration(milliseconds: 1500),
    Duration handshakeTimeout = const Duration(seconds: 3),
    void Function(String)? onLog,
  }) async {
    Object? lastError;
    final candidates = hosts
        .map((host) => host.trim())
        .where((host) => host.isNotEmpty)
        .toSet()
        .toList();
    onLog?.call('候选地址：${candidates.join(' / ')}:$port');

    for (final host in candidates) {
      Socket? socket;
      ByteChannel? channel;
      var handedOff = false;
      try {
        onLog?.call('→ 连接 $host:$port …');
        socket = await Socket.connect(host, port, timeout: perHostTimeout);
        socket.setOption(SocketOption.tcpNoDelay, true);
        channel = _wrap(socket);
        onLog?.call('  TCP 已连上 $host，开始握手');

        // Session 接管 channel 后由 Session.close() 负责其生命周期；失败
        // 时则在 finally 中关闭，保证下一候选地址不会和旧连接重叠。
        // A wrong service may accept TCP and then never speak Noise. Bound
        // that wait as well as the TCP connect so the next QR address gets a
        // chance instead of leaving the scanner stuck forever.
        final result = await handshake(channel).timeout(handshakeTimeout);
        handedOff = true;
        onLog?.call('  握手成功（$host）');
        return result;
      } catch (e) {
        lastError = e;
        onLog?.call('  ✗ $host 失败：${_short(e)}');
      } finally {
        if (!handedOff) {
          try {
            // The handshake failed, so no Session owns this channel. A hard
            // destroy is intentional here: waiting for a graceful close can
            // itself hang when the peer is the wrong/stale service.
            socket?.destroy();
          } catch (_) {
            socket?.destroy();
          }
        }
      }
    }

    if (candidates.isEmpty) {
      throw const SocketException('二维码未提供可用的桌面地址');
    }
    throw SocketException('无法连接任一地址 $candidates:$port（最后错误：$lastError）');
  }

  static String _short(Object e) {
    final s = e.toString();
    return s.length > 120 ? '${s.substring(0, 120)}…' : s;
  }

  static ByteChannel _wrap(Socket socket) {
    return ByteChannel(
      input: socket,
      sink: socket.add,
      flush: socket.flush,
      close: () async {
        try {
          await socket.close();
        } catch (_) {}
        socket.destroy();
      },
    );
  }

  /// 配对：连桌面（二维码里的 host/port），发前导 0x01，跑 IK 握手。
  static Future<Session> pair(DhKeyPair phoneStatic, QrPayload qr,
      {void Function(String)? onLog}) async {
    return _connectAny(qr.host, qr.port, (ch) async {
      onLog?.call('  发送配对前导(0x01)');
      await ch.write([Protocol.modePair]);
      onLog?.call('  运行 IK 握手（写 msg1，等 msg2）…');
      return Handshake.initiatorPair(
        ch,
        phoneStatic,
        qr.sPubBytes,
        qr.codeBytes,
      );
    }, onLog: onLog);
  }

  /// 重连：连上次的 host/port，发前导 0x02，跑 KK 握手（双方静态已知）。
  static Future<Session> reconnect(
    DhKeyPair phoneStatic,
    Uint8List desktopPublic,
    List<String> hosts,
    int port,
  ) async {
    return _connectAny(hosts, port, (ch) async {
      await ch.write([Protocol.modeReconnect]);
      return Handshake.initiatorReconnect(ch, phoneStatic, desktopPublic);
    });
  }
}
