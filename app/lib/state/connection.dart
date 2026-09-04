import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';

import '../noise/protocol.dart';
import '../noise/qr_payload.dart';
import '../noise/session.dart';
import '../transport/identity_store.dart';
import '../transport/pairing_store.dart';
import '../transport/tcp_client.dart';
import '../transport/account_import.dart';
import '../transport/filter_sync.dart';
import 'ctx_info.dart';

enum ConnStatus { idle, connecting, connected, error }

class PairResult {
  final String desktopFingerprint; // 应与 PC 屏幕显示一致
  final String phoneFingerprint; // 在 PC 上核对后点接受
  const PairResult(this.desktopFingerprint, this.phoneFingerprint);
}

/// 管理与桌面的一条加密会话：连接、收 ctx、发 fill、心跳、断线自动重连。
class ConnectionManager extends ChangeNotifier {
  final IdentityStore identity;
  final PairingStore pairing;

  ConnectionManager(this.identity, this.pairing);

  ConnStatus status = ConnStatus.idle;
  String? lastError;
  CtxInfo? ctx;
  // 最近一次配对的实时日志：逐地址、逐阶段记录，失败时展示给用户排障。
  final List<String> pairLog = [];
  Future<void> Function(AccountImportPayload payload)? onAccountImport;
  void Function(String query)? onFilterSync;

  Session? _session;
  bool _wantConnected = false;
  Timer? _pingTimer;
  Timer? _reconnectTimer;
  int _reconnectAttempts = 0;
  // Invalidates an in-flight reconnect when the user starts a new pairing,
  // disconnects, or locks the vault.  Dart sockets cannot be force-cancelled
  // portably, so stale results are closed and ignored when they complete.
  int _connectionGeneration = 0;

  bool get isConnected => status == ConnStatus.connected;

  void _set(ConnStatus s, {String? error}) {
    status = s;
    lastError = error;
    notifyListeners();
  }

  /// 若已配对则尝试重连（KK）。UI 进入账户页时调用。
  Future<void> ensureConnected() async {
    if (status == ConnStatus.connecting || status == ConnStatus.connected) {
      return;
    }
    final generation = ++_connectionGeneration;
    final record = await pairing.load();
    if (generation != _connectionGeneration) return;
    if (record == null) {
      _set(ConnStatus.idle);
      return;
    }
    _wantConnected = true;
    _reconnectAttempts = 0;
    await _reconnect(record, generation);
  }

  Future<void> _reconnect(PairingRecord record,
      [int? expectedGeneration]) async {
    final generation = expectedGeneration ?? _connectionGeneration;
    if (generation != _connectionGeneration || !_wantConnected) return;
    _set(ConnStatus.connecting);
    try {
      final phone = await identity.loadOrCreate();
      final session = await TcpClient.reconnect(
        phone,
        record.desktopPublic,
        record.hosts,
        record.port,
      );

      // A manual pairing or disconnect may have superseded this attempt
      // while the TCP/Noise handshake was in flight.  Never let the old PC
      // steal the active session after the user selected a new one.
      if (generation != _connectionGeneration || !_wantConnected) {
        await session.close();
        return;
      }
      _onSessionUp(session);
    } catch (_) {
      if (generation != _connectionGeneration || !_wantConnected) return;
      _reconnectAttempts++;
      _set(ConnStatus.error, error: '重连失败');
      if (_reconnectAttempts < 3)
        _scheduleReconnect(generation);
      else
        _wantConnected = false;
    }
  }

  /// 扫码配对（IK）。成功后返回两端指纹供用户目视核对，并持久化配对记录。
  Future<PairResult> pair(QrPayload qr) async {
    // A new QR pairing replaces any previous computer connection.
    _connectionGeneration++;
    final generation = _connectionGeneration;
    _wantConnected = false;
    _reconnectTimer?.cancel();
    _teardown();
    pairLog.clear();
    void log(String m) {
      pairLog.add(m);
      notifyListeners();
    }

    log('开始配对：${qr.host.join(' / ')}:${qr.port}');
    _set(ConnStatus.connecting);
    try {
      final phone = await identity.loadOrCreate();
      final session = await TcpClient.pair(phone, qr, onLog: log);
      log('配对完成，等待桌面确认指纹');

      // Another pairing may have been started while the socket handshake was
      // in flight.  Do not persist or expose a stale session in that case.
      if (generation != _connectionGeneration) {
        await session.close();
        throw StateError('配对请求已被新的连接替换');
      }

      await pairing.save(PairingRecord(qr.sPubBytes, qr.host, qr.port));
      if (generation != _connectionGeneration) {
        await session.close();
        throw StateError('配对请求已被新的连接替换');
      }
      _wantConnected = true;
      _onSessionUp(session);

      final desktopFp = await Protocol.fingerprint(qr.sPubBytes);
      final phoneFp = await Protocol.fingerprint(phone.publicKey);
      return PairResult(desktopFp, phoneFp);
    } catch (e) {
      log('配对失败：${e.toString()}');
      final message = e.toString().contains('EndOfStream')
          ? '电脑未开启配对，请在电脑端刷新二维码后重试'
          : '配对失败: $e';
      if (generation == _connectionGeneration) {
        _teardown();
        _set(ConnStatus.error, error: message);
      }
      rethrow;
    }
  }

  void _onSessionUp(Session session) {
    _reconnectAttempts = 0;
    _session = session;
    ctx = null;
    _set(ConnStatus.connected);
    _startPing();
    unawaited(_receiveLoop(session));
  }

  Future<void> _receiveLoop(Session session) async {
    try {
      while (identical(_session, session)) {
        final frame = await session.receive();
        if (frame.isEmpty) continue;
        switch (frame[0]) {
          case Session.tagCtx:
            final body = Uint8List.sublistView(frame, 1);
            ctx = CtxInfo.parse(Session.ctxJson(body));
            notifyListeners();
            break;
          case Session.tagPong:
            break;
          case Session.tagAccountImport:
            try {
              final payload = AccountImportPayload.decode(frame);
              try {
                final handler = onAccountImport;
                if (handler != null) await handler(payload);
              } finally {
                for (var i = 0; i < payload.passwordBytes.length; i++) {
                  payload.passwordBytes[i] = 0;
                }
              }
            } finally {
              frame.fillRange(0, frame.length, 0);
            }
            break;
          case Session.tagFilterSync:
            final query = FilterSyncFrame.decode(frame);
            onFilterSync?.call(query);
            frame.fillRange(0, frame.length, 0);
            break;
          default:
            break;
        }
      }
    } catch (e) {
      if (identical(_session, session)) {
        final generation = _connectionGeneration;
        _teardown();
        _reconnectAttempts++;
        _set(ConnStatus.error, error: '重连失败');
        if (_reconnectAttempts < 3) {
          _scheduleReconnect(generation);
        } else {
          _wantConnected = false;
        }
      }
    }
  }

  void _startPing() {
    _pingTimer?.cancel();
    _pingTimer = Timer.periodic(const Duration(seconds: 15), (_) async {
      final s = _session;
      if (s == null) return;
      try {
        await s.sendPing();
      } catch (_) {/* 收发循环会处理断线 */}
    });
  }

  void _scheduleReconnect([int? expectedGeneration]) {
    final generation = expectedGeneration ?? _connectionGeneration;
    if (!_wantConnected || generation != _connectionGeneration) return;
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(const Duration(seconds: 3), () async {
      if (!_wantConnected || generation != _connectionGeneration) return;
      final record = await pairing.load();
      if (record != null &&
          _wantConnected &&
          generation == _connectionGeneration) {
        await _reconnect(record, generation);
      }
    });
  }

  /// 发送一条 fill。[secretBytes] 敏感，本方法在发送后清零它。
  Future<void> sendFill(Uint8List secretBytes, {required bool enter}) async {
    final s = _session;
    if (s == null) throw StateError('未连接');
    try {
      await s.sendFill(secretBytes, enter: enter);
    } finally {
      for (var i = 0; i < secretBytes.length; i++) {
        secretBytes[i] = 0;
      }
    }
  }

  void disconnect() {
    _connectionGeneration++;
    _wantConnected = false;
    _teardown();
    _set(ConnStatus.idle);
  }

  void _teardown() {
    _pingTimer?.cancel();
    _reconnectTimer?.cancel();
    final s = _session;
    _session = null;
    ctx = null;
    if (s != null) unawaited(s.close());
  }

  @override
  void dispose() {
    _connectionGeneration++;
    _wantConnected = false;
    _teardown();
    super.dispose();
  }
}
