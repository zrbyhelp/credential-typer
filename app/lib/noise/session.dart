import 'dart:convert';
import 'dart:typed_data';

import 'byte_channel.dart';
import 'cipher_state.dart';
import 'frame.dart';

/// 握手完成后的加密会话：分帧 + Noise CipherState 加解密。
/// 明文帧格式见 PROTOCOL.md §5：首字节 tag，其后 body。对应桌面 `Session.cs`。
class Session {
  /// 会话密文帧上限（PROTOCOL.md §4）。
  static const int maxCiphertextLen = 16384;

  // 明文帧 tag
  static const int tagCtx = 0x01; // 桌面→手机，body = UTF-8 JSON
  static const int tagPing = 0x02; // 手机→桌面，body 空
  static const int tagPong = 0x03; // 桌面→手机，body 空
  static const int tagFill = 0x04; // 手机→桌面，body = [flags][UTF-8 明文…]，敏感
  static const int tagAccountImport = 0x05; // 桌面→手机，二进制账号导入
  static const int tagFilterSync = 0x06; // 桌面→手机，搜索同步

  final ByteChannel _ch;
  final CipherState _send;
  final CipherState _recv;

  // 简单发送串行化：同一时刻只加密/发送一帧，保证 nonce 单调。
  Future<void> _sendChain = Future<void>.value();

  Session(this._ch, this._send, this._recv);

  /// 发送一帧（含 tag，串行化，避免并发导致 nonce 乱序）。
  /// 若调用方持有敏感明文，发送后自行清零。
  Future<void> sendFrame(List<int> plaintextFrame) {
    final prev = _sendChain;
    final done = prev.then((_) async {
      final ct = await _send.encryptWithAd(const <int>[], plaintextFrame);
      await Frame.write(_ch, ct);
    });
    _sendChain = done.catchError((_) {});
    return done;
  }

  /// 收一帧并解密。返回明文帧（首字节 tag）可能含敏感数据。
  Future<Uint8List> receive() async {
    final cipher = await Frame.read(_ch, limit: maxCiphertextLen);
    return _recv.decryptWithAd(const <int>[], cipher);
  }

  // —— 便捷封装 ——

  Future<void> sendPing() => sendFrame(const [tagPing]);

  /// 发送 fill：body = [flags][UTF-8 明文字节]。enter 置位则注入后补回车。
  /// [secretBytes] 为敏感数据，调用方在返回后应清零。
  Future<void> sendFill(List<int> secretBytes, {required bool enter}) {
    final frame = Uint8List(2 + secretBytes.length);
    frame[0] = tagFill;
    frame[1] = enter ? 0x01 : 0x00;
    frame.setAll(2, secretBytes);
    // 帧内含明文副本；发送后由调用者清零 secretBytes，这里也在链尾清零 frame。
    return sendFrame(frame).whenComplete(() {
      for (var i = 0; i < frame.length; i++) {
        frame[i] = 0;
      }
    });
  }

  static String ctxJson(Uint8List frameBody) => utf8.decode(frameBody);

  Future<void> close() => _ch.close();
}
