import 'dart:typed_data';

import 'byte_channel.dart';

/// 2 字节大端长度前缀分帧。握手消息（裸）与会话消息（Noise 密文）都用这个包。
/// 对应桌面 `Frame.cs`。
class Frame {
  /// 单帧上限（2 字节自然上限）。
  static const int maxLen = 65535;

  static Future<void> write(ByteChannel ch, List<int> payload) async {
    if (payload.length > maxLen) {
      throw StateError('帧长 ${payload.length} 超过上限 $maxLen');
    }
    final header = Uint8List(2);
    ByteData.sublistView(header).setUint16(0, payload.length, Endian.big);
    // 一次性写出，减少 TCP 小包
    final out = Uint8List(2 + payload.length)
      ..setAll(0, header)
      ..setAll(2, payload);
    await ch.write(out);
  }

  static Future<Uint8List> read(ByteChannel ch, {int limit = maxLen}) async {
    final header = await ch.readExact(2);
    final len = ByteData.sublistView(header).getUint16(0, Endian.big);
    if (len > limit) {
      throw StateError('帧长 $len 超过上限 $limit，按异常断开处理');
    }
    return ch.readExact(len);
  }
}
