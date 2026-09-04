import 'dart:convert';
import 'dart:typed_data';

class FilterSyncFrame {
  static const int tag = 0x06;
  static const int version = 0x01;

  static Uint8List encode(String query) {
    final body = utf8.encode(query);
    if (body.length > 0xffff || body.length + 4 > 16384) {
      throw ArgumentError('筛选内容过长');
    }
    final out = Uint8List(body.length + 4);
    out[0] = tag;
    out[1] = version;
    out[2] = body.length >> 8;
    out[3] = body.length & 0xff;
    out.setRange(4, out.length, body);
    return out;
  }

  static String decode(Uint8List frame) {
    if (frame.length < 4 || frame[0] != tag || frame[1] != version) {
      throw const FormatException('无效的筛选同步帧');
    }
    final len = (frame[2] << 8) | frame[3];
    if (len + 4 != frame.length) throw const FormatException('筛选同步帧长度不匹配');
    return utf8.decode(frame.sublist(4), allowMalformed: false);
  }
}
