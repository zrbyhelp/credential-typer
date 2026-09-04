import 'dart:convert';
import 'dart:typed_data';

class AccountImportPayload {
  final String title;
  final String username;
  final String website;
  final String note;
  final Uint8List passwordBytes;

  AccountImportPayload(
      {required this.title,
      required this.username,
      required this.website,
      required this.note,
      required this.passwordBytes});

  static const int tag = 0x05;
  static const int version = 0x02;

  static Uint8List encode(
      {required String title,
      required String username,
      required String website,
      required String note,
      required List<int> passwordBytes}) {
    final parts = [
      utf8.encode(title),
      utf8.encode(username),
      utf8.encode(website),
      utf8.encode(note),
      passwordBytes
    ];
    if (parts.any((x) => x.length > 0xffff)) throw ArgumentError('字段过长');
    final total = 12 + parts.fold<int>(0, (a, b) => a + b.length);
    if (total > 16384) throw ArgumentError('账号数据过大');
    final out = Uint8List(total)
      ..[0] = tag
      ..[1] = version;
    var p = 2;
    for (final part in parts) {
      out[p++] = part.length >> 8;
      out[p++] = part.length & 0xff;
    }
    for (final part in parts) {
      out.setRange(p, p + part.length, part);
      p += part.length;
    }
    return out;
  }

  static AccountImportPayload decode(Uint8List frame) {
    if (frame.length < 12 ||
        frame.length > 16384 ||
        frame[0] != tag ||
        frame[1] != version) throw const FormatException('无效的账号导入帧');
    final lengths = <int>[];
    var p = 2;
    for (var i = 0; i < 5; i++) {
      lengths.add((frame[p] << 8) | frame[p + 1]);
      p += 2;
    }
    if (12 + lengths.fold<int>(0, (a, b) => a + b) != frame.length)
      throw const FormatException('账号导入帧长度不匹配');
    List<int> take(int len) {
      final v = frame.sublist(p, p + len);
      p += len;
      return v;
    }

    return AccountImportPayload(
      title: utf8.decode(take(lengths[0]), allowMalformed: false),
      username: utf8.decode(take(lengths[1]), allowMalformed: false),
      website: utf8.decode(take(lengths[2]), allowMalformed: false),
      note: utf8.decode(take(lengths[3]), allowMalformed: false),
      passwordBytes: Uint8List.fromList(take(lengths[4])),
    );
  }
}
