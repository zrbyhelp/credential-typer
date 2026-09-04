import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:path_provider/path_provider.dart';

import '../noise/base64url.dart';

/// 已配对桌面的记录：桌面静态公钥（公钥不敏感，明文存）+ 上次的 host/port。
/// 对应桌面 `PairingStore`（桌面存手机公钥；这里手机存桌面公钥）。
class PairingRecord {
  final Uint8List desktopPublic;
  final List<String> hosts;
  final int port;

  const PairingRecord(this.desktopPublic, this.hosts, this.port);
}

class PairingStore {
  final String? _overrideDir;
  PairingStore([this._overrideDir]);

  Future<File> _file() async {
    final dir = _overrideDir ?? (await getApplicationSupportDirectory()).path;
    await Directory(dir).create(recursive: true);
    return File('$dir/pairing.json');
  }

  Future<bool> get hasPaired async => (await load()) != null;

  Future<PairingRecord?> load() async {
    final f = await _file();
    if (!await f.exists()) return null;
    try {
      final map = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
      return PairingRecord(
        Base64Url.decode(map['dpub'] as String),
        (map['host'] as List<dynamic>).map((e) => e.toString()).toList(),
        (map['port'] as num).toInt(),
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> save(PairingRecord record) async {
    final f = await _file();
    await f.writeAsString(jsonEncode({
      'dpub': Base64Url.encode(record.desktopPublic),
      'host': record.hosts,
      'port': record.port,
    }));
  }

  Future<void> clear() async {
    final f = await _file();
    if (await f.exists()) await f.delete();
  }
}
