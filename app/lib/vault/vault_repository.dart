import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:path_provider/path_provider.dart';

import '../crypto/vault_crypto.dart';
import '../noise/base64url.dart';
import 'account.dart';

class _Entry {
  Uint8List sealedMeta;
  Uint8List sealedSecret;
  _Entry(this.sealedMeta, this.sealedSecret);
}

/// 保险库：管理加密文件、解锁后在内存持有 DEK，提供账户增删改查。
/// 密码字段只在 [secretBytes] 按需解密为字节返回，绝不缓存明文密码。
class VaultRepository {
  final String? _overrideDir;
  VaultRepository([this._overrideDir]);

  /// 每次成功落盘后回调（供上层做 R2 自动备份等）。绝不传出明文，回调方
  /// 应自行读取加密快照（[exportBytes]）。
  void Function()? onChanged;

  static const int _version = 1;

  Uint8List? _dek; // 内存态；lock() 时清零并置 null
  KdfParams _kdf = const KdfParams();
  Uint8List _salt = Uint8List(0);
  final Map<String, _Entry> _entries = {};
  final Map<String, Account> _accounts = {};

  bool get isUnlocked => _dek != null;

  Future<File> _file() async {
    final dir = _overrideDir ?? (await getApplicationSupportDirectory()).path;
    await Directory(dir).create(recursive: true);
    return File('$dir/vault.json');
  }

  Future<bool> exists() async => (await _file()).exists();

  /// 首次创建保险库（设定主密码）。
  Future<void> create(List<int> masterPasswordBytes) async {
    _kdf = const KdfParams();
    _salt = VaultCrypto.randomBytes(16);
    final kek = await VaultCrypto.deriveKek(masterPasswordBytes, _salt, _kdf);
    final dek = VaultCrypto.randomBytes(32);

    _sealedDek = await VaultCrypto.seal(kek, dek, aad: _dekAad);
    _zero(kek);

    _dek = dek;
    _entries.clear();
    _accounts.clear();
    await _persist();
  }

  Uint8List _sealedDek = Uint8List(0);
  static const List<int> _dekAad = [0x44, 0x45, 0x4b]; // "DEK"

  /// 用主密码解锁。成功返回 true 并载入所有账户元数据；主密码错返回 false。
  Future<bool> unlock(List<int> masterPasswordBytes) async {
    final f = await _file();
    if (!await f.exists()) return false;

    final map = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
    _kdf = KdfParams.fromJson(map['kdf'] as Map<String, dynamic>);
    _salt = Base64Url.decode(map['salt'] as String);
    _sealedDek = Base64Url.decode(map['dek'] as String);

    final kek = await VaultCrypto.deriveKek(masterPasswordBytes, _salt, _kdf);
    Uint8List dek;
    try {
      dek = await VaultCrypto.open(kek, _sealedDek, aad: _dekAad);
    } on SecretBoxAuthenticationError {
      _zero(kek);
      return false; // 主密码错
    } finally {
      _zero(kek);
    }

    _entries.clear();
    _accounts.clear();
    for (final e in (map['entries'] as List<dynamic>? ?? const [])) {
      final m = e as Map<String, dynamic>;
      final id = m['id'] as String;
      final entry = _Entry(
        Base64Url.decode(m['meta'] as String),
        Base64Url.decode(m['secret'] as String),
      );
      _entries[id] = entry;
      final metaBytes = await VaultCrypto.open(dek, entry.sealedMeta);
      _accounts[id] = Account.fromMeta(id, metaBytes);
    }

    _dek = dek;
    return true;
  }

  void lock() {
    final d = _dek;
    if (d != null) _zero(d);
    _dek = null;
    _accounts.clear();
    _entries.clear();
  }

  /// 校验主密码是否正确，但**不改变解锁态**（用于「查看密码」前的二次确认）。
  /// 复用解锁态已缓存的 kdf/salt/sealedDek，重新派生 KEK 尝试解封 DEK。
  Future<bool> verifyMasterPassword(List<int> pwBytes) async {
    if (_sealedDek.isEmpty) return false;
    final kek = await VaultCrypto.deriveKek(pwBytes, _salt, _kdf);
    try {
      final dek = await VaultCrypto.open(kek, _sealedDek, aad: _dekAad);
      _zero(dek);
      return true;
    } on SecretBoxAuthenticationError {
      return false;
    } finally {
      _zero(kek);
    }
  }

  /// 导出整库加密快照（`vault.json` 原始字节，纯密文；R2 上/备份文件里都无
  /// 主密码不可解）。用于加密备份导出与 R2 自动备份。
  Future<Uint8List> exportBytes() async {
    final f = await _file();
    if (!await f.exists()) throw StateError('保险库不存在');
    return f.readAsBytes();
  }

  /// 从加密备份恢复（**覆盖当前库**）。需提供该备份对应的主密码：先只用头部
  /// 的 kdf/salt/sealedDek 验证主密码能解开，再覆写落盘并重新解锁载入。
  /// 主密码错或文件损坏返回 false，且不改动当前库。
  Future<bool> importFrom(Uint8List backup, List<int> pwBytes) async {
    final KdfParams kdf;
    final Uint8List salt;
    final Uint8List sealedDek;
    try {
      final map = jsonDecode(utf8.decode(backup)) as Map<String, dynamic>;
      kdf = KdfParams.fromJson(map['kdf'] as Map<String, dynamic>);
      salt = Base64Url.decode(map['salt'] as String);
      sealedDek = Base64Url.decode(map['dek'] as String);
    } catch (_) {
      return false; // 非法/损坏文件
    }

    final kek = await VaultCrypto.deriveKek(pwBytes, salt, kdf);
    try {
      final dek = await VaultCrypto.open(kek, sealedDek, aad: _dekAad);
      _zero(dek);
    } on SecretBoxAuthenticationError {
      return false; // 主密码错，不动当前库
    } finally {
      _zero(kek);
    }

    // 校验通过：覆盖落盘并重新解锁载入（unlock 不走 _persist，故不会触发回传）。
    final f = await _file();
    await f.writeAsBytes(backup, flush: true);
    return unlock(pwBytes);
  }

  List<Account> accounts() {
    final list = _accounts.values.toList();
    list.sort((a, b) {
      final t = a.title.toLowerCase().compareTo(b.title.toLowerCase());
      return t != 0 ? t : b.updatedAt.compareTo(a.updatedAt);
    });
    return list;
  }

  Account? account(String id) => _accounts[id];

  /// 按需解密某账户的密码，返回原始 UTF-8 字节。调用方用完必须清零。
  Future<Uint8List> secretBytes(String id) async {
    _requireUnlocked();
    final entry = _entries[id];
    if (entry == null) throw StateError('账户不存在: $id');
    return VaultCrypto.open(_dek!, entry.sealedSecret);
  }

  /// 账户的用户名（账号）作为可注入字节。
  List<int> usernameBytes(String id) {
    final acc = _accounts[id];
    if (acc == null) throw StateError('账户不存在: $id');
    return utf8.encode(acc.username);
  }

  Future<void> markUsed(String id) async {
    _requireUnlocked();
    final acc = _accounts[id];
    final entry = _entries[id];
    if (acc == null || entry == null) return;
    acc.lastUsedAt = DateTime.now().millisecondsSinceEpoch;
    final sealedMeta = await VaultCrypto.seal(_dek!, acc.metaBytes());
    _entries[id] = _Entry(sealedMeta, entry.sealedSecret);
    await _persist();
  }

  Future<void> recordFill(
      {required String accountId,
      required bool password,
      required String contextKey}) async {
    _requireUnlocked();
    final acc = _accounts[accountId];
    final entry = _entries[accountId];
    if (acc == null || entry == null) return;
    final map = password ? acc.passwordUseCounts : acc.usernameUseCounts;
    map[contextKey] = (map[contextKey] ?? 0) + 1;
    acc.lastUsedAt = DateTime.now().millisecondsSinceEpoch;
    _entries[accountId] = _Entry(
        await VaultCrypto.seal(_dek!, acc.metaBytes()), entry.sealedSecret);
    await _persist();
  }

  /// 新增或更新。[passwordBytes] 为原始密码字节；传 null 表示保留原密码（仅改元数据）。
  /// 调用方在返回后应清零传入的 passwordBytes。
  Future<Account> upsert({
    String? id,
    required String title,
    required String username,
    String website = '',
    String note = '',
    List<int>? passwordBytes,
  }) async {
    _requireUnlocked();
    final now = DateTime.now().millisecondsSinceEpoch;
    final entryId = id ?? _newId();

    final acc = Account(
      id: entryId,
      title: title,
      username: username,
      website: Account.normalizeWebsite(website),
      note: note,
      updatedAt: now,
      lastUsedAt: _accounts[entryId]?.lastUsedAt ?? 0,
    );

    final sealedMeta = await VaultCrypto.seal(_dek!, acc.metaBytes());

    final existing = _entries[entryId];
    Uint8List sealedSecret;
    if (passwordBytes != null) {
      sealedSecret = await VaultCrypto.seal(_dek!, passwordBytes);
    } else if (existing != null) {
      sealedSecret = existing.sealedSecret;
    } else {
      sealedSecret = await VaultCrypto.seal(_dek!, const <int>[]); // 空密码
    }

    _entries[entryId] = _Entry(sealedMeta, sealedSecret);
    _accounts[entryId] = acc;
    await _persist();
    return acc;
  }

  Future<void> delete(String id) async {
    _requireUnlocked();
    _entries.remove(id);
    _accounts.remove(id);
    await _persist();
  }

  Future<void> _persist() async {
    final f = await _file();
    final entriesJson = _entries.entries
        .map((e) => {
              'id': e.key,
              'meta': Base64Url.encode(e.value.sealedMeta),
              'secret': Base64Url.encode(e.value.sealedSecret),
            })
        .toList();

    await f.writeAsString(jsonEncode({
      'v': _version,
      'kdf': _kdf.toJson(),
      'salt': Base64Url.encode(_salt),
      'dek': Base64Url.encode(_sealedDek),
      'entries': entriesJson,
    }));
    onChanged?.call();
  }

  void _requireUnlocked() {
    if (_dek == null) throw StateError('保险库未解锁');
  }

  static String _newId() {
    final b = VaultCrypto.randomBytes(16);
    return b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  }

  static void _zero(Uint8List b) {
    for (var i = 0; i < b.length; i++) {
      b[i] = 0;
    }
  }
}
