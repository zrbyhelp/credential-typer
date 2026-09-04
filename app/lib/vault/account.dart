import 'dart:convert';

/// 账户的可显示元数据（非密码部分）。密码单独作为敏感字节封装，不进本类。
class Account {
  final String id;
  String title;
  String username;
  String website;
  String note;
  int updatedAt;
  int lastUsedAt; // 最近一次注入使用的时间戳（毫秒），用于「最近使用」排序
  Map<String, int> usernameUseCounts;
  Map<String, int> passwordUseCounts;

  Account({
    required this.id,
    required this.title,
    required this.username,
    this.website = '',
    this.note = '',
    required this.updatedAt,
    this.lastUsedAt = 0,
    Map<String, int>? usernameUseCounts,
    Map<String, int>? passwordUseCounts,
  })  : usernameUseCounts = usernameUseCounts ?? <String, int>{},
        passwordUseCounts = passwordUseCounts ?? <String, int>{};

  /// 元数据 JSON（供 DEK 封装落盘）。不含密码。
  Map<String, dynamic> toMetaJson() => {
        'title': title,
        'username': username,
        'website': website,
        'note': note,
        'updatedAt': updatedAt,
        'lastUsedAt': lastUsedAt,
        'usernameUseCounts': usernameUseCounts,
        'passwordUseCounts': passwordUseCounts,
      };

  List<int> metaBytes() => utf8.encode(jsonEncode(toMetaJson()));

  static Account fromMeta(String id, List<int> metaBytes) {
    final m = jsonDecode(utf8.decode(metaBytes)) as Map<String, dynamic>;
    return Account(
      id: id,
      title: m['title'] as String? ?? '',
      username: m['username'] as String? ?? '',
      website: normalizeWebsite(m['website'] as String? ?? ''),
      note: m['note'] as String? ?? '',
      updatedAt: (m['updatedAt'] as num?)?.toInt() ?? 0,
      lastUsedAt: (m['lastUsedAt'] as num?)?.toInt() ?? 0,
      usernameUseCounts: _counts(m['usernameUseCounts']),
      passwordUseCounts: _counts(m['passwordUseCounts']),
    );
  }

  static Map<String, int> _counts(dynamic value) {
    if (value is! Map) return <String, int>{};
    return value
        .map((k, v) => MapEntry(k.toString(), (v as num?)?.toInt() ?? 0));
  }

  /// Keeps only a host/domain for stable matching and search.
  static String normalizeWebsite(String input) {
    var value = input.trim().toLowerCase();
    if (value.isEmpty) return '';
    value = value.replaceFirst(RegExp(r'^[a-z][a-z0-9+.-]*://'), '');
    value = value.split(RegExp(r'[/?#\s]')).first;
    value = value.replaceFirst(RegExp(r'^www\.'), '');
    value = value.replaceFirst(RegExp(r':\d+$'), '');
    value = value.replaceAll(RegExp(r'[^a-z0-9._-]'), '');
    return value;
  }
}
