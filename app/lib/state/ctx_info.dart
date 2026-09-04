import 'dart:convert';

/// 桌面上报的焦点上下文（tag 0x01 的 JSON body），仅用于排序提示，非敏感。
/// 形如 {"app":"chrome.exe","title":"登录","field":{"kind":"password","name":"密码"}}
class CtxInfo {
  final String app;
  final String title;
  final String fieldKind; // password | text | other | none
  final String fieldName;

  const CtxInfo({
    required this.app,
    required this.title,
    required this.fieldKind,
    required this.fieldName,
  });

  static CtxInfo? parse(String json) {
    try {
      final m = jsonDecode(json) as Map<String, dynamic>;
      final field = m['field'] as Map<String, dynamic>?;
      return CtxInfo(
        app: m['app'] as String? ?? '',
        title: m['title'] as String? ?? '',
        fieldKind: field?['kind'] as String? ?? 'none',
        fieldName: field?['name'] as String? ?? '',
      );
    } catch (_) {
      return null;
    }
  }

  bool get isPasswordField => fieldKind == 'password';
  bool get hasField => fieldKind != 'none';
}
