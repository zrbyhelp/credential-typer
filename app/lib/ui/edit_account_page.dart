import 'dart:convert';

import 'package:flutter/material.dart';

import '../state/app_state.dart';
import '../vault/account.dart';

/// 新增 / 编辑账户。编辑时密码留空表示不改动。
class EditAccountPage extends StatefulWidget {
  final Account? existing;
  const EditAccountPage({super.key, this.existing});

  @override
  State<EditAccountPage> createState() => _EditAccountPageState();
}

class _EditAccountPageState extends State<EditAccountPage> {
  late final TextEditingController _title;
  late final TextEditingController _username;
  late final TextEditingController _website;
  late final TextEditingController _password;
  late final TextEditingController _note;
  bool _obscure = true;
  bool _busy = false;
  String? _error;
  final List<String> _passwordOptions = [];

  bool get _isEdit => widget.existing != null;

  @override
  void initState() {
    super.initState();
    final e = widget.existing;
    _title = TextEditingController(text: e?.title ?? '');
    _username = TextEditingController(text: e?.username ?? '');
    _website = TextEditingController(text: e?.website ?? '');
    _password = TextEditingController();
    _note = TextEditingController(text: e?.note ?? '');
    WidgetsBinding.instance.addPostFrameCallback((_) => _loadPasswordOptions());
  }

  Future<void> _loadPasswordOptions() async {
    if (!mounted) return;
    final app = AppScope.of(context);
    final values = <String>{};
    for (final account
        in app.vault.accounts().where((a) => a.id != widget.existing?.id)) {
      final bytes = await app.vault.secretBytes(account.id);
      try {
        values.add(utf8.decode(bytes));
      } finally {
        bytes.fillRange(0, bytes.length, 0);
      }
    }
    if (mounted)
      setState(() {
        _passwordOptions
          ..clear()
          ..addAll(values);
      });
  }

  @override
  void dispose() {
    _title.dispose();
    _username.dispose();
    _website.dispose();
    _password.dispose();
    _note.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (_title.text.trim().isEmpty) {
      setState(() => _error = '请填写名称');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final app = AppScope.of(context);
      List<int>? pwBytes;
      if (_password.text.isNotEmpty) {
        pwBytes = utf8.encode(_password.text);
      } else if (!_isEdit) {
        pwBytes = const <int>[]; // 新建且未填 → 空密码
      } // 编辑且留空 → null，保留原密码

      await app.vault.upsert(
        id: widget.existing?.id,
        title: _title.text.trim(),
        username: _username.text.trim(),
        website: Account.normalizeWebsite(_website.text),
        note: _note.text.trim(),
        passwordBytes: pwBytes,
      );

      // 尽量抹掉输入框里的密码副本。
      _password.text = '';
      if (mounted) Navigator.pop(context);
    } catch (e) {
      setState(() => _error = '保存失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(_isEdit ? '编辑账户' : '新增账户'),
        actions: [
          TextButton(
            onPressed: _busy ? null : _save,
            child: const Text('保存'),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _text(_title, '名称', autofocus: true),
          _usernameField(),
          _passwordField(),
          const SizedBox(height: 12),
          _text(_note, '备注（可选）', maxLines: 3),
          const SizedBox(height: 4),
          _text(_website, '所属网站 / 域名（如 https://example.com/login）'),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(_error!, style: const TextStyle(color: Colors.red)),
          ],
          const SizedBox(height: 24),
          FilledButton(
            onPressed: _busy ? null : _save,
            child: _busy
                ? const SizedBox(
                    height: 20,
                    width: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Text('保存'),
          ),
        ],
      ),
    );
  }

  Widget _text(TextEditingController c, String label,
      {int maxLines = 1, bool autofocus = false}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: TextField(
        controller: c,
        maxLines: maxLines,
        autofocus: autofocus,
        decoration: InputDecoration(
          labelText: label,
          border: const OutlineInputBorder(),
        ),
      ),
    );
  }

  Widget _usernameField() {
    final accounts = AppScope.of(context).vault.accounts();
    final domains = <String>{'gmail.com', 'outlook.com', 'qq.com', '163.com'};
    for (final a in accounts) {
      final at = a.username.lastIndexOf('@');
      if (at > 0 && at < a.username.length - 1)
        domains.add(a.username.substring(at + 1));
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Autocomplete<String>(
        initialValue: TextEditingValue(text: _username.text),
        optionsBuilder: (value) {
          final q = value.text.toLowerCase();
          final options = <String>{
            ...accounts.map((a) => a.username).where((u) => u.isNotEmpty),
          };
          if (q.contains('@')) {
            final prefix = value.text.substring(0, value.text.indexOf('@'));
            options.addAll(domains.map((d) => '$prefix@$d'));
          }
          return options.where((o) => o.toLowerCase().contains(q));
        },
        onSelected: (v) => _username.text = v,
        fieldViewBuilder: (context, controller, focus, onSubmit) {
          controller.addListener(() {
            if (_username.text != controller.text)
              _username.text = controller.text;
          });
          return TextField(
            controller: controller,
            focusNode: focus,
            decoration: const InputDecoration(
                labelText: '账号 / 用户名', border: OutlineInputBorder()),
          );
        },
      ),
    );
  }

  Widget _passwordField() {
    return RawAutocomplete<String>(
      textEditingController: _password,
      optionsBuilder: (value) {
        final q = value.text.toLowerCase();
        return _passwordOptions
            .where((p) => q.isEmpty || p.toLowerCase().contains(q));
      },
      onSelected: (password) => _password.text = password,
      optionsViewBuilder: (context, onSelected, options) => Align(
        alignment: Alignment.topLeft,
        child: Material(
          elevation: 4,
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 220, minWidth: 280),
            child: ListView.builder(
              padding: EdgeInsets.zero,
              shrinkWrap: true,
              itemCount: options.length,
              itemBuilder: (context, index) {
                final password = options.elementAt(index);
                return ListTile(
                  leading: const Icon(Icons.key),
                  title: Text(password),
                  onTap: () => onSelected(password),
                );
              },
            ),
          ),
        ),
      ),
      fieldViewBuilder: (context, controller, focusNode, onFieldSubmitted) =>
          TextField(
        controller: controller,
        focusNode: focusNode,
        obscureText: _obscure,
        decoration: InputDecoration(
          labelText: _isEdit ? '密码（留空则不修改）' : '密码',
          hintText: _passwordOptions.isEmpty ? null : '可直接选择已有密码',
          border: const OutlineInputBorder(),
          suffixIcon: IconButton(
            icon: Icon(_obscure ? Icons.visibility : Icons.visibility_off),
            onPressed: () => setState(() => _obscure = !_obscure),
          ),
        ),
      ),
    );
  }
}
