import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../state/app_state.dart';
import '../state/connection.dart';
import 'edit_account_page.dart';

/// 账户详情：点「账号 / 密码」把对应内容注入到 PC 当前焦点框。
/// 按用户要求，App 不自动区分账号/密码——用户点哪个就发哪个。
class AccountDetailPage extends StatefulWidget {
  final String accountId;
  const AccountDetailPage({super.key, required this.accountId});

  @override
  State<AccountDetailPage> createState() => _AccountDetailPageState();
}

class _AccountDetailPageState extends State<AccountDetailPage> {
  bool _sending = false;

  Future<void> _fillUsername(bool enter) async {
    final app = AppScope.of(context);
    final bytes = Uint8List.fromList(app.vault.usernameBytes(widget.accountId));
    await _send(bytes, enter, '账号');
  }

  Future<void> _fillPassword(bool enter) async {
    final app = AppScope.of(context);
    final bytes = await app.vault.secretBytes(widget.accountId);
    await _send(bytes, enter, '密码');
  }

  Future<void> _send(Uint8List bytes, bool enter, String what) async {
    final app = AppScope.of(context);
    if (!app.connection.isConnected) {
      for (var i = 0; i < bytes.length; i++) {
        bytes[i] = 0;
      }
      _toast('未连接桌面，无法注入');
      return;
    }
    setState(() => _sending = true);
    try {
      await app.connection.sendFill(bytes, enter: enter); // 内部会清零 bytes
      final acc = app.vault.account(widget.accountId);
      final appName = app.connection.ctx?.app.toLowerCase().trim() ?? '';
      await app.vault.recordFill(
          accountId: widget.accountId,
          password: what == '密码',
          contextKey: '$appName|${acc?.website ?? ''}');
      _toast('已发送$what${enter ? '（含回车）' : ''}');
    } catch (e) {
      _toast('注入失败: $e');
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(content: Text(msg)));
  }

  /// 查看密码：输主密码作门槛 → 校验 → 取明文字节 → 显示对话框。
  Future<void> _viewPassword() async {
    final app = AppScope.of(context);
    final ctrl = TextEditingController();
    final pw = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('输入主密码'),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          obscureText: true,
          decoration: const InputDecoration(
            labelText: '主密码',
            hintText: '查看明文密码需再次验证',
          ),
          onSubmitted: (v) => Navigator.pop(ctx, v),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx), child: const Text('取消')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, ctrl.text),
              child: const Text('确定')),
        ],
      ),
    );
    ctrl.dispose();
    if (pw == null || pw.isEmpty) return;

    final pwBytes = utf8.encode(pw); // Uint8List
    final ok = await app.vault.verifyMasterPassword(pwBytes);
    for (var i = 0; i < pwBytes.length; i++) {
      pwBytes[i] = 0;
    }
    if (!mounted) return;
    if (!ok) {
      _toast('主密码错误');
      return;
    }
    final secret = await app.vault.secretBytes(widget.accountId);
    if (!mounted) {
      for (var i = 0; i < secret.length; i++) {
        secret[i] = 0;
      }
      return;
    }
    await showDialog<void>(
      context: context,
      builder: (_) => _PasswordViewDialog(secret: secret),
    );
    // 对话框内已在关闭时清零 secret。
  }

  Future<void> _edit() async {
    final app = AppScope.of(context);
    final acc = app.vault.account(widget.accountId);
    if (acc == null) return;
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => EditAccountPage(existing: acc)),
    );
    if (mounted) setState(() {});
  }

  Future<void> _delete() async {
    final app = AppScope.of(context);
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('删除账户'),
        content: const Text('确定删除该账户？此操作不可撤销。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('删除'),
          ),
        ],
      ),
    );
    if (ok == true) {
      await app.vault.delete(widget.accountId);
      if (mounted) Navigator.pop(context);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final acc = app.vault.account(widget.accountId);
    if (acc == null) {
      return const Scaffold(body: Center(child: Text('账户不存在')));
    }

    return Scaffold(
      appBar: AppBar(
        title: Text(acc.title),
        actions: [
          IconButton(
              icon: const Icon(Icons.visibility_outlined),
              tooltip: '查看密码',
              onPressed: _viewPassword),
          IconButton(icon: const Icon(Icons.edit), onPressed: _edit),
          IconButton(
              icon: const Icon(Icons.delete_outline), onPressed: _delete),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _field('账号', acc.username.isEmpty ? '（空）' : acc.username),
          if (acc.website.isNotEmpty) _field('所属网站', acc.website),
          if (acc.note.isNotEmpty) _field('备注', acc.note),
          const SizedBox(height: 8),
          ListenableBuilder(
            listenable: app.connection,
            builder: (context, _) => _hint(app.connection),
          ),
          const SizedBox(height: 16),
          _fillSection(),
        ],
      ),
    );
  }

  Widget _field(String label, String value) => Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label,
                style: const TextStyle(color: Colors.grey, fontSize: 12)),
            const SizedBox(height: 2),
            SelectableText(value, style: const TextStyle(fontSize: 16)),
          ],
        ),
      );

  Widget _hint(ConnectionManager conn) {
    if (!conn.isConnected) {
      return const Text('· 未连接桌面，注入按钮不可用',
          style: TextStyle(color: Colors.grey));
    }
    final ctx = conn.ctx;
    if (ctx == null || !ctx.hasField) {
      return const Text('· 请先在 PC 上点一下要填的输入框',
          style: TextStyle(color: Colors.orange));
    }
    final target = ctx.isPasswordField ? '密码框' : '输入框';
    return Text(
        '· PC 当前焦点：$target${ctx.fieldName.isEmpty ? '' : '「${ctx.fieldName}」'}',
        style: const TextStyle(color: Colors.green));
  }

  Widget _fillSection() {
    final enabled = !_sending && AppScope.of(context).connection.isConnected;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('注入到 PC 当前焦点框', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 12),
        Row(children: [
          Expanded(
            child: FilledButton.tonalIcon(
              onPressed: enabled ? () => _fillUsername(false) : null,
              icon: const Icon(Icons.person),
              label: const Text('填账号'),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: FilledButton.tonalIcon(
              onPressed: enabled ? () => _fillUsername(true) : null,
              icon: const Icon(Icons.keyboard_return),
              label: const Text('账号+回车'),
            ),
          ),
        ]),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(
            child: FilledButton.icon(
              onPressed: enabled ? () => _fillPassword(false) : null,
              icon: const Icon(Icons.key),
              label: const Text('填密码'),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: FilledButton.icon(
              onPressed: enabled ? () => _fillPassword(true) : null,
              icon: const Icon(Icons.login),
              label: const Text('密码+回车'),
            ),
          ),
        ]),
        if (_sending) ...[
          const SizedBox(height: 16),
          const Center(child: CircularProgressIndicator()),
        ],
      ],
    );
  }
}

/// 明文密码查看对话框：默认打码，眼睛切换，复制后 30 秒自动清空剪贴板。
/// 持有的密码字节在对话框销毁时清零（Dart String 不可清零，是查看功能的固有取舍）。
class _PasswordViewDialog extends StatefulWidget {
  final Uint8List secret;
  const _PasswordViewDialog({required this.secret});

  @override
  State<_PasswordViewDialog> createState() => _PasswordViewDialogState();
}

class _PasswordViewDialogState extends State<_PasswordViewDialog> {
  bool _reveal = false;
  Timer? _clearTimer;

  String get _plain => utf8.decode(widget.secret, allowMalformed: true);

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: _plain));
    _clearTimer?.cancel();
    _clearTimer = Timer(const Duration(seconds: 30), () {
      Clipboard.setData(const ClipboardData(text: ''));
    });
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(
          const SnackBar(content: Text('已复制，30 秒后自动清除剪贴板')));
  }

  @override
  void dispose() {
    // 注意：不取消 _clearTimer——即便对话框关闭也要按时清空剪贴板。
    for (var i = 0; i < widget.secret.length; i++) {
      widget.secret[i] = 0;
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final display = _reveal ? _plain : '●' * (_plain.isEmpty ? 4 : _plain.length);
    return AlertDialog(
      title: const Text('密码'),
      content: Row(
        children: [
          Expanded(
            child: SelectableText(
              display.isEmpty ? '（空）' : display,
              style: const TextStyle(fontSize: 18, fontFamily: 'monospace'),
            ),
          ),
          IconButton(
            icon: Icon(_reveal ? Icons.visibility_off : Icons.visibility),
            tooltip: _reveal ? '隐藏' : '显示',
            onPressed: () => setState(() => _reveal = !_reveal),
          ),
        ],
      ),
      actions: [
        TextButton.icon(
          onPressed: _copy,
          icon: const Icon(Icons.copy),
          label: const Text('复制'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('关闭'),
        ),
      ],
    );
  }
}
