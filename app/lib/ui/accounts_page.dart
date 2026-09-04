import 'dart:convert';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

import '../state/app_state.dart';
import '../vault/account.dart';
import 'account_detail_page.dart';
import 'connection_bar.dart';
import 'edit_account_page.dart';
import 'pair_page.dart';
import 'r2_settings_page.dart';

/// 主页面：连接状态条 + 账户列表。
class AccountsPage extends StatefulWidget {
  const AccountsPage({super.key});

  @override
  State<AccountsPage> createState() => _AccountsPageState();
}

class _AccountsPageState extends State<AccountsPage> {
  String _query = '';
  final TextEditingController _searchController = TextEditingController();
  String _lastSyncedQuery = '';
  String? _websiteFilter;
  int _sort = 0; // 0 usage count, 1 recent use, 2 updated

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();
    // 进入即尝试重连（若已配对）。
    WidgetsBinding.instance.addPostFrameCallback((_) {
      AppScope.of(context).connection.ensureConnected();
    });
  }

  Future<void> _pair() async {
    final app = AppScope.of(context);
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const PairPage()),
    );
    if (mounted) setState(() {});
    // 配对后连接状态由 ConnectionManager 通知刷新。
    app.connection.ensureConnected();
  }

  Future<void> _add() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const EditAccountPage()),
    );
    if (mounted) setState(() {});
  }

  void _lock() => AppScope.of(context).lock();

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(content: Text(msg)));
  }

  /// 询问一个主密码（用于导入/从 R2 恢复的二次验证）。取消返回 null。
  Future<String?> _askPassword(String title) async {
    final ctrl = TextEditingController();
    final v = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          obscureText: true,
          decoration: const InputDecoration(labelText: '该备份的主密码'),
          onSubmitted: (t) => Navigator.pop(ctx, t),
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
    return v;
  }

  Future<bool> _confirmOverwrite() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('覆盖当前数据'),
        content: const Text('恢复备份会用备份内容**覆盖**当前保险库，当前所有账户将被替换。确定继续？'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('取消')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('覆盖恢复')),
        ],
      ),
    );
    return ok == true;
  }

  Future<void> _exportBackup() async {
    final app = AppScope.of(context);
    try {
      final bytes = await app.vault.exportBytes();
      final now = DateTime.now();
      final stamp = '${now.year}${_pad2(now.month)}${_pad2(now.day)}'
          '-${_pad2(now.hour)}${_pad2(now.minute)}';
      final path = await FilePicker.platform.saveFile(
        dialogTitle: '导出加密备份',
        fileName: 'credential-typer-backup-$stamp.ctvault',
        bytes: bytes,
      );
      if (path == null) return; // 用户取消
      _toast('已导出加密备份');
    } catch (e) {
      _toast('导出失败：$e');
    }
  }

  Future<void> _importBackup() async {
    final app = AppScope.of(context);
    final res = await FilePicker.platform.pickFiles(withData: true);
    if (res == null || res.files.isEmpty) return;
    final data = res.files.first.bytes;
    if (data == null) {
      _toast('无法读取所选文件');
      return;
    }
    if (!await _confirmOverwrite()) return;
    final pw = await _askPassword('输入备份主密码');
    if (pw == null || pw.isEmpty) return;
    final pwBytes = utf8.encode(pw);
    final ok = await app.importBackup(Uint8List.fromList(data), pwBytes);
    _zeroList(pwBytes);
    if (!mounted) return;
    _toast(ok ? '已从备份恢复' : '主密码错误或文件损坏');
    if (ok) setState(() {});
  }

  Future<void> _openR2Settings() async {
    await Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const R2SettingsPage()),
    );
    if (mounted) setState(() {});
  }

  Future<void> _backupToR2Now() async {
    final app = AppScope.of(context);
    if (!app.r2Configured) {
      _toast('请先在「R2 备份设置」里配置');
      return;
    }
    _toast('正在备份到 R2…');
    final err = await app.backupNow();
    if (!mounted) return;
    _toast(err == null ? '已备份到 R2' : 'R2 备份失败：$err');
  }

  Future<void> _restoreFromR2() async {
    final app = AppScope.of(context);
    if (!app.r2Configured) {
      _toast('请先在「R2 备份设置」里配置');
      return;
    }
    Uint8List? data;
    try {
      _toast('正在从 R2 拉取…');
      data = await app.fetchR2Backup();
    } catch (e) {
      _toast('R2 拉取失败：$e');
      return;
    }
    if (!mounted) return;
    if (data == null) {
      _toast('R2 上暂无备份');
      return;
    }
    if (!await _confirmOverwrite()) return;
    final pw = await _askPassword('输入该备份的主密码');
    if (pw == null || pw.isEmpty) return;
    final pwBytes = utf8.encode(pw);
    final ok = await app.importBackup(data, pwBytes);
    _zeroList(pwBytes);
    if (!mounted) return;
    _toast(ok ? '已从 R2 恢复' : '主密码错误或备份损坏');
    if (ok) setState(() {});
  }

  static String _pad2(int n) => n.toString().padLeft(2, '0');

  static void _zeroList(List<int> b) {
    for (var i = 0; i < b.length; i++) {
      b[i] = 0;
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final all = app.vault.accounts();
    if (app.syncedSearchQuery != _lastSyncedQuery &&
        app.syncedSearchQuery != _query) {
      _lastSyncedQuery = app.syncedSearchQuery;
      _query = app.syncedSearchQuery;
      _searchController.value = TextEditingValue(text: _query);
    }
    final q = _query.trim().toLowerCase();
    final contextApp = app.connection.ctx?.app.toLowerCase().trim() ?? '';
    final passwordField = app.connection.ctx?.isPasswordField ?? false;
    final websiteFilter = _websiteFilter ?? app.syncedWebsite;
    final accounts = all
        .where((a) =>
            a.title.toLowerCase().contains(q) ||
            a.username.toLowerCase().contains(q) ||
            a.website.toLowerCase().contains(q) ||
            a.note.toLowerCase().contains(q))
        .where((a) =>
            websiteFilter == null ||
            websiteFilter.isEmpty ||
            a.website == websiteFilter)
        .toList();
    accounts.sort((a, b) {
      if (_sort == 0) {
        final ac = (passwordField
                ? a.passwordUseCounts
                : a.usernameUseCounts)['$contextApp|${a.website}'] ??
            0;
        final bc = (passwordField
                ? b.passwordUseCounts
                : b.usernameUseCounts)['$contextApp|${b.website}'] ??
            0;
        final byCount = bc.compareTo(ac);
        if (byCount != 0) return byCount;
      }
      if (_sort == 1) return b.lastUsedAt.compareTo(a.lastUsedAt);
      if (_sort == 2) return b.updatedAt.compareTo(a.updatedAt);
      return a.title.toLowerCase().compareTo(b.title.toLowerCase());
    });

    return Scaffold(
      appBar: AppBar(
        title: const Text('账户'),
        actions: [
          IconButton(
            tooltip: '扫码配对',
            icon: const Icon(Icons.qr_code_scanner),
            onPressed: _pair,
          ),
          IconButton(
            tooltip: '锁定',
            icon: const Icon(Icons.lock_outline),
            onPressed: _lock,
          ),
          PopupMenuButton<String>(
            tooltip: '更多',
            onSelected: (v) {
              switch (v) {
                case 'export':
                  _exportBackup();
                  break;
                case 'import':
                  _importBackup();
                  break;
                case 'r2settings':
                  _openR2Settings();
                  break;
                case 'r2backup':
                  _backupToR2Now();
                  break;
                case 'r2restore':
                  _restoreFromR2();
                  break;
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(
                value: 'export',
                child: ListTile(
                    leading: Icon(Icons.upload_file),
                    title: Text('导出备份'),
                    dense: true),
              ),
              PopupMenuItem(
                value: 'import',
                child: ListTile(
                    leading: Icon(Icons.download),
                    title: Text('导入备份'),
                    dense: true),
              ),
              PopupMenuDivider(),
              PopupMenuItem(
                value: 'r2settings',
                child: ListTile(
                    leading: Icon(Icons.cloud_outlined),
                    title: Text('R2 备份设置'),
                    dense: true),
              ),
              PopupMenuItem(
                value: 'r2backup',
                child: ListTile(
                    leading: Icon(Icons.cloud_upload_outlined),
                    title: Text('立即备份到 R2'),
                    dense: true),
              ),
              PopupMenuItem(
                value: 'r2restore',
                child: ListTile(
                    leading: Icon(Icons.cloud_download_outlined),
                    title: Text('从 R2 恢复'),
                    dense: true),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          ConnectionBar(conn: app.connection),
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
            child: TextField(
              decoration: const InputDecoration(
                prefixIcon: Icon(Icons.search),
                hintText: '搜索账户',
                isDense: true,
                border: OutlineInputBorder(),
              ),
              onChanged: (v) => setState(() => _query = v),
              controller: _searchController,
            ),
          ),
          if (websiteFilter != null && websiteFilter.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 6),
              child: Align(
                alignment: Alignment.centerLeft,
                child: InputChip(
                  avatar: const Icon(Icons.language, size: 16),
                  label: Text('网站筛选：$websiteFilter'),
                  onDeleted: () => setState(() => _websiteFilter = ''),
                ),
              ),
            ),
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 8),
            child: Align(
              alignment: Alignment.centerRight,
              child: DropdownButton<int>(
                value: _sort,
                isDense: true,
                underline: const SizedBox.shrink(),
                items: const [
                  DropdownMenuItem(value: 0, child: Text('按使用次数')),
                  DropdownMenuItem(value: 1, child: Text('最近使用')),
                  DropdownMenuItem(value: 2, child: Text('最近修改'))
                ],
                onChanged: (v) => setState(() => _sort = v ?? 0),
              ),
            ),
          ),
          Expanded(
            child: accounts.isEmpty
                ? _empty(context)
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(horizontal: 12),
                    itemCount: accounts.length,
                    itemBuilder: (context, i) => _tile(context, accounts[i]),
                  ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _add,
        icon: const Icon(Icons.add),
        label: const Text('添加'),
      ),
    );
  }

  Widget _tile(BuildContext context, Account a) {
    return ListTile(
      leading: CircleAvatar(
        child: Text(a.title.isEmpty ? '?' : a.title.characters.first),
      ),
      title: Text(a.title),
      subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(a.username, maxLines: 1, overflow: TextOverflow.ellipsis),
        if (a.website.isNotEmpty)
          Text(a.website, style: Theme.of(context).textTheme.bodySmall),
      ]),
      trailing: PopupMenuButton<String>(
        onSelected: (v) async {
          if (!AppScope.of(context).connection.isConnected) {
            ScaffoldMessenger.of(context)
                .showSnackBar(const SnackBar(content: Text('未连接桌面')));
            return;
          }
          final bytes = v == 'password'
              ? await AppScope.of(context).vault.secretBytes(a.id)
              : AppScope.of(context).vault.usernameBytes(a.id);
          try {
            await AppScope.of(context)
                .connection
                .sendFill(Uint8List.fromList(bytes), enter: false);
            final appName =
                AppScope.of(context).connection.ctx?.app.toLowerCase().trim() ??
                    '';
            await AppScope.of(context).vault.recordFill(
                accountId: a.id,
                password: v == 'password',
                contextKey: '$appName|${a.website}');
          } finally {
            if (v == 'password') bytes.fillRange(0, bytes.length, 0);
          }
        },
        itemBuilder: (_) => const [
          PopupMenuItem(value: 'username', child: Text('填账号')),
          PopupMenuItem(value: 'password', child: Text('填密码'))
        ],
      ),
      onTap: () async {
        await Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => AccountDetailPage(accountId: a.id)),
        );
        if (mounted) setState(() {});
      },
    );
  }

  Widget _empty(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(Icons.inbox_outlined, size: 64, color: Colors.grey),
          const SizedBox(height: 12),
          Text('还没有账户', style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 4),
          const Text('点右下角「添加」新建一个', style: TextStyle(color: Colors.grey)),
        ],
      ),
    );
  }
}
