import 'package:flutter/material.dart';

import '../state/connection.dart';

/// 顶部连接状态条：显示与桌面的连接状态和当前焦点上下文。
class ConnectionBar extends StatelessWidget {
  final ConnectionManager conn;
  const ConnectionBar({super.key, required this.conn});

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: conn,
      builder: (context, _) {
        final (color, icon, text) = _describe();
        final ctx = conn.ctx;
        return Material(
          color: color.withOpacity(0.12),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            child: Row(
              children: [
                Icon(icon, color: color, size: 20),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(text,
                          style: TextStyle(
                              color: color, fontWeight: FontWeight.w600)),
                      if (conn.isConnected && ctx != null)
                        Text(
                          _ctxLine(
                              ctx.app, ctx.title, ctx.fieldKind, ctx.fieldName),
                          style: Theme.of(context).textTheme.bodySmall,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  (Color, IconData, String) _describe() {
    switch (conn.status) {
      case ConnStatus.connected:
        return (Colors.green, Icons.link, '已连接桌面');
      case ConnStatus.connecting:
        return (Colors.orange, Icons.sync, '连接中…');
      case ConnStatus.error:
        return (Colors.red, Icons.link_off, conn.lastError ?? '连接出错');
      case ConnStatus.idle:
        return (Colors.grey, Icons.link_off, '未连接（右上角扫码配对）');
    }
  }

  String _ctxLine(String app, String title, String kind, String name) {
    final kindText = switch (kind) {
      'password' => '密码框',
      'text' => '文本框',
      'other' => '其他控件',
      _ => '无焦点框',
    };
    final where = app.isEmpty ? '' : '$app · ';
    final field = name.isEmpty ? kindText : '$kindText「$name」';
    return '$where$field';
  }
}
