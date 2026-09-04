import 'dart:convert';

import 'package:flutter/material.dart';

import '../state/app_state.dart';

/// 首次运行：设定主密码，创建加密保险库。
class SetupPage extends StatefulWidget {
  const SetupPage({super.key});

  @override
  State<SetupPage> createState() => _SetupPageState();
}

class _SetupPageState extends State<SetupPage> {
  final _pw1 = TextEditingController();
  final _pw2 = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _pw1.dispose();
    _pw2.dispose();
    super.dispose();
  }

  Future<void> _create() async {
    final p1 = _pw1.text;
    if (p1.length < 8) {
      setState(() => _error = '主密码至少 8 位');
      return;
    }
    if (p1 != _pw2.text) {
      setState(() => _error = '两次输入不一致');
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await AppScope.of(context).createVault(utf8.encode(p1));
      _pw1.clear();
      _pw2.clear();
    } catch (e) {
      setState(() => _error = '创建失败: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('创建保险库')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 420),
          child: ListView(
            padding: const EdgeInsets.all(24),
            shrinkWrap: true,
            children: [
              const Icon(Icons.lock_outline, size: 64),
              const SizedBox(height: 16),
              Text('设定主密码', style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 8),
              const Text(
                '主密码用于加密本机保险库。忘记将无法找回——所有账户永久丢失。',
                style: TextStyle(color: Colors.orange),
              ),
              const SizedBox(height: 24),
              TextField(
                controller: _pw1,
                obscureText: true,
                autofocus: true,
                decoration: const InputDecoration(
                  labelText: '主密码',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _pw2,
                obscureText: true,
                onSubmitted: (_) => _create(),
                decoration: const InputDecoration(
                  labelText: '再次输入',
                  border: OutlineInputBorder(),
                ),
              ),
              if (_error != null) ...[
                const SizedBox(height: 12),
                Text(_error!, style: const TextStyle(color: Colors.red)),
              ],
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _busy ? null : _create,
                child: _busy
                    ? const SizedBox(
                        height: 20,
                        width: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('创建'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
