import 'package:flutter/material.dart';

import '../backup/r2_config.dart';
import '../state/app_state.dart';

/// Cloudflare R2 备份设置：四个字段 + 测试连接 + 保存。
/// 凭证只经 [R2ConfigStore] 存进 Android Keystore（flutter_secure_storage），
/// 不落普通存储、不进日志、不进版本控制。
class R2SettingsPage extends StatefulWidget {
  const R2SettingsPage({super.key});

  @override
  State<R2SettingsPage> createState() => _R2SettingsPageState();
}

class _R2SettingsPageState extends State<R2SettingsPage> {
  final _endpoint = TextEditingController();
  final _bucket = TextEditingController();
  final _accessKeyId = TextEditingController();
  final _secret = TextEditingController();
  bool _obscureSecret = true;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    final cfg = AppScope.of(context).r2Config;
    if (cfg != null) {
      _endpoint.text = cfg.endpoint;
      _bucket.text = cfg.bucket;
      _accessKeyId.text = cfg.accessKeyId;
      _secret.text = cfg.secretAccessKey;
    }
  }

  @override
  void dispose() {
    _endpoint.dispose();
    _bucket.dispose();
    _accessKeyId.dispose();
    _secret.dispose();
    super.dispose();
  }

  R2Config _current() => R2Config(
        endpoint: _endpoint.text,
        bucket: _bucket.text,
        accessKeyId: _accessKeyId.text,
        secretAccessKey: _secret.text,
      );

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(content: Text(msg)));
  }

  Future<void> _test() async {
    final cfg = _current();
    if (!cfg.isComplete) {
      _toast('请先填完四个字段');
      return;
    }
    setState(() => _busy = true);
    final err = await AppScope.of(context).testR2(cfg);
    if (!mounted) return;
    setState(() => _busy = false);
    _toast(err == null ? '连接成功' : '连接失败：$err');
  }

  Future<void> _save() async {
    final cfg = _current();
    if (!cfg.isComplete) {
      _toast('请先填完四个字段');
      return;
    }
    setState(() => _busy = true);
    await AppScope.of(context).saveR2Config(cfg);
    if (!mounted) return;
    setState(() => _busy = false);
    _toast('已保存');
    Navigator.of(context).pop();
  }

  Future<void> _clear() async {
    setState(() => _busy = true);
    await AppScope.of(context).clearR2Config();
    if (!mounted) return;
    _endpoint.clear();
    _bucket.clear();
    _accessKeyId.clear();
    _secret.clear();
    setState(() => _busy = false);
    _toast('已清除 R2 配置');
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    return Scaffold(
      appBar: AppBar(
        title: const Text('R2 备份设置'),
        actions: [
          IconButton(
            tooltip: '清除',
            icon: const Icon(Icons.delete_outline),
            onPressed: _busy ? null : _clear,
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          const Text(
            '把加密的保险库快照自动备份到 Cloudflare R2。上传的是密文，无主密码不可解；'
            '密钥仅保存在本机安全存储（Keystore）。',
            style: TextStyle(color: Colors.grey, fontSize: 13),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _endpoint,
            decoration: const InputDecoration(
              labelText: 'Endpoint',
              hintText: 'https://<accountId>.r2.cloudflarestorage.com',
              border: OutlineInputBorder(),
            ),
            keyboardType: TextInputType.url,
            autocorrect: false,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _bucket,
            decoration: const InputDecoration(
              labelText: 'Bucket',
              border: OutlineInputBorder(),
            ),
            autocorrect: false,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _accessKeyId,
            decoration: const InputDecoration(
              labelText: 'Access Key ID',
              border: OutlineInputBorder(),
            ),
            autocorrect: false,
          ),
          const SizedBox(height: 12),
          TextField(
            controller: _secret,
            obscureText: _obscureSecret,
            decoration: InputDecoration(
              labelText: 'Secret Access Key',
              border: const OutlineInputBorder(),
              suffixIcon: IconButton(
                icon: Icon(
                    _obscureSecret ? Icons.visibility : Icons.visibility_off),
                onPressed: () =>
                    setState(() => _obscureSecret = !_obscureSecret),
              ),
            ),
            autocorrect: false,
          ),
          const SizedBox(height: 20),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: _busy ? null : _test,
                  icon: const Icon(Icons.wifi_tethering),
                  label: const Text('测试连接'),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: FilledButton.icon(
                  onPressed: _busy ? null : _save,
                  icon: const Icon(Icons.save),
                  label: const Text('保存'),
                ),
              ),
            ],
          ),
          if (_busy) ...[
            const SizedBox(height: 20),
            const Center(child: CircularProgressIndicator()),
          ],
          if (app.lastBackupAt != null || app.lastBackupError != null) ...[
            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 8),
            if (app.lastBackupError != null)
              Text('上次备份失败：${app.lastBackupError}',
                  style: const TextStyle(color: Colors.red))
            else if (app.lastBackupAt != null)
              Text('上次备份：${app.lastBackupAt}',
                  style: const TextStyle(color: Colors.green)),
          ],
        ],
      ),
    );
  }
}
