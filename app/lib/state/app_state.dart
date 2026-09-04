import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';

import '../backup/r2_backup_service.dart';
import '../backup/r2_config.dart';
import '../transport/identity_store.dart';
import '../transport/pairing_store.dart';
import '../vault/vault_repository.dart';
import '../vault/account.dart';
import 'connection.dart';
import '../transport/account_import.dart';

/// 顶层应用状态：保险库 + 连接管理 + 身份。
class AppState extends ChangeNotifier {
  final VaultRepository vault;
  final IdentityStore identity;
  final PairingStore pairing;
  final ConnectionManager connection;
  final R2ConfigStore r2Store;

  bool vaultExists = false;

  /// Website supplied by the desktop on the latest account import; the list
  /// uses it as a temporary filter so the new account is easy to find.
  String? syncedWebsite;
  String syncedSearchQuery = '';
  bool _bootstrapped = false;

  // —— 自动锁定：无操作超时 ——
  static const Duration _idleTimeout = Duration(minutes: 3);
  Timer? _idleTimer;

  // —— R2 自动备份 ——
  R2Config? _r2Config;
  Timer? _backupDebounce;
  DateTime? lastBackupAt;
  String? lastBackupError;

  R2Config? get r2Config => _r2Config;
  bool get r2Configured => _r2Config?.isComplete ?? false;

  AppState._({
    required this.vault,
    required this.identity,
    required this.pairing,
    required this.connection,
    required this.r2Store,
  }) {
    // 桌面推来的焦点窗口(ctx)变化只通知 ConnectionManager；转发到 AppState，
    // 账户页才能随聚焦窗口切换实时重排。
    connection.addListener(notifyListeners);
    // 保险库每次落盘后调度一次 R2 自动备份。
    vault.onChanged = _scheduleBackup;
    connection.onAccountImport = _importAccount;
    connection.onFilterSync = (query) {
      syncedSearchQuery = query;
      notifyListeners();
    };
  }

  Future<void> _importAccount(AccountImportPayload payload) async {
    await vault.upsert(
      title: payload.title,
      username: payload.username,
      website: payload.website,
      note: payload.note,
      passwordBytes: payload.passwordBytes,
    );
    syncedWebsite = Account.normalizeWebsite(payload.website);
    notifyListeners();
  }

  factory AppState({
    VaultRepository? vault,
    IdentityStore? identity,
    PairingStore? pairing,
    R2ConfigStore? r2Store,
  }) {
    final id = identity ?? IdentityStore();
    final pr = pairing ?? PairingStore();
    return AppState._(
      vault: vault ?? VaultRepository(),
      identity: id,
      pairing: pr,
      connection: ConnectionManager(id, pr),
      r2Store: r2Store ?? R2ConfigStore(),
    );
  }

  bool get isUnlocked => vault.isUnlocked;

  Future<void> bootstrap() async {
    if (_bootstrapped) return;
    vaultExists = await vault.exists();
    _r2Config = await r2Store.load();
    _bootstrapped = true;
    notifyListeners();
  }

  Future<void> createVault(List<int> passwordBytes) async {
    await vault.create(passwordBytes);
    vaultExists = true;
    notifyListeners();
  }

  Future<bool> unlock(List<int> passwordBytes) async {
    final ok = await vault.unlock(passwordBytes);
    if (ok) {
      resetIdleTimer();
      notifyListeners();
    }
    return ok;
  }

  void lock() {
    _idleTimer?.cancel();
    _idleTimer = null;
    _backupDebounce?.cancel();
    _backupDebounce = null;
    connection.disconnect();
    vault.lock();
    notifyListeners();
  }

  // —— 自动锁定 ——

  /// 有用户操作时调用：仅在已解锁时（重）启动无操作计时。超时即 [lock]。
  void resetIdleTimer() {
    if (!isUnlocked) return;
    _idleTimer?.cancel();
    _idleTimer = Timer(_idleTimeout, _onIdleTimeout);
  }

  void _onIdleTimeout() {
    if (isUnlocked) lock();
  }

  // —— R2 自动备份 ——

  /// 保险库落盘后由 [VaultRepository.onChanged] 触发：防抖 5 秒后上传一次。
  void _scheduleBackup() {
    if (!r2Configured) return;
    _backupDebounce?.cancel();
    _backupDebounce = Timer(const Duration(seconds: 5), _runBackup);
  }

  Future<void> _runBackup() async {
    final cfg = _r2Config;
    if (cfg == null || !cfg.isComplete) return;
    if (!isUnlocked) return;
    try {
      final bytes = await vault.exportBytes();
      await R2BackupService(cfg).upload(bytes);
      lastBackupAt = DateTime.now();
      lastBackupError = null;
    } catch (e) {
      lastBackupError = e.toString();
    }
    notifyListeners();
  }

  /// 立即备份到 R2（菜单手动触发）。返回错误信息，null 表示成功。
  Future<String?> backupNow() async {
    final cfg = _r2Config;
    if (cfg == null || !cfg.isComplete) return '尚未配置 R2';
    try {
      final bytes = await vault.exportBytes();
      await R2BackupService(cfg).upload(bytes);
      lastBackupAt = DateTime.now();
      lastBackupError = null;
      notifyListeners();
      return null;
    } catch (e) {
      lastBackupError = e.toString();
      notifyListeners();
      return e.toString();
    }
  }

  /// 从 R2 拉回最新加密快照；对象不存在返回 null。失败抛异常。
  Future<Uint8List?> fetchR2Backup() async {
    final cfg = _r2Config;
    if (cfg == null || !cfg.isComplete) {
      throw StateError('尚未配置 R2');
    }
    return R2BackupService(cfg).download();
  }

  /// 用加密备份覆盖当前库（恢复语义）。需要该备份对应的主密码。
  Future<bool> importBackup(Uint8List bytes, List<int> pwBytes) async {
    final ok = await vault.importFrom(bytes, pwBytes);
    if (ok) {
      vaultExists = true;
      resetIdleTimer();
      notifyListeners();
    }
    return ok;
  }

  // —— R2 配置 ——

  Future<void> saveR2Config(R2Config cfg) async {
    await r2Store.save(cfg);
    _r2Config = cfg;
    notifyListeners();
  }

  Future<void> clearR2Config() async {
    await r2Store.clear();
    _r2Config = null;
    notifyListeners();
  }

  /// 试连 R2；返回 null=成功，否则为可展示的错误信息。
  Future<String?> testR2(R2Config cfg) => R2BackupService(cfg).test();

  @override
  void dispose() {
    _idleTimer?.cancel();
    _backupDebounce?.cancel();
    connection.removeListener(notifyListeners);
    connection.dispose();
    super.dispose();
  }
}

/// 让 widget 树取到 AppState。
class AppScope extends InheritedNotifier<AppState> {
  const AppScope({super.key, required AppState state, required super.child})
      : super(notifier: state);

  static AppState of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppScope>();
    assert(scope != null, '找不到 AppScope');
    return scope!.notifier!;
  }
}
