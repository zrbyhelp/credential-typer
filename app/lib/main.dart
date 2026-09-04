import 'package:flutter/material.dart';

import 'state/app_state.dart';
import 'ui/accounts_page.dart';
import 'ui/setup_page.dart';
import 'ui/unlock_page.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(CredentialTyperApp(state: AppState()));
}

class CredentialTyperApp extends StatefulWidget {
  final AppState state;
  const CredentialTyperApp({super.key, required this.state});

  @override
  State<CredentialTyperApp> createState() => _CredentialTyperAppState();
}

class _CredentialTyperAppState extends State<CredentialTyperApp>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    widget.state.bootstrap();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    widget.state.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // 真正进后台（paused/hidden）时自动锁定，清零内存 DEK。
    // 不处理 inactive，避免权限弹窗/切换动画/来电等瞬态误锁。
    if ((state == AppLifecycleState.paused ||
            state == AppLifecycleState.hidden) &&
        widget.state.isUnlocked) {
      widget.state.lock();
    }
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      state: widget.state,
      child: MaterialApp(
        title: '凭据填充器',
        debugShowCheckedModeBanner: false,
        theme: ThemeData(
          colorSchemeSeed: const Color(0xFF3B6EA5),
          useMaterial3: true,
          brightness: Brightness.light,
        ),
        darkTheme: ThemeData(
          colorSchemeSeed: const Color(0xFF3B6EA5),
          useMaterial3: true,
          brightness: Brightness.dark,
        ),
        // 任意触摸都重置无操作计时；解锁态静置超时会自动锁定。
        builder: (context, child) => Listener(
          behavior: HitTestBehavior.translucent,
          onPointerDown: (_) => widget.state.resetIdleTimer(),
          child: child,
        ),
        home: const _Root(),
      ),
    );
  }
}

/// 根据保险库状态路由：首次 → 创建；已存在未解锁 → 解锁；已解锁 → 账户列表。
class _Root extends StatelessWidget {
  const _Root();

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    return ListenableBuilder(
      listenable: app,
      builder: (context, _) {
        if (app.isUnlocked) return const AccountsPage();
        if (!app.vaultExists) return const SetupPage();
        return const UnlockPage();
      },
    );
  }
}
