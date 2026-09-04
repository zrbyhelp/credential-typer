import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../noise/qr_payload.dart';
import '../noise/protocol.dart';
import '../state/app_state.dart';
import '../state/connection.dart';

/// 扫描桌面二维码 → IK 配对 → 指纹目视核对。
class PairPage extends StatefulWidget {
  const PairPage({super.key});

  @override
  State<PairPage> createState() => _PairPageState();
}

class _PairPageState extends State<PairPage> with WidgetsBindingObserver {
  bool _handled = false;
  bool _pairing = false;
  String? _error;
  String? _diag; // 诊断细节：实际尝试的地址 + 原始错误，供排障阅读
  PairResult? _result;
  bool _manual = false;
  final _manualCode = TextEditingController();
  late final MobileScannerController _scannerController;

  // The native camera API is stateful.  Keep every start/stop/dispose call on
  // one queue so a route transition, lifecycle callback, and retry cannot
  // invoke the plugin concurrently.
  Future<void> _scannerQueue = Future<void>.value();
  bool _scannerDisposed = false;
  bool _scannerRetrying = false;
  bool _appResumed = true;

  @override
  void initState() {
    super.initState();
    _scannerController = MobileScannerController(autoStart: false);
    final lifecycle = WidgetsBinding.instance.lifecycleState;
    _appResumed = lifecycle == null || lifecycle == AppLifecycleState.resumed;
    WidgetsBinding.instance.addObserver(this);

    // MobileScanner attaches the supplied controller from its own initState.
    // Starting on the next frame guarantees that attach has completed.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && _appResumed) unawaited(_startScanner());
    });
  }

  @override
  void dispose() {
    _scannerDisposed = true;
    WidgetsBinding.instance.removeObserver(this);

    // Do not dispose the controller while an asynchronous native start is in
    // flight.  Queue disposal behind the pending operation.
    unawaited(_enqueueScanner(() async {
      try {
        await _scannerController.stop();
      } catch (_) {
        // The controller may already be stopped or the Activity may be gone.
      }
      try {
        await _scannerController.dispose();
      } catch (_) {
        // Disposal is best effort during Activity teardown.
      }
    }).catchError((_) {}));
    _manualCode.dispose();
    super.dispose();
  }

  /// Run a camera operation after all previously queued operations.
  Future<void> _enqueueScanner(Future<void> Function() operation) {
    final next = _scannerQueue.then<void>(
      (_) async => operation(),
      onError: (Object _, StackTrace __) async => operation(),
    );
    // A failed operation must not poison the queue; callers still receive the
    // original error through [next] when they need it.
    _scannerQueue = next.catchError((_) {});
    return next;
  }

  Future<void> _startScanner() {
    return _enqueueScanner(() async {
      if (_scannerDisposed ||
          !mounted ||
          !_appResumed ||
          _handled ||
          _pairing ||
          _result != null ||
          _error != null) {
        return;
      }

      // After a denied permission, MobileScanner marks the controller as
      // initialized but without camera access.  Do not keep re-requesting it
      // from lifecycle callbacks; the explicit retry button can still try
      // again after the user changes the system permission.
      if (_scannerController.value.isInitialized &&
          !_scannerController.value.hasCameraPermission) {
        return;
      }

      // A failed CameraX/ML Kit initialization is retained in the controller
      // as `value.error` while `isInitialized` remains true.  Lifecycle
      // callbacks (especially the resume event emitted after a permission
      // dialog) must not call start() again automatically: the native
      // controller may still be unwinding the failed provider and a second
      // bind can reproduce the Android null-object crash.  The explicit
      // retry action below is the only path that retries a failed start.
      if (_scannerController.value.error != null) {
        return;
      }

      try {
        await _scannerController.start();
      } catch (_) {
        // MobileScanner normally stores initialization failures in its state
        // and renders errorBuilder.  Ignore teardown/attach races here so an
        // unhandled Future does not crash the Flutter isolate.
      }
    });
  }

  Future<void> _stopScanner() {
    return _enqueueScanner(() async {
      if (_scannerDisposed) return;
      try {
        await _scannerController.stop();
      } catch (_) {
        // stop() is intentionally idempotent for route/lifecycle changes.
      }
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (_scannerDisposed) return;

    // Keep our own visibility flag up to date even while permission is being
    // requested.  The guard below only suppresses camera calls during that
    // transient period.
    _appResumed = state == AppLifecycleState.resumed;

    // Permission dialogs themselves emit inactive/resumed events.  The
    // controller is not ready during that window, so ignoring those events
    // prevents a stop/start race while Android is asking for permission.
    if (!_scannerController.value.hasCameraPermission) return;

    switch (state) {
      case AppLifecycleState.resumed:
        if (!_handled && !_pairing && _result == null && _error == null) {
          unawaited(_startScanner());
        }
        break;
      case AppLifecycleState.inactive:
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
      case AppLifecycleState.detached:
        unawaited(_stopScanner());
        break;
    }
  }

  Future<void> _onDetect(BarcodeCapture capture) async {
    if (_handled) return;
    final raw = capture.barcodes
        .map((b) => b.rawValue)
        .firstWhere((v) => v != null && v.isNotEmpty, orElse: () => null);
    if (raw == null) return;

    await _pairRaw(raw);
  }

  Future<void> _pairRaw(String raw) async {
    if (_handled || _pairing || _result != null) return;
    _handled = true;
    // Stop frame delivery before opening the network session.  This also
    // serializes with an in-progress initial camera start.
    await _stopScanner();
    if (!mounted) return;
    setState(() => _pairing = true);

    QrPayload? qr;
    try {
      qr = QrPayload.fromQrText(raw);
      final result = await AppScope.of(context).connection.pair(qr);
      if (mounted) {
        setState(() {
          _result = result;
          _pairing = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = _pairErrorText(e);
          _diag = _pairDiag(e, qr);
          _pairing = false;
        });
      }
    }
  }

  /// 排障用：把「实际尝试的地址:端口」和「原始错误」拼出来展示，
  /// 让用户一眼看出手机到底连的是哪个 IP、失败在连接阶段还是握手阶段。
  String? _pairDiag(Object error, QrPayload? qr) {
    if (qr == null) return null;
    final addr = '${qr.host.join(' / ')}:${qr.port}';
    final text = error.toString();
    final stage = text.contains('EndOfStream')
        ? '已连上电脑，但握手被中断（多为电脑端未处在配对窗口 / 扫了旧二维码）'
        : (text.contains('无法连接任一地址') ||
                text.contains('SocketException') ||
                error is SocketException)
            ? '没能连上电脑（连接被拒绝或超时，多为防火墙 / 该 IP 不可达）'
            : '其它错误';
    // 截断原始错误，避免把 Java/Native 堆栈整段贴出来。
    final rawShort = text.length > 180 ? '${text.substring(0, 180)}…' : text;
    return '尝试地址：$addr\n判断：$stage\n原始：$rawShort';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('扫码配对')),
      body: _result != null
          ? _confirmView(_result!)
          : _error != null
              ? _errorView()
              : _scanView(),
    );
  }

  Widget _scanView() {
    return Stack(
      alignment: Alignment.center,
      children: [
        MobileScanner(
          controller: _scannerController,
          // Lifecycle is handled by this State so start/stop calls stay
          // serialized with retries and route transitions.
          useAppLifecycleState: false,
          onDetect: _onDetect,
          errorBuilder: (context, error) => _cameraError(error),
          overlayBuilder: (context, constraints) => Center(
            child: Container(
                width: 260,
                height: 260,
                decoration: BoxDecoration(
                    border: Border.all(color: Colors.white, width: 3),
                    borderRadius: BorderRadius.circular(18))),
          ),
        ),
        if (_pairing)
          Container(
            color: Colors.black54,
            child: const Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircularProgressIndicator(),
                  SizedBox(height: 12),
                  Text('配对中…', style: TextStyle(color: Colors.white)),
                ],
              ),
            ),
          )
        else
          Positioned(
              bottom: 24,
              left: 16,
              right: 16,
              child: Column(children: [
                const Text('把镜头对准 PC 上显示的二维码',
                    style: TextStyle(color: Colors.white, fontSize: 16)),
                const SizedBox(height: 12),
                OutlinedButton.icon(
                    onPressed: _showManualInput,
                    icon: const Icon(Icons.keyboard, color: Colors.white),
                    label: const Text('输入连接码',
                        style: TextStyle(color: Colors.white))),
              ])),
      ],
    );
  }

  Widget _cameraError(MobileScannerException error) {
    final denied = error.errorCode == MobileScannerErrorCode.permissionDenied;
    final unsupported = error.errorCode == MobileScannerErrorCode.unsupported;
    final preparing =
        error.errorCode == MobileScannerErrorCode.controllerNotAttached ||
            error.errorCode == MobileScannerErrorCode.controllerInitializing;
    // Do not expose the native exception/details here.  Android camera
    // backends occasionally return a Java stack trace (or a null-object
    // message), which is not actionable for a user and makes the page look
    // broken.  Keep the message short and offer a deterministic retry path.
    final title = denied
        ? '需要相机权限才能扫码'
        : unsupported
            ? '当前设备不支持相机扫码'
            : preparing
                ? '相机正在准备'
                : '相机暂时不可用';
    final detail = denied
        ? '请在系统设置中允许相机权限，也可以改用手动输入连接码。'
        : unsupported
            ? '请改用手动输入连接码完成配对。'
            : preparing
                ? '请稍候片刻后重试。'
                : '请点击重试；仍无法启动时可改用手动输入连接码。';
    return ColoredBox(
        color: Colors.black87,
        child: Center(
            child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(denied ? Icons.no_photography : Icons.camera_alt_outlined,
                color: Colors.white, size: 56),
            const SizedBox(height: 12),
            Text(title,
                style: const TextStyle(color: Colors.white, fontSize: 18)),
            const SizedBox(height: 8),
            Text(detail,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white70)),
            const SizedBox(height: 16),
            Wrap(spacing: 8, children: [
              OutlinedButton(
                onPressed: _scannerRetrying ? null : _retryScanner,
                child: _scannerRetrying
                    ? const SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('重试'),
              ),
              FilledButton(
                  onPressed: _showManualInput, child: const Text('手动输入')),
            ]),
          ]),
        )));
  }

  Future<void> _retryScanner() async {
    if (_scannerRetrying || _scannerDisposed || !mounted) return;
    setState(() => _scannerRetrying = true);

    try {
      await _enqueueScanner(() async {
        if (_scannerDisposed || !mounted || !_appResumed) return;
        try {
          await _scannerController.stop();
        } catch (_) {}

        // CameraX may finish releasing the previous use cases on the next
        // main-loop turn.  A short gap prevents an immediate duplicate bind.
        await Future<void>.delayed(const Duration(milliseconds: 120));
        if (_scannerDisposed ||
            !mounted ||
            !_appResumed ||
            _handled ||
            _pairing ||
            _result != null ||
            _error != null) {
          return;
        }
        try {
          await _scannerController.start();
        } catch (_) {}
      });
    } finally {
      if (mounted) setState(() => _scannerRetrying = false);
    }
  }

  /// Remove whitespace and copy/paste artefacts before attempting to decode a
  /// manual connection code.  The same cleaning is also performed by
  /// [QrPayload], but doing it here lets the user see what will be parsed.
  String _cleanManualCode(String value) => value.replaceAll(
        RegExp(r'[\u0000-\u0020\u00a0\u200b\u200c\u200d\ufeff]'),
        '',
      );

  String _manualCodeError(Object error) {
    if (error is FormatException) {
      final message = error.message.toString().trim();
      // QrPayload emits short, user-facing Chinese validation messages.  Do
      // not render arbitrary exception text (which may contain a Java stack
      // trace or implementation details).
      if (message.isNotEmpty && message.length <= 64) return message;
    }
    return '连接码格式错误，请检查复制内容';
  }

  String _pairErrorText(Object error) {
    if (error is FormatException) return '格式错误，请重新扫描或检查粘贴内容';
    final text = error.toString();
    if (error is SocketException ||
        text.contains('EndOfStream') ||
        text.contains('Timeout') ||
        text.contains('SocketException')) {
      return '二维码已失效或电脑不可达，请在电脑端点击二维码刷新，并确认手机与电脑在同一 Wi‑Fi';
    }
    return '配对失败，请重试或改用手动输入';
  }

  Future<void> _showManualInput() async {
    if (_manual || _pairing || _scannerDisposed) return;
    // The dialog can remain visible while the Activity stays resumed, so stop
    // the camera explicitly instead of relying only on lifecycle callbacks.
    await _stopScanner();
    if (!mounted) return;
    setState(() => _manual = true);

    await showDialog<void>(
      context: context,
      barrierDismissible: true,
      builder: (dialogContext) {
        QrPayload? parsed;
        String? parseError;
        String? desktopFingerprint;
        bool parsing = false;
        bool connecting = false;

        return StatefulBuilder(
          builder: (context, setDialogState) {
            Future<void> parseCode() async {
              final cleaned = _cleanManualCode(_manualCode.text);
              if (cleaned != _manualCode.text) {
                _manualCode.value = TextEditingValue(
                  text: cleaned,
                  selection: TextSelection.collapsed(offset: cleaned.length),
                );
              }
              if (cleaned.isEmpty) {
                setDialogState(() {
                  parsed = null;
                  desktopFingerprint = null;
                  parseError = '请输入连接码';
                });
                return;
              }

              setDialogState(() {
                parsing = true;
                parsed = null;
                desktopFingerprint = null;
                parseError = null;
              });
              try {
                final qr = QrPayload.fromQrText(cleaned);
                final fp = await Protocol.fingerprint(qr.sPubBytes);
                if (!context.mounted) return;
                setDialogState(() {
                  parsed = qr;
                  desktopFingerprint = fp;
                  parseError = null;
                  parsing = false;
                });
              } catch (error) {
                if (!context.mounted) return;
                setDialogState(() {
                  parsed = null;
                  desktopFingerprint = null;
                  parseError = _manualCodeError(error);
                  parsing = false;
                });
              }
            }

            Future<void> connect() async {
              final qr = parsed;
              if (qr == null || connecting) return;
              final cleaned = _cleanManualCode(_manualCode.text);
              setDialogState(() {
                connecting = true;
                parseError = null;
              });

              // Keep the dialog open while pairing so the progress state is
              // visible and the input remains available if the attempt fails.
              await _pairRaw(cleaned);
              if (!mounted || !context.mounted) return;
              if (_result != null) {
                Navigator.of(dialogContext).pop();
                return;
              }

              final failure = _error ?? '连接失败，请检查电脑端是否已开启配对';
              // _pairRaw marks the attempt as handled.  Clear that marker on a
              // failed manual attempt so the user can edit and retry in place.
              setState(() {
                _error = null;
                _handled = false;
              });
              setDialogState(() {
                connecting = false;
                parseError = failure;
              });
            }

            final canConnect = parsed != null && !parsing && !connecting;
            return AlertDialog(
              title: const Text('输入连接码'),
              content: SingleChildScrollView(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 460),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextField(
                        controller: _manualCode,
                        maxLines: 4,
                        autofocus: true,
                        enabled: !connecting,
                        keyboardType: TextInputType.multiline,
                        autocorrect: false,
                        enableSuggestions: false,
                        style: const TextStyle(fontFamily: 'monospace'),
                        onChanged: (_) => setDialogState(() {
                          parsed = null;
                          desktopFingerprint = null;
                          parseError = null;
                        }),
                        decoration: const InputDecoration(
                          hintText: '粘贴 PC 上的二维码文本',
                          helperText: '支持直接粘贴，解析前会自动去除空格和换行',
                          border: OutlineInputBorder(),
                        ),
                      ),
                      Row(
                        mainAxisAlignment: MainAxisAlignment.end,
                        children: [
                          TextButton.icon(
                            onPressed: connecting
                                ? null
                                : () async {
                                    final data = await Clipboard.getData(
                                      Clipboard.kTextPlain,
                                    );
                                    final text = data?.text;
                                    if (!context.mounted || text == null) {
                                      return;
                                    }
                                    final cleaned = _cleanManualCode(text);
                                    _manualCode.value = TextEditingValue(
                                      text: cleaned,
                                      selection: TextSelection.collapsed(
                                          offset: cleaned.length),
                                    );
                                    setDialogState(() {
                                      parsed = null;
                                      desktopFingerprint = null;
                                      parseError = null;
                                    });
                                  },
                            icon: const Icon(Icons.content_paste),
                            label: const Text('粘贴'),
                          ),
                          TextButton(
                            onPressed: connecting
                                ? null
                                : () {
                                    _manualCode.clear();
                                    setDialogState(() {
                                      parsed = null;
                                      desktopFingerprint = null;
                                      parseError = null;
                                    });
                                  },
                            child: const Text('清空'),
                          ),
                        ],
                      ),
                      if (parsing || connecting) ...[
                        const SizedBox(height: 8),
                        const LinearProgressIndicator(),
                        const SizedBox(height: 8),
                        Text(
                          parsing ? '正在解析连接码…' : '正在连接电脑…',
                          textAlign: TextAlign.center,
                          style: const TextStyle(color: Colors.grey),
                        ),
                      ],
                      if (parseError != null && !parsing) ...[
                        const SizedBox(height: 8),
                        Text(
                          parseError!,
                          style: const TextStyle(color: Colors.red),
                        ),
                      ],
                      if (parsed != null && !connecting) ...[
                        const SizedBox(height: 12),
                        Card(
                          margin: EdgeInsets.zero,
                          child: Padding(
                            padding: const EdgeInsets.all(12),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                const Text(
                                  '连接信息预览',
                                  style: TextStyle(fontWeight: FontWeight.bold),
                                ),
                                const SizedBox(height: 8),
                                Text('电脑地址：${parsed!.host.join('、')}'),
                                Text('端口：${parsed!.port}'),
                                if (desktopFingerprint != null)
                                  SelectableText(
                                    '桌面指纹：$desktopFingerprint',
                                    style: const TextStyle(
                                      fontFamily: 'monospace',
                                    ),
                                  ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              actions: [
                TextButton(
                  onPressed:
                      connecting ? null : () => Navigator.pop(dialogContext),
                  child: const Text('取消'),
                ),
                OutlinedButton(
                  onPressed: parsing || connecting ? null : parseCode,
                  child: const Text('解析连接码'),
                ),
                FilledButton(
                  onPressed: canConnect ? connect : null,
                  child: connecting
                      ? const SizedBox(
                          height: 18,
                          width: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Text('开始连接'),
                ),
              ],
            );
          },
        );
      },
    );

    if (!mounted) return;
    setState(() => _manual = false);
    if (!_pairing &&
        _result == null &&
        _error == null &&
        _appResumed &&
        !_handled) {
      unawaited(_startScanner());
    }
  }

  Widget _errorView() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: SingleChildScrollView(
          child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, color: Colors.red, size: 56),
            const SizedBox(height: 12),
            Text(_error!, textAlign: TextAlign.center),
            if (_diag != null) ...[
              const SizedBox(height: 16),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: SelectableText(
                  _diag!,
                  style: const TextStyle(
                    fontSize: 12,
                    fontFamily: 'monospace',
                    color: Colors.black54,
                  ),
                ),
              ),
            ],
            Builder(builder: (ctx) {
              final log = AppScope.of(ctx).connection.pairLog;
              if (log.isEmpty) return const SizedBox.shrink();
              return Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SizedBox(height: 16),
                  Row(children: [
                    const Text('配对日志',
                        style: TextStyle(fontWeight: FontWeight.bold)),
                    const Spacer(),
                    TextButton.icon(
                      onPressed: () async {
                        await Clipboard.setData(
                            ClipboardData(text: log.join('\n')));
                        if (ctx.mounted) {
                          ScaffoldMessenger.of(ctx).showSnackBar(
                              const SnackBar(content: Text('日志已复制到剪贴板')));
                        }
                      },
                      icon: const Icon(Icons.copy, size: 16),
                      label: const Text('复制'),
                    ),
                  ]),
                  Container(
                    width: double.infinity,
                    constraints: const BoxConstraints(maxHeight: 200),
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.05),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: SingleChildScrollView(
                      child: SelectableText(
                        log.join('\n'),
                        style: const TextStyle(
                          fontSize: 12,
                          fontFamily: 'monospace',
                          color: Colors.black54,
                        ),
                      ),
                    ),
                  ),
                ],
              );
            }),
            const SizedBox(height: 24),
            FilledButton(
              onPressed: () {
                setState(() {
                  _error = null;
                  _diag = null;
                  _handled = false;
                  _manual = false;
                });
                WidgetsBinding.instance.addPostFrameCallback((_) {
                  if (mounted) unawaited(_startScanner());
                });
              },
              child: const Text('重新扫码'),
            ),
          ],
        ),
        ),
      ),
    );
  }

  Widget _confirmView(PairResult r) {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 460),
        child: ListView(
          shrinkWrap: true,
          padding: const EdgeInsets.all(24),
          children: [
            const Icon(Icons.verified_user, color: Colors.green, size: 56),
            const SizedBox(height: 12),
            Text('核对指纹', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 8),
            const Text('为防中间人，请两端目视核对以下指纹一致：'),
            const SizedBox(height: 20),
            _fpCard('桌面指纹（应与 PC 屏幕一致）', r.desktopFingerprint,
                Icons.desktop_windows),
            const SizedBox(height: 12),
            _fpCard(
                '本机指纹（在 PC 上核对后点「接受」）', r.phoneFingerprint, Icons.smartphone),
            const SizedBox(height: 24),
            const Text(
              '在 PC 上确认「本机指纹」与这里一致后，点 PC 的接受。'
              '配对完成后即可回到账户列表注入。',
              style: TextStyle(color: Colors.grey),
            ),
            const SizedBox(height: 24),
            FilledButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('完成'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _fpCard(String label, String fp, IconData icon) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            Icon(icon),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label,
                      style: const TextStyle(fontSize: 12, color: Colors.grey)),
                  const SizedBox(height: 4),
                  SelectableText(
                    fp,
                    style: const TextStyle(
                      fontSize: 20,
                      fontFamily: 'monospace',
                      letterSpacing: 1.5,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
