using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using CredentialTyper.Core.Automation;
using CredentialTyper.Core.Input;
using CredentialTyper.Transport.Wire;

namespace CredentialTyper.Core.Service;

/// <summary>
/// 桌面端 LAN 服务：监听 TCP，按连接前导分流到配对（IK）或重连（KK）握手，
/// 握手成功后进入加密会话 —— 一边周期上报焦点上下文，一边接收手机的 fill 指令并注入。
///
/// 线程/边界：
/// - 每条连接一个 Task，互不影响；
/// - 焦点上报在线程池（MTA）线程里跑 FlaUI；
/// - fill 帧解密后就地注入并 <see cref="CryptographicOperations.ZeroMemory"/>，密码不进 string、不落盘。
/// </summary>
public sealed class DesktopServer : IDisposable
{
    private readonly DesktopIdentity _identity;
    private readonly PairingStore _pairing;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    // Pairing state is changed by the UI thread while handshake tasks run on
    // thread-pool threads. Keep the code and its generation under one lock so
    // a QR refresh can never mutate the byte buffer currently used by a
    // handshake.
    private readonly object _pairingGate = new();
    private bool _pairingOpen;
    private long _pairingGeneration;
    private byte[]? _pairingCode;
    private volatile Session? _activeSession;

    public int Port { get; private set; }

    /// <summary>收到配对握手后回调：参数是手机静态公钥，UI 显示其指纹让用户核对，返回是否接受。</summary>
    public Func<byte[], CancellationToken, Task<bool>>? OnPairingRequest;
    /// <summary>配对落库后触发（可用于关闭二维码界面）。</summary>
    public Action? OnPaired;
    /// <summary>非敏感日志（绝不会带密码）。</summary>
    public Action<string>? OnLog;
    /// <summary>一次注入完成，报告走了哪条路径（诊断用）。</summary>
    public Action<CredentialInjector.Path>? OnInjected;

    /// <summary>
    /// 注入实现的可替换钩子（仅测试用：捕获解密后的明文以验证整条管线）。
    /// 生产环境保持 null —— 走 <see cref="CredentialInjector"/> 的两层降级真注入。
    /// </summary>
    public Func<ReadOnlyMemory<byte>, bool, CredentialInjector.Path>? InjectorOverride;

    public DesktopServer(DesktopIdentity identity, PairingStore pairing)
    {
        _identity = identity;
        _pairing = pairing;
    }

    public void Start(int port = 0)
    {
        if (_listener is not null)
            throw new InvalidOperationException("桌面服务已经启动");

        // 47820 is the well-known/default port, but an older tray instance,
        // another copy of the app, or a security product can legitimately
        // occupy it.  A hard startup failure leaves the user looking at a QR
        // produced by the wrong process (the phone then reports EndOfStream).
        // Try a short deterministic range before giving up.  The actual port
        // is always written into the QR payload via the Port property.
        var candidates = port == 0
            ? new[] { 0 }
            : Enumerable.Range(port, 11).ToArray();
        SocketException? last = null;
        foreach (var candidate in candidates)
        {
            var listener = new TcpListener(IPAddress.Any, candidate);
            try
            {
                listener.Start();
                _listener = listener;
                _cts = new CancellationTokenSource();
                Port = ((IPEndPoint)listener.LocalEndpoint).Port;
                _ = AcceptLoopAsync(_cts.Token);
                return;
            }
            catch (SocketException ex)
            {
                last = ex;
                try { listener.Stop(); } catch { }
            }
        }

        throw new SocketException(last?.SocketErrorCode is { } code
            ? (int)code
            : (int)SocketError.AddressAlreadyInUse);
    }

    /// <summary>开启配对窗口，生成一次性 code，返回二维码载荷。</summary>
    public QrPayload OpenPairing()
    {
        byte[]? oldCode;
        QrPayload payload;
        lock (_pairingGate)
        {
            oldCode = _pairingCode;
            var code = Protocol.NewPairingCode();
            _pairingCode = code;
            _pairingOpen = true;
            _pairingGeneration++;

            // QrPayload.Create base64-encodes the code synchronously, so the
            // generated QR no longer aliases the mutable code buffer.
            payload = QrPayload.Create(
                _identity.Static.Public,
                LocalAddresses.LanIpv4(),
                Port,
                code);
        }

        if (oldCode is not null)
            CryptographicOperations.ZeroMemory(oldCode);
        return payload;
    }

    public void ClosePairing()
    {
        byte[]? oldCode;
        lock (_pairingGate)
        {
            _pairingOpen = false;
            _pairingGeneration++;
            oldCode = _pairingCode;
            _pairingCode = null;
        }
        if (oldCode is not null)
            CryptographicOperations.ZeroMemory(oldCode);
    }

    public byte[] DesktopPublicKey => _identity.Static.Public;
    public string DesktopFingerprint => Protocol.Fingerprint(_identity.Static.Public);
    public bool IsPhoneConnected => _activeSession is not null;

    /// <summary>
    /// Immediately closes the active phone session.  PairingStore is kept
    /// separate so callers can choose whether to keep or clear the pairing
    /// identity (the desktop UI uses this when the user clicks “取消连接”).
    /// </summary>
    public void DisconnectPhone()
    {
        var session = Interlocked.Exchange(ref _activeSession, null);
        if (session is not null)
        {
            try { session.Dispose(); } catch { /* best effort during teardown */ }
        }
    }

    /// <summary>当前是否有一个仍然有效的二维码配对窗口。</summary>
    public bool IsPairingOpen
    {
        get { lock (_pairingGate) return _pairingOpen && _pairingCode is not null; }
    }

    /// <summary>
    /// 取得当前二维码的不可变快照。调用方必须在使用完 [code] 后清零。
    /// </summary>
    private bool TryCapturePairing(out byte[] code, out long generation)
    {
        lock (_pairingGate)
        {
            if (!_pairingOpen || _pairingCode is null)
            {
                code = Array.Empty<byte>();
                generation = 0;
                return false;
            }

            code = (byte[])_pairingCode.Clone();
            generation = _pairingGeneration;
            return true;
        }
    }

    private bool IsCurrentPairing(long generation)
    {
        lock (_pairingGate)
            return _pairingOpen && _pairingCode is not null &&
                   _pairingGeneration == generation;
    }

    /// Sends a complete account to the currently connected phone. The caller's
    /// password buffer is cleared before returning.
    public async Task SendAccountImportAsync(string title, string username, string website, string note,
        byte[] password, CancellationToken ct = default)
    {
        byte[]? frame = null;
        try
        {
            var session = _activeSession ?? throw new InvalidOperationException("手机未连接");
            // Keep encoding inside the finally scope as well.  Boundary
            // validation can throw before a frame is produced (for example
            // an over-sized field); the caller's password buffer must still
            // be cleared on that path.
            frame = AccountImportFrame.Encode(title, username, website, note, password);
            await session.SendAsync(frame, ct).ConfigureAwait(false);
        }
        finally
        {
            if (frame is not null) CryptographicOperations.ZeroMemory(frame);
            CryptographicOperations.ZeroMemory(password);
        }
    }

    public async Task SendFilterSyncAsync(string query, CancellationToken ct = default)
    {
        var session = _activeSession ?? throw new InvalidOperationException("手机未连接");
        var frame = FilterSyncFrame.Encode(query);
        try { await session.SendAsync(frame, ct).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(frame); }
    }

    private void Log(string msg) => OnLog?.Invoke(msg);

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener!.AcceptTcpClientAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { Log($"接受连接失败: {e.Message}"); continue; }

            _ = HandleClientAsync(client, ct);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        {
            client.NoDelay = true;
            var remote = SafeRemote(client);
            var stream = client.GetStream();
            try
            {
                Log($"收到来自 {remote} 的连接");
                var mode = new byte[1];
                await ReadExactAsync(stream, mode, ct).ConfigureAwait(false);

                switch (mode[0])
                {
                    case Protocol.ConnectMode.Pair:
                        Log($"[{remote}] 前导=配对(IK)，进入配对握手");
                        await HandlePairingAsync(stream, ct); break;
                    case Protocol.ConnectMode.Reconnect:
                        Log($"[{remote}] 前导=重连(KK)，进入重连握手");
                        await HandleReconnectAsync(stream, ct); break;
                    default: Log($"[{remote}] 未知连接前导 0x{mode[0]:X2}，断开"); break;
                }
            }
            catch (Exception e)
            {
                Log($"[{remote}] 连接结束: {e.Message}");
            }
        }
    }

    private async Task HandlePairingAsync(NetworkStream stream, CancellationToken ct)
    {
        if (!TryCapturePairing(out var pairingCode, out var generation))
        {
            Log("当前不在配对窗口，拒绝配对连接（请在桌面端点“重新配对/刷新二维码”后重扫）");
            return;
        }

        try
        {
            // Use the cloned code, never the live UI-owned buffer. A QR
            // refresh while this handshake is in flight therefore cannot
            // alter the prologue half way through Noise.
            var (session, phonePub) = await Handshake.ResponderPairAsync(
                    stream, _identity.Static, pairingCode, ct)
                .ConfigureAwait(false);
            Log($"配对握手成功，手机指纹 {Protocol.Fingerprint(phonePub)}，等待桌面确认");

            // If the user refreshed the QR (or another phone completed
            // pairing) while we were handshaking, this request came from a
            // stale QR. Do not accept it or overwrite the new record.
            if (!IsCurrentPairing(generation))
            {
                Log("配对二维码已刷新，忽略旧请求");
                session.Dispose();
                return;
            }

            bool accept = OnPairingRequest is not null &&
                await OnPairingRequest(phonePub, ct).ConfigureAwait(false);
            if (!accept)
            {
                Log("配对未获确认，断开");
                session.Dispose();
                return;
            }

            // Re-check after the user confirmation dialog too: refreshing the
            // QR while the dialog is open must invalidate this request.
            if (!IsCurrentPairing(generation))
            {
                Log("配对二维码已刷新，忽略旧请求");
                session.Dispose();
                return;
            }

            _pairing.Save(phonePub);
            ClosePairing();
            OnPaired?.Invoke();
            Log($"配对成功（手机指纹 {Protocol.Fingerprint(phonePub)}），进入会话");
            await SessionLoopAsync(session, ct).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pairingCode);
        }
    }

    private async Task HandleReconnectAsync(NetworkStream stream, CancellationToken ct)
    {
        if (!_pairing.HasPaired)
        {
            Log("尚未配对任何手机，拒绝重连");
            return;
        }

        Session session;
        try
        {
            session = await Handshake.ResponderReconnectAsync(stream, _identity.Static, _pairing.PhonePublic, ct)
                .ConfigureAwait(false);
        }
        catch (CryptographicException)
        {
            Log("重连身份校验失败（对端静态公钥不符），断开");
            return;
        }

        Log("重连成功，进入会话");
        await SessionLoopAsync(session, ct).ConfigureAwait(false);
    }

    private async Task SessionLoopAsync(Session session, CancellationToken ct)
    {
        _activeSession = session;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var reporter = ReportFocusLoopAsync(session, linked.Token);
        try
        {
            while (!linked.IsCancellationRequested)
            {
                byte[] frame;
                try
                {
                    frame = await session.ReceiveAsync(linked.Token).ConfigureAwait(false);
                }
                catch (Exception e)
                {
                    Log($"会话读取结束: {e.Message}");
                    break;
                }

                await DispatchAsync(session, frame, linked.Token).ConfigureAwait(false);
            }
        }
        finally
        {
            if (ReferenceEquals(_activeSession, session)) _activeSession = null;
            linked.Cancel();
            try { await reporter.ConfigureAwait(false); } catch { /* 上报任务收尾异常忽略 */ }
            session.Dispose();
        }
    }

    private async Task DispatchAsync(Session session, byte[] frame, CancellationToken ct)
    {
        if (frame.Length == 0) return;

        switch (frame[0])
        {
            case Session.Tag.Ping:
                await session.SendPongAsync(ct).ConfigureAwait(false);
                break;

            case Session.Tag.Fill:
                InjectFill(frame);   // 同步：Span 不能跨 await
                break;

            default:
                CryptographicOperations.ZeroMemory(frame);   // 其余帧一律清零，保守起见
                break;
        }
    }

    /// <summary>注入一帧 fill。整帧含明文密码，无论成败都在返回前清零。</summary>
    private void InjectFill(byte[] frame)
    {
        bool enter = frame.Length > 1 && (frame[1] & 0x01) != 0;
        try
        {
            // 不复制：直接在 frame 上开一段视图（body 从下标 2 开始）。
            var body = new ReadOnlyMemory<byte>(frame, 2, Math.Max(0, frame.Length - 2));
            var path = InjectorOverride is not null
                ? InjectorOverride(body, enter)
                : CredentialInjector.TypeUtf8ToForegroundFocus(body.Span, enter);
            OnInjected?.Invoke(path);
            Log($"已注入（{path}，{(enter ? "含回车" : "不回车")}）");
        }
        catch (InjectionAbortedException ex)
        {
            Log($"注入中止: {ex.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frame);
        }
    }

    private Task ReportFocusLoopAsync(Session session, CancellationToken ct) => Task.Run(async () =>
    {
        using var locator = new FormLocator();
        string? lastSig = null;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var wc = WindowContext.CaptureForeground();
                var field = locator.CaptureFocused();
                var json = CtxMessage.Build(wc, field);
                if (json != lastSig)
                {
                    await session.SendCtxAsync(json, ct).ConfigureAwait(false);
                    lastSig = json;
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { Log($"焦点上报异常: {e.Message}"); }

            try { await Task.Delay(400, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
    }, ct);

    private static string SafeRemote(TcpClient client)
    {
        try { return client.Client.RemoteEndPoint?.ToString() ?? "未知"; }
        catch { return "未知"; }
    }

    private static async Task ReadExactAsync(Stream s, Memory<byte> buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf[read..], ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("连接在读取连接前导时被关闭");
            read += n;
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _listener?.Stop();
        DisconnectPhone();
        ClosePairing();
        _cts?.Dispose();
    }
}
