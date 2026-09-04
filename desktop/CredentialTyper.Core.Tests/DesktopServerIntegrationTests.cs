using System.Net.Sockets;
using System.Text;
using CredentialTyper.Core.Input;
using CredentialTyper.Core.Service;
using CredentialTyper.Transport.Crypto;
using CredentialTyper.Transport.Wire;
using Xunit;

namespace CredentialTyper.Core.Tests;

/// <summary>
/// 桌面服务端到端集成：真 TCP（回环）+ 真 Noise 握手 + 真分帧 + fill 派发。
/// 用 InjectorOverride 捕获解密后的明文，断言整条管线把密码原样送达（不做真实注入，
/// 真实注入的可行性已由 Check GUI 在实机验证）。
/// </summary>
public class DesktopServerIntegrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ct-test-" + Guid.NewGuid().ToString("N"));

    private static async Task<T> WithTimeout<T>(Task<T> task, int ms = 5000)
    {
        if (await Task.WhenAny(task, Task.Delay(ms)) != task)
            throw new TimeoutException("操作超时");
        return await task;
    }

    private static async Task WithTimeout(Task task, int ms = 5000)
    {
        if (await Task.WhenAny(task, Task.Delay(ms)) != task)
            throw new TimeoutException("操作超时");
        await task;
    }

    private (DesktopServer Server, TaskCompletionSource<(byte[] Bytes, bool Enter)> Captured) StartServer()
    {
        var identity = DesktopIdentity.LoadOrCreate(_dir);
        var pairing = new PairingStore(_dir);
        var captured = new TaskCompletionSource<(byte[], bool)>(TaskCreationOptions.RunContinuationsAsynchronously);

        var server = new DesktopServer(identity, pairing)
        {
            OnPairingRequest = (_, _) => Task.FromResult(true),   // 测试自动接受
            InjectorOverride = (mem, enter) =>
            {
                captured.TrySetResult((mem.ToArray(), enter));
                return CredentialInjector.Path.MessageWmChar;
            },
        };
        server.Start(0);
        return (server, captured);
    }

    private static async Task<Session> PhonePairAsync(DesktopServer server, Dh.KeyPair phone, QrPayload qr)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Port);
        tcp.NoDelay = true;
        var stream = tcp.GetStream();
        await stream.WriteAsync(new[] { Protocol.ConnectMode.Pair });
        return await Handshake.InitiatorPairAsync(stream, phone, qr.SPubBytes, qr.CodeBytes);
    }

    private static async Task<Session> PhoneReconnectAsync(DesktopServer server, Dh.KeyPair phone)
    {
        var tcp = new TcpClient();
        await tcp.ConnectAsync(System.Net.IPAddress.Loopback, server.Port);
        tcp.NoDelay = true;
        var stream = tcp.GetStream();
        await stream.WriteAsync(new[] { Protocol.ConnectMode.Reconnect });
        return await Handshake.InitiatorReconnectAsync(stream, phone, server.DesktopPublicKey);
    }

    private static async Task SendFillAsync(Session session, string text, bool enter)
    {
        var pw = Encoding.UTF8.GetBytes(text);
        var frame = new byte[2 + pw.Length];
        frame[0] = Session.Tag.Fill;
        frame[1] = (byte)(enter ? 0x01 : 0x00);
        pw.CopyTo(frame, 2);
        await session.SendAsync(frame);
    }

    [Fact]
    public async Task Pair_Then_Fill_Delivers_Exact_Plaintext()
    {
        var (server, captured) = StartServer();
        using var _ = server;
        var phone = Dh.Generate();
        var qr = server.OpenPairing();

        var session = await WithTimeout(PhonePairAsync(server, phone, qr));
        const string secret = "P@ss中文🔐!#$";
        await SendFillAsync(session, secret, enter: true);

        var (bytes, enterFlag) = await WithTimeout(captured.Task);
        Assert.Equal(secret, Encoding.UTF8.GetString(bytes));
        Assert.True(enterFlag);

        session.Dispose();
    }

    [Fact]
    public async Task Reconnect_After_Pairing_Also_Delivers_Fill()
    {
        // 先配对（让 PairingStore 落库手机公钥）
        var (server, captured1) = StartServer();
        using var _ = server;
        var phone = Dh.Generate();
        var qr = server.OpenPairing();
        var s1 = await WithTimeout(PhonePairAsync(server, phone, qr));
        await SendFillAsync(s1, "first", false);
        await WithTimeout(captured1.Task);
        s1.Dispose();

        // 重连（KK，双方已知静态）——需要新的捕获点
        var captured2 = new TaskCompletionSource<(byte[], bool)>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.InjectorOverride = (mem, enter) =>
        {
            captured2.TrySetResult((mem.ToArray(), enter));
            return CredentialInjector.Path.MessageWmChar;
        };

        var s2 = await WithTimeout(PhoneReconnectAsync(server, phone));
        await SendFillAsync(s2, "reconnected-秘密", false);
        var (bytes, _) = await WithTimeout(captured2.Task);
        Assert.Equal("reconnected-秘密", Encoding.UTF8.GetString(bytes));
        s2.Dispose();
    }

    [Fact]
    public async Task Reconnect_With_Wrong_Identity_Is_Rejected()
    {
        var (server, _) = StartServer();
        using var _ = server;
        var phone = Dh.Generate();
        var qr = server.OpenPairing();
        (await WithTimeout(PhonePairAsync(server, phone, qr))).Dispose();

        // 冒充者用不同静态密钥重连，桌面 KK 校验应失败并断开
        var imposter = Dh.Generate();
        await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            var s = await WithTimeout(PhoneReconnectAsync(server, imposter));
            // 桌面握手失败会关连接；这里发一帧应触发异常
            await SendFillAsync(s, "x", false);
            await WithTimeout(s.ReceiveAsync());
        });
    }

    [Fact]
    public async Task Refreshing_Qr_Invalidates_InFlight_Request_But_New_Qr_Works()
    {
        // A QR refresh is a normal operation when moving the phone to a new
        // computer.  The old implementation shared the mutable pairing-code
        // array with the handshake and could either mix the wrong code or
        // accept a request from an obsolete QR.  Hold the confirmation dialog
        // open to deterministically exercise that race.
        var (server, _) = StartServer();
        using var _ = server;
        var phone = Dh.Generate();
        var qr1 = server.OpenPairing();

        var requestSeen = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var allowRequest = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        server.OnPairingRequest = async (_, _) =>
        {
            requestSeen.TrySetResult(true);
            return await allowRequest.Task;
        };

        var firstPhoneSessionTask = PhonePairAsync(server, phone, qr1);
        await WithTimeout(requestSeen.Task);

        // Rotate the QR while the first handshake is waiting for user
        // confirmation.  The first request must not be persisted.
        var qr2 = server.OpenPairing();
        allowRequest.SetResult(true);
        var firstPhoneSession = await WithTimeout(firstPhoneSessionTask);
        firstPhoneSession.Dispose();
        Assert.True(server.IsPairingOpen);
        Assert.False(File.Exists(Path.Combine(_dir, "pairing.json")));

        // The newly displayed QR remains usable and should be the one that is
        // committed to the pairing store.
        server.OnPairingRequest = (_, _) => Task.FromResult(true);
        var secondPhoneSession = await WithTimeout(PhonePairAsync(server, phone, qr2));
        for (var i = 0; i < 20 && !server.IsPhoneConnected; i++)
            await Task.Delay(10);
        Assert.True(server.IsPhoneConnected);
        Assert.False(server.IsPairingOpen);
        secondPhoneSession.Dispose();
    }

    [Fact]
    public void Pairing_Window_State_Is_Explicit_And_Stable()
    {
        var (server, _) = StartServer();
        using var _ = server;

        Assert.False(server.IsPairingOpen);
        server.OpenPairing();
        Assert.True(server.IsPairingOpen);
        server.ClosePairing();
        Assert.False(server.IsPairingOpen);
    }

    [Fact]
    public void Start_Uses_Next_Port_When_Requested_Port_Is_Occupied()
    {
        // An older tray instance may still own the well-known port while the
        // user launches the new build.  The server should move to the next
        // port and put that actual value in the QR instead of leaving the UI
        // attached to a stale process.
        // Bind the wildcard address as DesktopServer does; a loopback-only
        // listener can coexist with a wildcard listener on Windows.
        using var blocker = new TcpListener(System.Net.IPAddress.Any, 0);
        blocker.Start();
        var requested = ((System.Net.IPEndPoint)blocker.LocalEndpoint).Port;

        var identity = DesktopIdentity.LoadOrCreate(_dir);
        var pairing = new PairingStore(_dir);
        using var server = new DesktopServer(identity, pairing);
        server.Start(requested);

        Assert.NotEqual(requested, server.Port);
        Assert.InRange(server.Port, 1, 65535);
    }

    [Fact]
    public async Task AccountImport_ClearsPassword_WhenDisconnected()
    {
        var (server, _) = StartServer();
        using var _ = server;
        var password = Encoding.UTF8.GetBytes("temporary-secret");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            server.SendAccountImportAsync("title", "user", "example.com", "note", password));

        Assert.All(password, b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData("vEthernet (WSL (Hyper-V firewall))", "")]
    [InlineData("docker0", "Docker Desktop")]
    [InlineData("VMware Network Adapter VMnet8", "VMware")]
    [InlineData("本地连接* 6", "WAN Miniport (IP)")]
    [InlineData("Ethernet", "Realtek PCIe GbE Family Controller")]
    public void LocalAddress_Classifier_Excludes_Virtual_Adapters(
        string name, string description)
    {
        var expected = name.Contains("vEthernet", StringComparison.OrdinalIgnoreCase) ||
                       name.Contains("docker", StringComparison.OrdinalIgnoreCase) ||
                       name.Contains("vmware", StringComparison.OrdinalIgnoreCase) ||
                       description.Contains("WAN Miniport", StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expected, LocalAddresses.IsVirtualInterfaceName(name, description));
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }
}
