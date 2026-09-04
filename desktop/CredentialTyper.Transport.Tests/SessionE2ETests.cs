using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CredentialTyper.Transport.Crypto;
using CredentialTyper.Transport.Wire;

namespace CredentialTyper.Transport.Tests;

/// <summary>
/// 端到端会话测试：用回环 TCP 模拟「手机(发起方) ↔ 桌面(响应方)」，
/// 跑真握手、真分帧、真 ChaCha20-Poly1305，验证 Wire 层整体自洽。
/// </summary>
public class SessionE2ETests
{
    private static async Task<(NetworkStream Client, NetworkStream Server)> LoopbackPairAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var client = new TcpClient();
        var connectTask = client.ConnectAsync(IPAddress.Loopback, port);
        var server = await listener.AcceptTcpClientAsync();
        await connectTask;
        listener.Stop();

        client.NoDelay = server.NoDelay = true;
        return (client.GetStream(), server.GetStream());
    }

    [Fact]
    public async Task Pairing_Then_Fill_And_Ctx_RoundTrip()
    {
        var (cs, ss) = await LoopbackPairAsync();

        var phone = Dh.Generate();      // 手机静态
        var desktop = Dh.Generate();    // 桌面静态
        var code = Protocol.NewPairingCode();

        // 手机从二维码得到 desktop.Public 与 code；双方并行握手。
        var phoneTask = Handshake.InitiatorPairAsync(cs, phone, desktop.Public, code);
        var deskTask = Handshake.ResponderPairAsync(ss, desktop, code);

        var phoneSession = await phoneTask;
        var (deskSession, learnedPhonePub) = await deskTask;

        // 桌面应学到手机静态公钥（用于指纹核对与落库）
        Assert.Equal(Convert.ToHexString(phone.Public), Convert.ToHexString(learnedPhonePub));

        // 手机 → 桌面：fill（tag 0x04 | flags bit0=enter | UTF-8 密码）
        var pw = Encoding.UTF8.GetBytes("P@ss中文🔐");
        var fill = new byte[2 + pw.Length];
        fill[0] = Session.Tag.Fill;
        fill[1] = 0x01;                 // enter = true
        pw.CopyTo(fill, 2);
        await phoneSession.SendAsync(fill);

        var got = await deskSession.ReceiveAsync();
        Assert.Equal(Session.Tag.Fill, got[0]);
        Assert.Equal(0x01, got[1]);
        Assert.Equal(Convert.ToHexString(pw), Convert.ToHexString(got[2..]));

        // 桌面 → 手机：ctx JSON
        await deskSession.SendCtxAsync("""{"app":"chrome.exe","title":"登录","field":{"kind":"password","name":"密码"}}""");
        var ctx = await phoneSession.ReceiveAsync();
        Assert.Equal(Session.Tag.Ctx, ctx[0]);
        Assert.Contains("chrome.exe", Encoding.UTF8.GetString(ctx[1..]));

        // 手机 → 桌面：ping / 桌面 → 手机：pong
        await phoneSession.SendAsync(new[] { Session.Tag.Ping });
        var ping = await deskSession.ReceiveAsync();
        Assert.Equal(Session.Tag.Ping, ping[0]);
        await deskSession.SendPongAsync();
        var pong = await phoneSession.ReceiveAsync();
        Assert.Equal(Session.Tag.Pong, pong[0]);

        phoneSession.Dispose();
        deskSession.Dispose();
    }

    [Fact]
    public async Task Reconnect_KK_Works_When_Identities_Match()
    {
        var (cs, ss) = await LoopbackPairAsync();
        var phone = Dh.Generate();
        var desktop = Dh.Generate();

        var phoneTask = Handshake.InitiatorReconnectAsync(cs, phone, desktop.Public);
        var deskTask = Handshake.ResponderReconnectAsync(ss, desktop, phone.Public);

        var phoneSession = await phoneTask;
        var deskSession = await deskTask;

        await phoneSession.SendAsync(new[] { Session.Tag.Ping });
        var f = await deskSession.ReceiveAsync();
        Assert.Equal(Session.Tag.Ping, f[0]);

        phoneSession.Dispose();
        deskSession.Dispose();
    }

    [Fact]
    public async Task Reconnect_KK_Fails_When_Desktop_Expects_Wrong_Phone_Identity()
    {
        var (cs, ss) = await LoopbackPairAsync();
        var phone = Dh.Generate();
        var desktop = Dh.Generate();
        var imposter = Dh.Generate();   // 桌面库里存的是别的公钥

        var phoneTask = Handshake.InitiatorReconnectAsync(cs, phone, desktop.Public);
        var deskTask = Handshake.ResponderReconnectAsync(ss, desktop, imposter.Public);

        // KK 里静态公钥参与密钥派生，身份不符 → 桌面解 msg1 时认证失败抛出
        await Assert.ThrowsAnyAsync<CryptographicException>(async () => await deskTask);

        // 桌面失败后不会写 msg2；先关双方流，让手机端挂起的读取快速失败，避免死锁。
        cs.Dispose(); ss.Dispose();
        try { await phoneTask; } catch { /* 对端已断，发起方侧异常忽略 */ }
    }

    [Fact]
    public void Qr_Payload_Roundtrips()
    {
        var spub = RandomNumberGenerator.GetBytes(32);
        var code = Protocol.NewPairingCode();
        var qr = QrPayload.Create(spub, new[] { "192.168.1.20", "10.0.0.5" }, 47820, code);

        var text = qr.ToQrText();
        var back = QrPayload.FromQrText(text);

        Assert.Equal(1, back.Version);
        Assert.Equal(Convert.ToHexString(spub), Convert.ToHexString(back.SPubBytes));
        Assert.Equal(Convert.ToHexString(code), Convert.ToHexString(back.CodeBytes));
        Assert.Equal(47820, back.Port);
        Assert.Equal(new[] { "192.168.1.20", "10.0.0.5" }, back.Host);
    }

    [Fact]
    public void Fingerprint_Is_Stable_And_Grouped()
    {
        var pub = Convert.FromHexString("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62");
        var fp = Protocol.Fingerprint(pub);
        Assert.Matches(@"^[0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4} [0-9A-F]{4}$", fp);
        Assert.Equal(fp, Protocol.Fingerprint(pub)); // 稳定
    }
}
