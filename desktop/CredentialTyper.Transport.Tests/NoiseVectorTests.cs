using CredentialTyper.Transport.Crypto;

namespace CredentialTyper.Transport.Tests;

/// <summary>
/// 用 Noise 官方 cacophony 测试向量验证握手实现的字节级正确性。
/// 向量前缀 prologue = "John Galt"（仅测试用，与生产环境的 prologue 不同）。
/// 两端注入固定临时密钥（FixedEphemeralPrivate）以复现确定性的密文。
/// </summary>
public class NoiseVectorTests
{
    // —— 官方向量密钥（hex）——
    private const string InitStatic   = "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1";
    private const string InitEph      = "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a";
    private const string InitRemoteS  = "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62";
    private const string RespStatic   = "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893";
    private const string RespEph      = "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b";

    private const string Payload0Hex = "4c756477696720766f6e204d69736573"; // "Ludwig von Mises"
    private const string Payload1Hex = "4d757272617920526f746862617264";   // "Murray Rothbard"

    private static readonly byte[] Prologue = Convert.FromHexString("4a6f686e2047616c74"); // "John Galt"

    private static byte[] Hex(string s) => Convert.FromHexString(s);
    private static string Hx(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Fact]
    public void KK_Matches_Official_Vector()
    {
        var initStatic = Dh.FromPrivate(Hex(InitStatic));
        var respStatic = Dh.FromPrivate(Hex(RespStatic));

        // KK：双方都预先知道对端静态公钥。
        var init = new HandshakeState(HandshakeState.Pattern.KK, initiator: true,
            Prologue, initStatic, remoteStatic: respStatic.Public) { FixedEphemeralPrivate = Hex(InitEph) };
        var resp = new HandshakeState(HandshakeState.Pattern.KK, initiator: false,
            Prologue, respStatic, remoteStatic: initStatic.Public) { FixedEphemeralPrivate = Hex(RespEph) };

        // msg0：发起方 -> 响应方
        var msg0 = init.WriteMessage(Hex(Payload0Hex), out _);
        Assert.Equal(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440177015efc1fe7a37c629af7120a96274e6ab7afcc9261901d0e09ae32a5bb96",
            Hx(msg0));
        var got0 = resp.ReadMessage(msg0, out _);
        Assert.Equal(Payload0Hex, Hx(got0));

        // msg1：响应方 -> 发起方（此消息后握手结束，双方派生 transport）
        var msg1 = resp.WriteMessage(Hex(Payload1Hex), out var respTransport);
        Assert.Equal(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843b274d3429adc47ca093ba63ef90f8da89fda108db471dccfa4894aa7b00003",
            Hx(msg1));
        var got1 = init.ReadMessage(msg1, out var initTransport);
        Assert.Equal(Payload1Hex, Hx(got1));

        // handshake_hash 两端一致且匹配向量
        Assert.Equal("24c6b51ecb76277140ca018b5985bc9f03de321dae2d34dcae433dafef0131d9", Hx(init.HandshakeHash));
        Assert.Equal(Hx(init.HandshakeHash), Hx(resp.HandshakeHash));

        Assert.NotNull(initTransport);
        Assert.NotNull(respTransport);
    }

    [Fact]
    public void IK_Matches_Official_Vector()
    {
        var initStatic = Dh.FromPrivate(Hex(InitStatic));
        var respStatic = Dh.FromPrivate(Hex(RespStatic));

        // IK：发起方通过二维码已知响应方静态公钥；响应方在握手中才学到发起方静态。
        var init = new HandshakeState(HandshakeState.Pattern.IK, initiator: true,
            Prologue, initStatic, remoteStatic: respStatic.Public) { FixedEphemeralPrivate = Hex(InitEph) };
        var resp = new HandshakeState(HandshakeState.Pattern.IK, initiator: false,
            Prologue, respStatic, remoteStatic: null) { FixedEphemeralPrivate = Hex(RespEph) };

        var msg0 = init.WriteMessage(Hex(Payload0Hex), out _);
        Assert.Equal(
            "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7",
            Hx(msg0));
        var got0 = resp.ReadMessage(msg0, out _);
        Assert.Equal(Payload0Hex, Hx(got0));

        // 响应方应在握手中学到发起方静态公钥
        Assert.Equal(Hx(initStatic.Public), Hx(resp.RemoteStaticPublic));

        var msg1 = resp.WriteMessage(Hex(Payload1Hex), out var respTransport);
        Assert.Equal(
            "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5",
            Hx(msg1));
        var got1 = init.ReadMessage(msg1, out var initTransport);
        Assert.Equal(Payload1Hex, Hx(got1));

        Assert.Equal("0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7", Hx(init.HandshakeHash));
        Assert.Equal(Hx(init.HandshakeHash), Hx(resp.HandshakeHash));

        Assert.NotNull(initTransport);
        Assert.NotNull(respTransport);
    }

    [Fact]
    public void RoundTrip_Transport_Is_Bidirectional()
    {
        // 用随机密钥跑一次 IK，然后验证派生的 transport 双向收发一致。
        var initStatic = Dh.Generate();
        var respStatic = Dh.Generate();

        var init = new HandshakeState(HandshakeState.Pattern.IK, initiator: true,
            Prologue, initStatic, remoteStatic: respStatic.Public);
        var resp = new HandshakeState(HandshakeState.Pattern.IK, initiator: false,
            Prologue, respStatic, remoteStatic: null);

        var m0 = init.WriteMessage(Array.Empty<byte>(), out _);
        resp.ReadMessage(m0, out _);
        var m1 = resp.WriteMessage(Array.Empty<byte>(), out var respT);
        init.ReadMessage(m1, out var initT);

        Assert.NotNull(initT);
        Assert.NotNull(respT);

        // 发起方发 → 响应方收
        var ad = Array.Empty<byte>();
        var plain = System.Text.Encoding.UTF8.GetBytes("中文密码🔐");
        var ct = initT!.Value.Send.EncryptWithAd(ad, plain);
        var dec = respT!.Value.Recv.DecryptWithAd(ad, ct);
        Assert.Equal(Hx(plain), Hx(dec));

        // 响应方发 → 发起方收
        var plain2 = System.Text.Encoding.UTF8.GetBytes("pong");
        var ct2 = respT.Value.Send.EncryptWithAd(ad, plain2);
        var dec2 = initT.Value.Recv.DecryptWithAd(ad, ct2);
        Assert.Equal(Hx(plain2), Hx(dec2));
    }
}
