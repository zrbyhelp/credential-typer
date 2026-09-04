using CredentialTyper.Transport.Crypto;

namespace CredentialTyper.Transport.Wire;

/// <summary>
/// 把 <see cref="HandshakeState"/> 跑在一条 Stream 上，握手成功后产出 <see cref="Session"/>。
/// 手机是发起方（initiator），桌面是响应方（responder）；两种模式：
///   配对 = IK（手机已从二维码知道桌面静态公钥）
///   重连 = KK（双方静态公钥都已存）
/// 握手消息 payload 一律为空。
/// </summary>
public static class Handshake
{
    /// <summary>握手成功但对端静态公钥与预期不符时抛出（防冒充）。</summary>
    public sealed class IdentityMismatchException(string message) : Exception(message);

    // —— 桌面（responder）——

    /// <summary>配对：桌面作 IK 响应方。返回会话与学到的手机静态公钥（供指纹核对与落库）。</summary>
    public static async Task<(Session Session, byte[] RemoteStatic)> ResponderPairAsync(
        Stream stream, Dh.KeyPair localStatic, byte[] pairingCode, CancellationToken ct = default)
    {
        var hs = new HandshakeState(HandshakeState.Pattern.IK, initiator: false,
            Protocol.PairingPrologue(pairingCode), localStatic, remoteStatic: null);

        var msg1 = await Frame.ReadAsync(stream, ct: ct).ConfigureAwait(false);
        hs.ReadMessage(msg1, out _);

        var msg2 = hs.WriteMessage(Array.Empty<byte>(), out var transport);
        await Frame.WriteAsync(stream, msg2, ct).ConfigureAwait(false);

        var (send, recv) = transport!.Value;
        return (new Session(stream, send, recv), hs.RemoteStaticPublic);
    }

    /// <summary>重连：桌面作 KK 响应方，校验对端静态公钥与库里一致。</summary>
    public static async Task<Session> ResponderReconnectAsync(
        Stream stream, Dh.KeyPair localStatic, byte[] expectedRemoteStatic, CancellationToken ct = default)
    {
        var hs = new HandshakeState(HandshakeState.Pattern.KK, initiator: false,
            Protocol.ReconnectPrologue(), localStatic, remoteStatic: expectedRemoteStatic);

        var msg1 = await Frame.ReadAsync(stream, ct: ct).ConfigureAwait(false);
        hs.ReadMessage(msg1, out _);

        var msg2 = hs.WriteMessage(Array.Empty<byte>(), out var transport);
        await Frame.WriteAsync(stream, msg2, ct).ConfigureAwait(false);

        var (send, recv) = transport!.Value;
        return new Session(stream, send, recv);
    }

    // —— 手机（initiator）：C# 参考实现，供端到端测试；Flutter 端另行实现同协议 ——

    public static async Task<Session> InitiatorPairAsync(
        Stream stream, Dh.KeyPair localStatic, byte[] remoteStatic, byte[] pairingCode,
        CancellationToken ct = default)
    {
        var hs = new HandshakeState(HandshakeState.Pattern.IK, initiator: true,
            Protocol.PairingPrologue(pairingCode), localStatic, remoteStatic);

        var msg1 = hs.WriteMessage(Array.Empty<byte>(), out _);
        await Frame.WriteAsync(stream, msg1, ct).ConfigureAwait(false);

        var msg2 = await Frame.ReadAsync(stream, ct: ct).ConfigureAwait(false);
        hs.ReadMessage(msg2, out var transport);

        var (send, recv) = transport!.Value;
        return new Session(stream, send, recv);
    }

    public static async Task<Session> InitiatorReconnectAsync(
        Stream stream, Dh.KeyPair localStatic, byte[] remoteStatic, CancellationToken ct = default)
    {
        var hs = new HandshakeState(HandshakeState.Pattern.KK, initiator: true,
            Protocol.ReconnectPrologue(), localStatic, remoteStatic);

        var msg1 = hs.WriteMessage(Array.Empty<byte>(), out _);
        await Frame.WriteAsync(stream, msg1, ct).ConfigureAwait(false);

        var msg2 = await Frame.ReadAsync(stream, ct: ct).ConfigureAwait(false);
        hs.ReadMessage(msg2, out var transport);

        var (send, recv) = transport!.Value;
        return new Session(stream, send, recv);
    }
}
