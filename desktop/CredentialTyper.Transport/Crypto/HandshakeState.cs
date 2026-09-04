using System.Text;

namespace CredentialTyper.Transport.Crypto;

/// <summary>
/// Noise 握手状态机，支持本项目用到的两种模式：
///   IK（配对，发起方已通过二维码知道响应方静态公钥）
///   KK（重连，双方静态公钥都已知）
/// 只实现这两种模式所需的 token：e s ee es se ss。不含 PSK。
/// </summary>
public sealed class HandshakeState
{
    private const int DhLen = 32;

    public enum Pattern { IK, KK }

    private readonly SymmetricState _ss = new();
    private readonly bool _initiator;

    private Dh.KeyPair? _s;    // 本地静态
    private Dh.KeyPair? _e;    // 本地临时
    private byte[]? _rs;       // 对端静态公钥
    private byte[]? _re;       // 对端临时公钥

    /// <summary>仅测试用：注入固定临时密钥以复现 Noise 官方测试向量。生产环境保持 null（每次随机生成）。</summary>
    internal byte[]? FixedEphemeralPrivate { get; set; }

    private readonly Queue<string[]> _messagePatterns;

    public HandshakeState(
        Pattern pattern,
        bool initiator,
        byte[] prologue,
        Dh.KeyPair localStatic,
        byte[]? remoteStatic)
    {
        _initiator = initiator;
        _s = localStatic;
        _rs = remoteStatic;

        string name = pattern == Pattern.IK
            ? "Noise_IK_25519_ChaChaPoly_SHA256"
            : "Noise_KK_25519_ChaChaPoly_SHA256";

        _ss.InitializeSymmetric(name);
        _ss.MixHash(prologue);

        // 预消息：按 -> 行（发起方静态）、<- 行（响应方静态）的顺序 MixHash 公钥。
        // 两端都知道涉及的公钥，算出的 h 一致。
        (byte[]? initiatorStatic, byte[]? responderStatic) pre = pattern switch
        {
            // IK: 只有 "<- s"（响应方静态）
            Pattern.IK => (null, initiator ? _rs : _s!.Public),
            // KK: "-> s" 然后 "<- s"
            Pattern.KK => (initiator ? _s!.Public : _rs,
                           initiator ? _rs : _s!.Public),
            _ => (null, null),
        };
        if (pre.initiatorStatic is not null) _ss.MixHash(pre.initiatorStatic);
        if (pre.responderStatic is not null) _ss.MixHash(pre.responderStatic);

        _messagePatterns = new Queue<string[]>(pattern switch
        {
            Pattern.IK => new[]
            {
                new[] { "e", "es", "s", "ss" },   // msg1 发起方
                new[] { "e", "ee", "se" },        // msg2 响应方
            },
            Pattern.KK => new[]
            {
                new[] { "e", "es", "ss" },        // msg1 发起方
                new[] { "e", "ee", "se" },        // msg2 响应方
            },
            _ => Array.Empty<string[]>(),
        });
    }

    public byte[] RemoteStaticPublic => _rs ?? throw new InvalidOperationException("对端静态公钥尚未获得");
    public byte[] HandshakeHash => _ss.Handshakehash;

    /// <summary>写一条握手消息；若这是最后一条，out 返回派生的收发 CipherState。</summary>
    public byte[] WriteMessage(ReadOnlySpan<byte> payload, out (CipherState Send, CipherState Recv)? transport)
    {
        var tokens = _messagePatterns.Dequeue();
        var buffer = new List<byte>();

        foreach (var token in tokens)
        {
            switch (token)
            {
                case "e":
                    _e = FixedEphemeralPrivate is null ? Dh.Generate() : Dh.FromPrivate(FixedEphemeralPrivate);
                    buffer.AddRange(_e.Public);
                    _ss.MixHash(_e.Public);
                    break;
                case "s":
                    buffer.AddRange(_ss.EncryptAndHash(_s!.Public));
                    break;
                default:
                    _ss.MixKey(DhToken(token));
                    break;
            }
        }

        buffer.AddRange(_ss.EncryptAndHash(payload));
        transport = _messagePatterns.Count == 0 ? Finish() : null;
        return buffer.ToArray();
    }

    /// <summary>读一条握手消息；若这是最后一条，out 返回派生的收发 CipherState。</summary>
    public byte[] ReadMessage(ReadOnlySpan<byte> message, out (CipherState Send, CipherState Recv)? transport)
    {
        var tokens = _messagePatterns.Dequeue();
        int offset = 0;

        foreach (var token in tokens)
        {
            switch (token)
            {
                case "e":
                    _re = message.Slice(offset, DhLen).ToArray();
                    offset += DhLen;
                    _ss.MixHash(_re);
                    break;
                case "s":
                    int len = DhLen + 16;   // 握手中传 s 时一定已有密钥，带 16 字节标签
                    _rs = _ss.DecryptAndHash(message.Slice(offset, len));
                    offset += len;
                    break;
                default:
                    _ss.MixKey(DhToken(token));
                    break;
            }
        }

        var payload = _ss.DecryptAndHash(message[offset..]);
        transport = _messagePatterns.Count == 0 ? Finish() : null;
        return payload;
    }

    private byte[] DhToken(string token) => token switch
    {
        "ee" => Dh.Agree(_e!.Private, _re!),
        "ss" => Dh.Agree(_s!.Private, _rs!),
        "es" => _initiator ? Dh.Agree(_e!.Private, _rs!) : Dh.Agree(_s!.Private, _re!),
        "se" => _initiator ? Dh.Agree(_s!.Private, _re!) : Dh.Agree(_e!.Private, _rs!),
        _ => throw new InvalidOperationException($"未知 DH token: {token}"),
    };

    // 发起方：先发后收 → (send=c1, recv=c2)；响应方相反。
    private (CipherState Send, CipherState Recv) Finish()
    {
        var (c1, c2) = _ss.Split();
        return _initiator ? (c1, c2) : (c2, c1);
    }

    public static byte[] Prologue(string baseStr, ReadOnlySpan<byte> extra)
    {
        var b = Encoding.ASCII.GetBytes(baseStr);
        var buf = new byte[b.Length + extra.Length];
        b.CopyTo(buf, 0);
        extra.CopyTo(buf.AsSpan(b.Length));
        return buf;
    }
}
