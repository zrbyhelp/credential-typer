using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CredentialTyper.Transport.Crypto;

/// <summary>X25519 —— 生成密钥对、做原始 DH（Noise 的 MixKey 需要 32 字节原始结果）。</summary>
public static class Dh
{
    public const int KeyLen = 32;

    private static readonly SecureRandom Rng = new();

    public sealed class KeyPair
    {
        public required byte[] Private { get; init; }  // 32 字节
        public required byte[] Public { get; init; }   // 32 字节
    }

    public static KeyPair Generate()
    {
        var priv = new X25519PrivateKeyParameters(Rng);
        return new KeyPair { Private = priv.GetEncoded(), Public = priv.GeneratePublicKey().GetEncoded() };
    }

    public static KeyPair FromPrivate(byte[] priv32)
    {
        var priv = new X25519PrivateKeyParameters(priv32, 0);
        return new KeyPair { Private = priv.GetEncoded(), Public = priv.GeneratePublicKey().GetEncoded() };
    }

    /// <summary>DH(本地私钥, 对端公钥) → 32 字节共享秘密。</summary>
    public static byte[] Agree(byte[] localPrivate, byte[] remotePublic)
    {
        var agreement = new X25519Agreement();
        agreement.Init(new X25519PrivateKeyParameters(localPrivate, 0));
        var secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(new X25519PublicKeyParameters(remotePublic, 0), secret, 0);
        return secret;
    }
}
