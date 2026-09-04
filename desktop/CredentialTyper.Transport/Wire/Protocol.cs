using System.Security.Cryptography;
using System.Text;

namespace CredentialTyper.Transport.Wire;

/// <summary>协议级常量与派生工具，两端必须一致。</summary>
public static class Protocol
{
    public const int Version = 1;

    /// <summary>Prologue 基串，两端 MixHash。配对时其后附加 16 字节一次性配对码。</summary>
    public const string PrologueBase = "credential-typer/v1";

    public const int PairingCodeLen = 16;
    public const int PublicKeyLen = 32;

    /// <summary>连接前导：TCP 连上后手机先发 1 字节，告诉桌面这条连接是配对还是重连。</summary>
    public static class ConnectMode
    {
        public const byte Pair = 0x01;       // 走 Noise_IK
        public const byte Reconnect = 0x02;  // 走 Noise_KK
    }

    /// <summary>重连（KK）prologue：仅基串。</summary>
    public static byte[] ReconnectPrologue() => Encoding.ASCII.GetBytes(PrologueBase);

    /// <summary>配对（IK）prologue：基串 || 配对码。</summary>
    public static byte[] PairingPrologue(ReadOnlySpan<byte> code)
    {
        var b = Encoding.ASCII.GetBytes(PrologueBase);
        var buf = new byte[b.Length + code.Length];
        b.CopyTo(buf, 0);
        code.CopyTo(buf.AsSpan(b.Length));
        return buf;
    }

    public static byte[] NewPairingCode() => RandomNumberGenerator.GetBytes(PairingCodeLen);

    /// <summary>
    /// 静态公钥指纹：SHA-256 前 8 字节，分 4 组每组 4 位十六进制。
    /// 配对时两端各自算、用户目视核对，防中间人。
    /// </summary>
    public static string Fingerprint(ReadOnlySpan<byte> publicKey)
    {
        var hash = SHA256.HashData(publicKey.ToArray());
        var sb = new StringBuilder();
        for (int i = 0; i < 8; i++)
        {
            sb.Append(hash[i].ToString("X2"));
            if (i % 2 == 1 && i != 7) sb.Append(' ');
        }
        return sb.ToString();   // 例：A1B2 C3D4 E5F6 0708
    }
}
