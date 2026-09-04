using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CredentialTyper.Transport.Crypto;

/// <summary>
/// Noise 的 CipherState：ChaCha20-Poly1305 + 单调递增 nonce。
/// Noise 的 96 位 nonce = 前 4 字节 0 || 小端 uint64 计数器。
/// </summary>
public sealed class CipherState
{
    private byte[]? _k;   // 32 字节；null = 无密钥（明文透传）
    private ulong _n;

    public void InitializeKey(byte[]? key)
    {
        _k = key;
        _n = 0;
    }

    public bool HasKey => _k is not null;

    public byte[] EncryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext)
    {
        if (_k is null) return plaintext.ToArray();

        // 纯托管 RFC 8439 实现：不依赖平台 CNG，任何 Windows 版本都能与手机端互通。
        var ct = new byte[plaintext.Length];
        var tag = new byte[16];
        ManagedChaCha20Poly1305.Encrypt(_k, Nonce(_n), plaintext, ct, tag, ad);
        _n++;

        var outBuf = new byte[ct.Length + 16];
        ct.CopyTo(outBuf, 0);
        tag.CopyTo(outBuf, ct.Length);
        return outBuf;
    }

    public byte[] DecryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext)
    {
        if (_k is null) return ciphertext.ToArray();
        if (ciphertext.Length < 16) throw new CryptographicException("密文短于认证标签长度");

        int ctLen = ciphertext.Length - 16;
        var ct = ciphertext[..ctLen];
        var tag = ciphertext[ctLen..];
        var pt = new byte[ctLen];
        ManagedChaCha20Poly1305.Decrypt(_k, Nonce(_n), ct, tag, pt, ad);   // 标签不符会抛 CryptographicException
        _n++;
        return pt;
    }

    private static byte[] Nonce(ulong n)
    {
        var nonce = new byte[12];               // 前 4 字节保持 0
        BinaryPrimitives.WriteUInt64LittleEndian(nonce.AsSpan(4), n);
        return nonce;
    }
}
