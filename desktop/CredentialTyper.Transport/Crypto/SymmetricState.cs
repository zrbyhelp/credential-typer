using System.Security.Cryptography;
using System.Text;

namespace CredentialTyper.Transport.Crypto;

/// <summary>Noise 的 SymmetricState：链式密钥 ck + 握手哈希 h + 一个 CipherState。</summary>
public sealed class SymmetricState
{
    private const int HashLen = 32;

    private byte[] _ck = new byte[HashLen];
    private byte[] _h = new byte[HashLen];
    private readonly CipherState _cs = new();

    public void InitializeSymmetric(string protocolName)
    {
        var name = Encoding.ASCII.GetBytes(protocolName);
        if (name.Length <= HashLen)
        {
            _h = new byte[HashLen];
            name.CopyTo(_h, 0);           // 不足 32 字节补 0
        }
        else
        {
            _h = SHA256.HashData(name);
        }
        _ck = (byte[])_h.Clone();
        _cs.InitializeKey(null);
    }

    public void MixKey(byte[] inputKeyMaterial)
    {
        var (ck, tempK) = Hkdf2(_ck, inputKeyMaterial);
        _ck = ck;
        _cs.InitializeKey(tempK);
    }

    public void MixHash(ReadOnlySpan<byte> data)
    {
        var buf = new byte[_h.Length + data.Length];
        _h.CopyTo(buf, 0);
        data.CopyTo(buf.AsSpan(_h.Length));
        _h = SHA256.HashData(buf);
    }

    public byte[] Handshakehash => _h;

    public byte[] EncryptAndHash(ReadOnlySpan<byte> plaintext)
    {
        var ct = _cs.EncryptWithAd(_h, plaintext);
        MixHash(ct);
        return ct;
    }

    public byte[] DecryptAndHash(ReadOnlySpan<byte> ciphertext)
    {
        var pt = _cs.DecryptWithAd(_h, ciphertext);
        MixHash(ciphertext);
        return pt;
    }

    /// <summary>握手结束，派生出收发两个 CipherState。initiator 用 (c1=发, c2=收)。</summary>
    public (CipherState C1, CipherState C2) Split()
    {
        var (k1, k2) = Hkdf2(_ck, Array.Empty<byte>());
        var c1 = new CipherState(); c1.InitializeKey(k1);
        var c2 = new CipherState(); c2.InitializeKey(k2);
        return (c1, c2);
    }

    // Noise 版 HKDF，输出 2 段：先 HMAC(ck, ikm) 得 temp_key，再逐段 HMAC(temp_key, prev||i)
    private static (byte[] O1, byte[] O2) Hkdf2(byte[] ck, byte[] ikm)
    {
        var tempKey = HMACSHA256.HashData(ck, ikm);
        var o1 = HMACSHA256.HashData(tempKey, new byte[] { 0x01 });
        var o2 = HMACSHA256.HashData(tempKey, Concat(o1, 0x02));
        return (o1, o2);
    }

    private static byte[] Concat(byte[] a, byte b)
    {
        var buf = new byte[a.Length + 1];
        a.CopyTo(buf, 0);
        buf[a.Length] = b;
        return buf;
    }
}
