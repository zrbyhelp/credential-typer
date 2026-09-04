using System.Security.Cryptography;
using System.Text;
using CredentialTyper.Transport.Crypto;

namespace CredentialTyper.Transport.Tests;

/// <summary>
/// 验证纯托管 ChaCha20-Poly1305 与 RFC 8439 官方向量、与平台 CNG 实现字节级一致，
/// 从而保证换掉平台依赖后仍与手机端（Dart cryptography，同为 RFC 8439）互通。
/// </summary>
public class ManagedChaChaTests
{
    [Fact]
    public void Rfc8439_Aead_Vector()
    {
        var key = Enumerable.Range(0x80, 32).Select(i => (byte)i).ToArray();
        var nonce = new byte[] { 0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
        var aad = new byte[] { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
        var pt = Encoding.ASCII.GetBytes(
            "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");

        var ct = new byte[pt.Length];
        var tag = new byte[16];
        ManagedChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag, aad);

        // RFC 8439 §2.8.2 期望标签与密文前 16 字节。
        var expectedTag = new byte[] { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91 };
        var expectedCtHead = new byte[] { 0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2 };
        Assert.Equal(expectedTag, tag);
        Assert.Equal(expectedCtHead, ct[..16]);

        var back = new byte[pt.Length];
        ManagedChaCha20Poly1305.Decrypt(key, nonce, ct, tag, back, aad);
        Assert.Equal(pt, back);
    }

    [Fact]
    public void Matches_Platform_Implementation()
    {
        if (!ChaCha20Poly1305.IsSupported) return;   // 平台不支持则跳过对拍（正是本改动要解决的机器）

        var rng = RandomNumberGenerator.Create();
        for (int len = 0; len < 80; len++)           // 覆盖空、非 16 倍数、跨多块
        {
            var key = new byte[32]; rng.GetBytes(key);
            var nonce = new byte[12]; rng.GetBytes(nonce);
            var pt = new byte[len]; rng.GetBytes(pt);
            var aad = new byte[len % 17]; rng.GetBytes(aad);

            var sysCt = new byte[len]; var sysTag = new byte[16];
            using (var sys = new ChaCha20Poly1305(key))
                sys.Encrypt(nonce, pt, sysCt, sysTag, aad);

            var myCt = new byte[len]; var myTag = new byte[16];
            ManagedChaCha20Poly1305.Encrypt(key, nonce, pt, myCt, myTag, aad);

            Assert.Equal(sysCt, myCt);
            Assert.Equal(sysTag, myTag);

            // 交叉解密：托管实现必须能解开平台实现产生的密文。
            var dec = new byte[len];
            ManagedChaCha20Poly1305.Decrypt(key, nonce, sysCt, sysTag, dec, aad);
            Assert.Equal(pt, dec);
        }
    }

    [Fact]
    public void Tampered_Tag_Throws()
    {
        var key = new byte[32];
        var nonce = new byte[12];
        var pt = Encoding.UTF8.GetBytes("secret-payload");
        var ct = new byte[pt.Length];
        var tag = new byte[16];
        ManagedChaCha20Poly1305.Encrypt(key, nonce, pt, ct, tag, ReadOnlySpan<byte>.Empty);

        tag[0] ^= 0xff;
        var back = new byte[pt.Length];
        Assert.Throws<CryptographicException>(() =>
        {
            var t = new byte[16]; tag.CopyTo(t, 0);
            ManagedChaCha20Poly1305.Decrypt(key, nonce, ct, t, back, ReadOnlySpan<byte>.Empty);
        });
    }
}
