using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace CredentialTyper.Transport.Crypto;

/// <summary>
/// 纯托管的 RFC 8439 (IETF) ChaCha20-Poly1305 AEAD。
///
/// 为什么不用 <c>System.Security.Cryptography.ChaCha20Poly1305</c>：那个类走
/// Windows CNG，只有 Windows 11 / Server 2022+ 才带该算法；在 Windows 10 等系统上
/// <c>IsSupported == false</c>，调用直接抛 “Algorithm 'ChaCha20Poly1305' is not
/// supported on this platform.”，导致 Noise 握手第一帧就失败、手机端表现为
/// EndOfStream。改用本纯算法实现后，桌面端在任何 Windows 版本上都能与手机端
/// （Dart cryptography 包，同为 RFC 8439）字节级互通。
///
/// nonce 固定 12 字节；counter 从 0 生成 Poly1305 一次性密钥，从 1 开始加密流。
/// </summary>
public static class ManagedChaCha20Poly1305
{
    /// <summary>加密并生成 16 字节标签。ciphertext 长度须等于 plaintext，tag 须为 16。</summary>
    public static void Encrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> ad)
    {
        if (key.Length != 32) throw new ArgumentException("key 必须 32 字节", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("nonce 必须 12 字节", nameof(nonce));
        if (ciphertext.Length != plaintext.Length) throw new ArgumentException("ciphertext 长度须等于 plaintext");
        if (tag.Length != 16) throw new ArgumentException("tag 必须 16 字节", nameof(tag));

        Span<byte> polyKey = stackalloc byte[64];
        ChaCha20Block(key, nonce, 0, polyKey);          // counter 0 → 一次性 Poly1305 密钥
        ChaCha20(key, nonce, 1, plaintext, ciphertext); // counter 1.. → 加密流
        Poly1305Mac(polyKey[..32], ad, ciphertext, tag);
    }

    /// <summary>验证标签并解密。标签不符抛 <see cref="CryptographicException"/>（与 .NET 语义一致）。</summary>
    public static void Decrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> ad)
    {
        if (key.Length != 32) throw new ArgumentException("key 必须 32 字节", nameof(key));
        if (nonce.Length != 12) throw new ArgumentException("nonce 必须 12 字节", nameof(nonce));
        if (tag.Length != 16) throw new ArgumentException("tag 必须 16 字节", nameof(tag));
        if (plaintext.Length != ciphertext.Length) throw new ArgumentException("plaintext 长度须等于 ciphertext");

        Span<byte> polyKey = stackalloc byte[64];
        ChaCha20Block(key, nonce, 0, polyKey);

        Span<byte> expected = stackalloc byte[16];
        Poly1305Mac(polyKey[..32], ad, ciphertext, expected);
        if (!CryptographicOperations.FixedTimeEquals(expected, tag))
            throw new CryptographicException("Poly1305 认证标签不匹配");

        ChaCha20(key, nonce, 1, ciphertext, plaintext);
    }

    // —— ChaCha20 核心（RFC 8439 §2.3）——

    private static void ChaCha20(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter,
        ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> block = stackalloc byte[64];
        int pos = 0;
        uint ctr = counter;
        while (pos < input.Length)
        {
            ChaCha20Block(key, nonce, ctr, block);
            int n = Math.Min(64, input.Length - pos);
            for (int i = 0; i < n; i++)
                output[pos + i] = (byte)(input[pos + i] ^ block[i]);
            pos += n;
            ctr++;
        }
    }

    private static void ChaCha20Block(
        ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output64)
    {
        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * 4, 4));
        state[12] = counter;
        for (int i = 0; i < 3; i++)
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(i * 4, 4));

        Span<uint> x = stackalloc uint[16];
        state.CopyTo(x);
        for (int i = 0; i < 10; i++)   // 20 轮 = 10 个 double round
        {
            QuarterRound(x, 0, 4, 8, 12);
            QuarterRound(x, 1, 5, 9, 13);
            QuarterRound(x, 2, 6, 10, 14);
            QuarterRound(x, 3, 7, 11, 15);
            QuarterRound(x, 0, 5, 10, 15);
            QuarterRound(x, 1, 6, 11, 12);
            QuarterRound(x, 2, 7, 8, 13);
            QuarterRound(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(output64.Slice(i * 4, 4), x[i] + state[i]);
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 7);
    }

    private static uint Rotl(uint v, int n) => (v << n) | (v >> (32 - n));

    // —— Poly1305（RFC 8439 §2.5）——

    private static readonly BigInteger P = (BigInteger.One << 130) - 5;
    private static readonly BigInteger Mask128 = (BigInteger.One << 128) - 1;

    private static void Poly1305Mac(
        ReadOnlySpan<byte> otk, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ct, Span<byte> tag)
    {
        // r = clamp(otk[0..16])，s = otk[16..32]，均按小端解释。
        Span<byte> rBytes = stackalloc byte[16];
        otk[..16].CopyTo(rBytes);
        rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15;
        rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
        var r = new BigInteger(rBytes, isUnsigned: true, isBigEndian: false);
        var s = new BigInteger(otk.Slice(16, 16), isUnsigned: true, isBigEndian: false);

        BigInteger acc = 0;
        acc = ProcessBlocks(acc, r, ad);   // AD（末块按实际长度，等价于 pad16）
        acc = ProcessBlocks(acc, r, ct);   // 密文（同上）

        // 末尾长度块：le64(ad_len) || le64(ct_len)，作为一个完整 16 字节块处理。
        Span<byte> lenBlock = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(lenBlock[..8], (ulong)ad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lenBlock[8..], (ulong)ct.Length);
        acc = AddBlock(acc, r, lenBlock);

        acc = (acc + s) & Mask128;

        var outBytes = acc.ToByteArray(isUnsigned: true, isBigEndian: false);
        tag.Clear();
        int m = Math.Min(16, outBytes.Length);
        outBytes.AsSpan(0, m).CopyTo(tag);
    }

    private static BigInteger ProcessBlocks(BigInteger acc, BigInteger r, ReadOnlySpan<byte> data)
    {
        int off = 0;
        while (off < data.Length)
        {
            int n = Math.Min(16, data.Length - off);
            acc = AddBlock(acc, r, data.Slice(off, n));
            off += n;
        }
        return acc;
    }

    /// AEAD 构造已用 pad16 把 aad / 密文各自补齐到 16 的倍数，因此每一块都按
    /// 满 16 字节处理：不足的末块补零，追加的 0x01 高位固定落在第 17 字节
    /// （即 +2^128）。转成小端整数累加后乘 r 取模 —— Poly1305 的核心迭代。
    private static BigInteger AddBlock(BigInteger acc, BigInteger r, ReadOnlySpan<byte> block)
    {
        Span<byte> buf = stackalloc byte[17];
        buf.Clear();                 // stackalloc 不清零，末块补零依赖这里
        block.CopyTo(buf);           // block.Length ≤ 16
        buf[16] = 1;
        var n = new BigInteger(buf, isUnsigned: true, isBigEndian: false);
        return ((acc + n) * r) % P;
    }
}
