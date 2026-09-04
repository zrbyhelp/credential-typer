using System.Buffers.Binary;

namespace CredentialTyper.Transport.Wire;

/// <summary>
/// 2 字节大端长度前缀分帧。握手消息（裸）与会话消息（Noise 密文）都用这个包。
/// </summary>
public static class Frame
{
    /// <summary>单帧上限。会话密文上限 16384，握手消息远小于此，取 2 字节自然上限即可。</summary>
    public const int MaxLen = 65535;

    public static async Task WriteAsync(Stream s, ReadOnlyMemory<byte> payload, CancellationToken ct = default)
    {
        if (payload.Length > MaxLen)
            throw new InvalidOperationException($"帧长 {payload.Length} 超过上限 {MaxLen}");

        var header = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(header, (ushort)payload.Length);
        await s.WriteAsync(header, ct).ConfigureAwait(false);
        await s.WriteAsync(payload, ct).ConfigureAwait(false);
        await s.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadAsync(Stream s, int maxLen = MaxLen, CancellationToken ct = default)
    {
        var header = new byte[2];
        await ReadExactAsync(s, header, ct).ConfigureAwait(false);
        int len = BinaryPrimitives.ReadUInt16BigEndian(header);
        if (len > maxLen)
            throw new InvalidOperationException($"帧长 {len} 超过上限 {maxLen}，按异常断开处理");

        var payload = new byte[len];
        await ReadExactAsync(s, payload, ct).ConfigureAwait(false);
        return payload;
    }

    private static async Task ReadExactAsync(Stream s, Memory<byte> buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf[read..], ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException("连接在读满一帧前被对端关闭");
            read += n;
        }
    }
}
