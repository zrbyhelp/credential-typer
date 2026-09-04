using System.Buffers.Binary;
using System.Text;

namespace CredentialTyper.Transport.Wire;

public static class FilterSyncFrame
{
    public const byte Tag = 0x06;
    public const byte Version = 0x01;
    public static byte[] Encode(string query)
    {
        var body = new UTF8Encoding(false, true).GetBytes(query);
        if (body.Length > ushort.MaxValue || body.Length + 4 > Session.MaxCiphertextLen)
            throw new ArgumentException("筛选内容过长");
        var frame = new byte[4 + body.Length];
        frame[0] = Tag; frame[1] = Version;
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(2, 2), (ushort)body.Length);
        body.CopyTo(frame, 4);
        return frame;
    }
    public static string Decode(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 4 || frame[0] != Tag || frame[1] != Version)
            throw new FormatException("无效的筛选同步帧");
        var len = BinaryPrimitives.ReadUInt16BigEndian(frame[2..4]);
        if (len + 4 != frame.Length) throw new FormatException("筛选同步帧长度不匹配");
        return new UTF8Encoding(false, true).GetString(frame[4..]);
    }
}
