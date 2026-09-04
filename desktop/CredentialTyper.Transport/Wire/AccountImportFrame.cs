using System.Buffers.Binary;
using System.Text;

namespace CredentialTyper.Transport.Wire;

public static class AccountImportFrame
{
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);
    public const byte Tag = 0x05;
    public const byte Version = 0x02;
    private const int HeaderLength = 12;

    public static byte[] Encode(string title, string username, string website, string note, ReadOnlySpan<byte> password)
    {
        var fields = new[] { Utf8.GetBytes(title), Utf8.GetBytes(username), Utf8.GetBytes(NormalizeWebsite(website)), Utf8.GetBytes(note), password.ToArray() };
        if (fields.Any(x => x.Length > ushort.MaxValue)) throw new ArgumentException("字段过长");
        var frame = new byte[HeaderLength + fields.Sum(x => x.Length)];
        if (frame.Length > Session.MaxCiphertextLen) throw new ArgumentException("账号数据过大");
        frame[0] = Tag; frame[1] = Version; var p = 2;
        foreach (var field in fields) { BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(p, 2), (ushort)field.Length); p += 2; }
        foreach (var field in fields) { field.CopyTo(frame, p); p += field.Length; }
        return frame;
    }

    public static (string Title, string Username, string Website, string Note, byte[] Password) Decode(ReadOnlySpan<byte> input)
    {
        if (input.Length < HeaderLength || input.Length > Session.MaxCiphertextLen || input[0] != Tag || input[1] != Version) throw new FormatException("无效的账号导入帧");
        var frame = input.ToArray(); var lengths = new ushort[5]; var p = 2;
        for (var i = 0; i < lengths.Length; i++) { lengths[i] = BinaryPrimitives.ReadUInt16BigEndian(frame.AsSpan(p, 2)); p += 2; }
        if (HeaderLength + lengths.Sum(x => (int)x) != frame.Length) throw new FormatException("账号导入帧长度不匹配");
        ReadOnlySpan<byte> Take(int len) { var v = frame.AsSpan(p, len); p += len; return v; }
        return (Utf8.GetString(Take(lengths[0])), Utf8.GetString(Take(lengths[1])), Utf8.GetString(Take(lengths[2])), Utf8.GetString(Take(lengths[3])), Take(lengths[4]).ToArray());
    }

    public static string NormalizeWebsite(string input)
    {
        var value = input.Trim().ToLowerInvariant();
        var scheme = value.IndexOf("://", StringComparison.Ordinal); if (scheme >= 0) value = value[(scheme + 3)..];
        var cut = value.IndexOfAny(new[] { '/', '?', '#', ' ', '\\' }); if (cut >= 0) value = value[..cut];
        if (value.StartsWith("www.", StringComparison.Ordinal)) value = value[4..];
        var port = value.LastIndexOf(':'); if (port > 0 && value[(port + 1)..].All(char.IsDigit)) value = value[..port];
        return new string(value.Where(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' ).ToArray());
    }
}
