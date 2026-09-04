using System.Text.Json;
using System.Text.Json.Serialization;
using CredentialTyper.Transport.Wire;

namespace CredentialTyper.Core.Service;

/// <summary>
/// 已配对手机的静态公钥（v1 只支持一台手机，新配对覆盖旧的）。
/// 公钥不敏感，明文 JSON 落盘即可。重连时用它做 KK 的对端身份 pin。
/// </summary>
public sealed class PairingStore
{
    private sealed class Record
    {
        [JsonPropertyName("phonePub")] public string PhonePub { get; set; } = "";
    }

    private readonly string _path;
    private byte[]? _phonePublic;

    public PairingStore(string? dir = null)
    {
        dir ??= DesktopIdentity.DefaultDir;
        _path = Path.Combine(dir, "pairing.json");
        Load();
    }

    public bool HasPaired => _phonePublic is not null;

    /// <summary>已配对手机的静态公钥；未配对时抛。</summary>
    public byte[] PhonePublic => _phonePublic ?? throw new InvalidOperationException("尚未配对任何手机");

    public void Save(byte[] phonePublic)
    {
        _phonePublic = (byte[])phonePublic.Clone();
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var rec = new Record { PhonePub = Base64Url.Encode(phonePublic) };
        File.WriteAllText(_path, JsonSerializer.Serialize(rec));
    }

    /// <summary>清除已保存的配对，之后需要重新扫码配对。</summary>
    public void Clear()
    {
        _phonePublic = null;
        try { if (File.Exists(_path)) File.Delete(_path); }
        catch { /* 删除失败忽略，下次 Save 会覆盖 */ }
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var rec = JsonSerializer.Deserialize<Record>(File.ReadAllText(_path));
            if (!string.IsNullOrEmpty(rec?.PhonePub))
                _phonePublic = Base64Url.Decode(rec.PhonePub);
        }
        catch { /* 损坏则视为未配对 */ }
    }
}
