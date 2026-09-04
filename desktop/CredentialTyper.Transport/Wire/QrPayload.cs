using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CredentialTyper.Transport.Wire;

/// <summary>
/// 二维码内容：桌面身份公钥 + LAN 地址 + 一次性配对码。
/// 序列化为 UTF-8 JSON 再 base64url，塞进二维码。
/// </summary>
public sealed class QrPayload
{
    [JsonPropertyName("v")] public int Version { get; set; } = Protocol.Version;

    /// <summary>桌面静态公钥（32 字节）base64url。</summary>
    [JsonPropertyName("spub")] public string SPub { get; set; } = "";

    /// <summary>桌面所有 LAN IPv4，手机逐个尝试。</summary>
    [JsonPropertyName("host")] public string[] Host { get; set; } = Array.Empty<string>();

    [JsonPropertyName("port")] public int Port { get; set; }

    /// <summary>一次性配对码（16 字节）base64url。</summary>
    [JsonPropertyName("code")] public string Code { get; set; } = "";

    [JsonIgnore] public byte[] SPubBytes => Base64Url.Decode(SPub);
    [JsonIgnore] public byte[] CodeBytes => Base64Url.Decode(Code);

    private static readonly JsonSerializerOptions Opts = new() { DefaultIgnoreCondition = JsonIgnoreCondition.Never };

    public static QrPayload Create(byte[] spub, string[] host, int port, byte[] code) => new()
    {
        SPub = Base64Url.Encode(spub),
        Host = host,
        Port = port,
        Code = Base64Url.Encode(code),
    };

    /// <summary>整体 base64url，即二维码里的字符串。</summary>
    public string ToQrText() => Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(this, Opts));

    public static QrPayload FromQrText(string qr)
    {
        var json = Base64Url.Decode(qr);
        return JsonSerializer.Deserialize<QrPayload>(json, Opts)
            ?? throw new FormatException("二维码内容无法解析为 QrPayload");
    }

    public string ToJson() => Encoding.UTF8.GetString(JsonSerializer.SerializeToUtf8Bytes(this, Opts));
}
