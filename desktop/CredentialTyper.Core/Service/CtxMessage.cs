using System.Text.Json;
using System.Text.Json.Serialization;
using CredentialTyper.Core.Automation;

namespace CredentialTyper.Core.Service;

/// <summary>把桌面当前焦点上下文编码成 ctx 消息的 JSON（非敏感，仅作手机端排序/提示）。</summary>
public static class CtxMessage
{
    private sealed class FieldDto
    {
        [JsonPropertyName("kind")] public string Kind { get; set; } = "none";
        [JsonPropertyName("name")] public string Name { get; set; } = "";
    }

    private sealed class CtxDto
    {
        [JsonPropertyName("app")] public string App { get; set; } = "";
        [JsonPropertyName("title")] public string Title { get; set; } = "";
        [JsonPropertyName("field")] public FieldDto Field { get; set; } = new();
    }

    public static string Build(WindowContext? wc, FormLocator.Field? field)
    {
        var dto = new CtxDto
        {
            App = wc?.ProcessName ?? "",
            Title = wc?.Title ?? "",
            Field = new FieldDto { Kind = KindStr(field), Name = field?.Name ?? "" },
        };
        return JsonSerializer.Serialize(dto);
    }

    private static string KindStr(FormLocator.Field? f) => f?.Kind switch
    {
        FormLocator.FieldKind.Password => "password",
        FormLocator.FieldKind.Text => "text",
        FormLocator.FieldKind.Other => "other",
        _ => "none",
    };
}
