using FlaUI.Core.AutomationElements;
using FlaUI.Core.Definitions;
using FlaUI.UIA3;

namespace CredentialTyper.Core.Automation;

/// <summary>
/// 用 UI Automation 读出用户当前聚焦的输入框的上下文，作为发给手机端的匹配 / 提示信号。
///
/// 账号框 / 密码框由用户在 App 里手动选择，桌面端不再自动配对 —— 因为各家程序
/// （QQ、浏览器…）表单结构差异太大，启发式配对不可靠。这里只报告「焦点框是什么」：
/// <c>IsPassword</c>（Win32 密码框和浏览器 <c>&lt;input type=password&gt;</c> 都为 true）、
/// 字段名（如"输入QQ号""请输入腾讯云账号密码"，可作弱匹配线索）。
///
/// 域名拿不到：UIA 在浏览器里只能看到进程（chrome.exe），看不到页面表单的来源域名。
/// 浏览器域名匹配只能靠浏览器扩展。原生程序用进程名（QQ.exe）当匹配键。
///
/// UIA3Automation 持有 COM 资源、构造较重，本类持有一份复用，用完 Dispose。
/// </summary>
public sealed class FormLocator : IDisposable
{
    private readonly UIA3Automation _automation = new();

    /// <summary>被聚焦字段的可序列化快照（不含 FlaUI 类型，方便往外传）。</summary>
    public sealed record Field(
        FieldKind Kind,
        string Name,
        string AutomationId,
        nint NativeWindowHandle);

    public enum FieldKind { Password, Text, Other }

    /// <summary>用户当前聚焦的字段；无焦点或取不到时返回 null。</summary>
    public Field? CaptureFocused()
    {
        var el = _automation.FocusedElement();
        return el is null ? null : Describe(el);
    }

    private static bool IsPassword(AutomationElement el) =>
        el.Properties.IsPassword.ValueOrDefault;

    private static Field Describe(AutomationElement el)
    {
        var kind = IsPassword(el) ? FieldKind.Password
                 : el.Properties.ControlType.ValueOrDefault == ControlType.Edit ? FieldKind.Text
                 : FieldKind.Other;

        return new Field(
            kind,
            Safe(() => el.Name) ?? string.Empty,
            Safe(() => el.AutomationId) ?? string.Empty,
            Safe(() => (nint?)el.Properties.NativeWindowHandle.ValueOrDefault) ?? 0);
    }

    // UIA 属性可能抛 ElementNotAvailable（元素已消失），读取一律兜底
    private static T? Safe<T>(Func<T> read)
    {
        try { return read(); }
        catch { return default; }
    }

    public void Dispose() => _automation.Dispose();
}
