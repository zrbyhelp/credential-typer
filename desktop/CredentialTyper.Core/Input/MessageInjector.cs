using System.Security.Cryptography;
using System.Runtime.InteropServices;
using CredentialTyper.Core.Interop;

namespace CredentialTyper.Core.Input;

/// <summary>
/// WM_CHAR 消息级注入 —— SendInput 的后备路径。
///
/// SendInput 把事件投进系统的硬件输入队列，无真实输入栈的环境（无头 VM、
/// 断开的 RDP 会话）会静默丢弃。WM_CHAR 则直接投递给目标控件，不经过那条队列，
/// 因此在 SendInput 失败的机器上往往还能工作。
///
/// 代价与局限：
/// - 不更新按键状态，也不触发 WM_KEYDOWN/WM_KEYUP，靠捕捉键盘事件的程序可能收不到；
/// - 部分程序（尤其游戏、少数安全登录框）会忽略合成的 WM_CHAR；
/// - 必须投给真正获得焦点的那个子控件，投给顶层窗口通常无效。
///
/// 与 <see cref="Injector"/> 一样，不接受 string —— 明文密码必须活在可清零的
/// char[] / Span&lt;char&gt; 里。
/// </summary>
public static class MessageInjector
{
    /// <summary>用 SendMessage(WM_CHAR) 把文本逐码元投给指定控件（阻塞，按序到达）。</summary>
    public static void Type(ReadOnlySpan<char> text, nint targetControl)
    {
        if (targetControl == 0)
            throw new InjectionAbortedException("目标控件句柄为空，无法投递 WM_CHAR。", InjectionAbortReason.NoTarget);

        foreach (char c in text)
        {
            if (c == '\r') continue;               // 避免 CRLF 敲两次
            char ch = c == '\n' ? '\r' : c;        // 编辑框里回车字符是 \r(0x0D)
            // char 本身就是 UTF-16 码元，代理对自然拆成两条 WM_CHAR，编辑控件会合成。
            Native.SendMessageW(targetControl, Native.WM_CHAR, ch, 0);
        }
    }

    /// <summary>把 UTF-8 字节先解码到可清零的 char[]，投递后立即清零。</summary>
    public static void TypeUtf8(ReadOnlySpan<byte> utf8, nint targetControl)
    {
        var chars = new char[System.Text.Encoding.UTF8.GetCharCount(utf8)];
        try
        {
            int written = System.Text.Encoding.UTF8.GetChars(utf8, chars);
            Type(chars.AsSpan(0, written), targetControl);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
        }
    }

    /// <summary>解析出前台窗口里真正获得焦点的子控件，再投递。</summary>
    public static nint TypeToForegroundFocus(ReadOnlySpan<char> text)
    {
        nint fg = Native.GetForegroundWindow();
        nint control = Native.FocusedControlOf(fg);
        Type(text, control);
        return control;
    }
}
