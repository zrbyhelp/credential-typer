using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CredentialTyper.Core.Interop;

namespace CredentialTyper.Core.Input;

/// <summary>
/// 凭据注入的统一入口，两层降级：
///   1. 首选 <see cref="Injector"/>（SendInput）—— 硬件保真、更新键状态、兼容性最好；
///   2. SendInput 被环境拒绝（返回值不足）时降级 <see cref="MessageInjector"/>（WM_CHAR），
///      投给当前焦点子控件 —— 无真实输入栈的会话（无头 VM 等）用这条路。
///
/// 焦点改变（<see cref="InjectionAbortReason.FocusChanged"/>）绝不降级重试：那意味着
/// 目标窗口已变，重试只会把密码打进别处。只有 SendInput 的环境性拒绝才降级。
///
/// 入参是 UTF-8 明文字节（来自解密后的 fill 帧）。全程活在可清零缓冲里，返回前 ZeroMemory。
/// </summary>
public static class CredentialInjector
{
    public enum Path { SendInput, MessageWmChar }

    /// <summary>把 UTF-8 明文注入当前前台窗口的焦点控件。enter=true 时末尾补一个回车。</summary>
    public static Path TypeUtf8ToForegroundFocus(ReadOnlySpan<byte> utf8, bool enter)
    {
        nint fg = Native.GetForegroundWindow();
        if (fg == 0)
            throw new InjectionAbortedException("当前没有前台窗口，放弃注入。", InjectionAbortReason.NoTarget);

        nint control = Native.FocusedControlOf(fg);

        int count = Encoding.UTF8.GetCharCount(utf8);
        var chars = new char[count + (enter ? 1 : 0)];
        try
        {
            int written = Encoding.UTF8.GetChars(utf8, chars);
            if (enter) chars[written++] = '\n';   // 统一走注入器的换行逻辑（SendInput→VK_RETURN，WM_CHAR→\r）
            var span = chars.AsSpan(0, written);

            try
            {
                Injector.Type(span, fg);
                return Path.SendInput;
            }
            catch (InjectionAbortedException ex) when (ex.Reason == InjectionAbortReason.SendInputRejected)
            {
                // SendInput 环境性不可用（本机就是这种：始终返回 0）。降级前再校验一次焦点，
                // 焦点已变则放弃 —— 不把密码投到别的窗口。
                // 注：SendInput 在本类目标环境里是「整体不通/返回 0」，不会先成功注入半截再被拒，
                // 因此降级重发不会造成重复输入。
                if (Native.GetForegroundWindow() != fg)
                    throw new InjectionAbortedException("焦点在降级前已改变，放弃注入。", InjectionAbortReason.FocusChanged);

                MessageInjector.Type(span, control);
                return Path.MessageWmChar;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
        }
    }
}
