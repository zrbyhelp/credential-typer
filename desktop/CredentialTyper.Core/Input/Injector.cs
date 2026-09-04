using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using CredentialTyper.Core.Interop;

namespace CredentialTyper.Core.Input;

/// <summary>
/// 通过 SendInput 把文本以 UTF-16 码元逐个注入前台窗口。
///
/// 之所以不用「写剪贴板 + Ctrl+V」：剪贴板对所有进程可读，输入法和剪贴板管理器
/// 还会把内容持久化到磁盘。密码绝不能进剪贴板。
///
/// 本类型不接受 string —— .NET 的 string 不可变，一旦构造就无法清零，
/// 明文密码必须全程活在可清零的 char[] / Span&lt;char&gt; 里。
/// </summary>
public static class Injector
{
    /// <summary>一批最多注入多少个字符。每批之间会重新校验前台窗口。</summary>
    internal const int ChunkChars = 200;

    /// <summary>把一批 INPUT 交给系统。返回被接受的事件数。</summary>
    internal delegate uint InputSink(Native.INPUT[] batch, int count);

    private static readonly InputSink SystemSink =
        (batch, count) => Native.SendInput((uint)count, batch, Marshal.SizeOf<Native.INPUT>());

    /// <summary>
    /// 注入文本。注入前以及每批之间都会校验前台窗口仍是 <paramref name="expectedForeground"/>，
    /// 不符立即中止 —— UAC 弹窗、IM 消息、杀毒提示都可能在注入过程中抢走焦点，
    /// 不校验就意味着密码的后半截会打进别的窗口。
    /// </summary>
    /// <param name="text">待注入文本。调用方负责在用完后清零其底层缓冲。</param>
    /// <param name="expectedForeground">期望的前台窗口句柄。传 0 表示跳过校验，仅供测试使用。</param>
    /// <exception cref="InjectionAbortedException">焦点已改变，或 SendInput 被系统拦截。</exception>
    public static void Type(ReadOnlySpan<char> text, nint expectedForeground) =>
        TypeCore(text, expectedForeground, SystemSink);

    /// <summary>
    /// 把 UTF-8 字节解码后注入。中间产生的 char 缓冲会在返回前清零。
    /// 从网络收到的密文解密后就是 UTF-8 字节，用这个重载可以避免自己管理中间缓冲。
    /// </summary>
    public static void TypeUtf8(ReadOnlySpan<byte> utf8, nint expectedForeground)
    {
        var chars = new char[Encoding.UTF8.GetCharCount(utf8)];
        try
        {
            int written = Encoding.UTF8.GetChars(utf8, chars);
            Type(chars.AsSpan(0, written), expectedForeground);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(chars.AsSpan()));
        }
    }

    /// <summary>
    /// 真正的注入逻辑。<paramref name="sink"/> 可替换，使得分批与编码路径能被单测覆盖
    /// 而不依赖真实的输入栈（CI 和无头环境上 SendInput 不可用）。
    /// </summary>
    internal static void TypeCore(ReadOnlySpan<char> text, nint expectedForeground, InputSink sink)
    {
        if (text.IsEmpty) return;

        // INPUT 数组里的 wScan 字段装的就是密码的码元 —— 这个缓冲本身是敏感数据，
        // 用完必须清零。复用一个固定大小的缓冲，避免为长文本分配多份副本。
        var buffer = new Native.INPUT[ChunkChars * 2];

        try
        {
            int n = 0;
            foreach (char c in text)
            {
                // \r 直接丢弃，否则 CRLF 会敲两次回车
                if (c == '\r') continue;

                if (c == '\n')
                {
                    // 换行必须发真实按键。以 UNICODE 方式发 U+000A 多数程序不认。
                    buffer[n++] = Native.VirtualKey(Native.VK_RETURN, up: false);
                    buffer[n++] = Native.VirtualKey(Native.VK_RETURN, up: true);
                }
                else
                {
                    // C# 的 char 就是 UTF-16 码元，代理对（emoji）逐个码元发送即可，
                    // Windows 会自行合成 —— 不需要特殊处理。
                    buffer[n++] = Native.UnicodeUnit(c, up: false);
                    buffer[n++] = Native.UnicodeUnit(c, up: true);
                }

                if (n == buffer.Length)
                {
                    Flush(buffer, n, expectedForeground, sink);
                    n = 0;
                }
            }

            if (n > 0) Flush(buffer, n, expectedForeground, sink);
        }
        finally
        {
            Array.Clear(buffer);
        }
    }

    private static void Flush(Native.INPUT[] batch, int count, nint expectedForeground, InputSink sink)
    {
        if (expectedForeground != 0)
        {
            nint actual = Native.GetForegroundWindow();
            if (actual != expectedForeground)
                throw new InjectionAbortedException(
                    $"焦点已改变（期望 0x{expectedForeground:X}，实际 0x{actual:X}），注入中止",
                    InjectionAbortReason.FocusChanged);
        }

        uint sent = sink(batch, count);

        // 返回值必须检查。向以管理员权限运行的程序注入时，非管理员进程会被 UIPI
        // 静默拦截 —— SendInput 返回 0 但不设置错误码，不检查就会以为注入成功了。
        if (sent != count)
        {
            int err = Marshal.GetLastWin32Error();
            throw new InjectionAbortedException(
                $"SendInput 被拦截（{sent}/{count}，Win32 错误 {err}）。" +
                "常见原因：目标程序以管理员权限运行而本进程没有，或被反作弊/安全软件拦截。",
                InjectionAbortReason.SendInputRejected);
        }
    }
}

/// <summary>注入为何中止。降级策略据此判定：仅 SendInput 环境性拒绝才降级 WM_CHAR。</summary>
public enum InjectionAbortReason
{
    /// <summary>前台/焦点窗口已变，绝不能降级重试 —— 否则密码打进别处。</summary>
    FocusChanged,
    /// <summary>SendInput 被拦截或环境不接受合成事件（返回值不足）。可降级 WM_CHAR。</summary>
    SendInputRejected,
    /// <summary>没有可投递的目标控件。</summary>
    NoTarget,
}

public sealed class InjectionAbortedException : Exception
{
    public InjectionAbortReason Reason { get; }

    public InjectionAbortedException(string message, InjectionAbortReason reason = InjectionAbortReason.FocusChanged)
        : base(message) => Reason = reason;
}
