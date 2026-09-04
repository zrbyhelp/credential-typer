using System.Runtime.InteropServices;
using CredentialTyper.Core.Input;
using CredentialTyper.Core.Interop;
using Xunit;

namespace CredentialTyper.Core.Tests;

/// <summary>
/// 注入编码逻辑的测试。刻意不触碰真实的 SendInput —— 输入栈能否投递取决于运行环境
/// （无头虚拟机、CI、锁屏都会让 SendInput 静默返回 0），那是环境问题，
/// 而这里要锁住的是「字符如何变成 INPUT 事件」这件事本身。
/// </summary>
public class InjectorTests
{
    private static List<Native.INPUT> Encode(string text)
    {
        var collected = new List<Native.INPUT>();
        Injector.TypeCore(text, 0, (batch, count) =>
        {
            for (int i = 0; i < count; i++) collected.Add(batch[i]); // INPUT 是值类型，这里是复制
            return (uint)count;
        });
        return collected;
    }

    private static int CountBatches(string text)
    {
        int batches = 0;
        Injector.TypeCore(text, 0, (_, count) => { batches++; return (uint)count; });
        return batches;
    }

    [Fact]
    public void INPUT结构在x64下必须是40字节()
    {
        // cbSize 传错 SendInput 会直接失败并返回 ERROR_INVALID_PARAMETER，
        // 这个尺寸是整个注入路径的地基
        Assert.Equal(40, Marshal.SizeOf<Native.INPUT>());
    }

    [Fact]
    public void 每个字符产生一对按下与抬起事件()
    {
        var events = Encode("ab");

        Assert.Equal(4, events.Count);
        Assert.Equal('a', (char)events[0].U.ki.wScan);
        Assert.Equal('a', (char)events[1].U.ki.wScan);
        Assert.Equal('b', (char)events[2].U.ki.wScan);
        Assert.Equal('b', (char)events[3].U.ki.wScan);
    }

    [Fact]
    public void 普通字符走UNICODE通道且虚拟键必须为零()
    {
        var events = Encode("a");

        Assert.Equal(0, events[0].U.ki.wVk);
        Assert.Equal(Native.KEYEVENTF_UNICODE, events[0].U.ki.dwFlags);
        Assert.Equal(Native.KEYEVENTF_UNICODE | Native.KEYEVENTF_KEYUP, events[1].U.ki.dwFlags);
    }

    [Theory]
    [InlineData('密', 0x5BC6)]
    [InlineData('码', 0x7801)]
    [InlineData('é', 0x00E9)]
    [InlineData('€', 0x20AC)]
    public void 非ASCII字符按UTF16码元原样发送(char c, int expectedScan)
    {
        var events = Encode(c.ToString());

        Assert.Equal(2, events.Count);
        Assert.Equal(expectedScan, events[0].U.ki.wScan);
    }

    [Fact]
    public void Emoji拆成两个代理码元共四个事件()
    {
        // U+1F510 🔐 在 UTF-16 里是代理对 D83D DD10。
        // 逐个码元发送即可，Windows 会自行合成 —— 不需要特殊处理。
        var events = Encode("🔐");

        Assert.Equal(4, events.Count);
        Assert.Equal(0xD83D, events[0].U.ki.wScan);
        Assert.Equal(0xD83D, events[1].U.ki.wScan);
        Assert.Equal(0xDD10, events[2].U.ki.wScan);
        Assert.Equal(0xDD10, events[3].U.ki.wScan);
    }

    [Fact]
    public void 换行发真实回车键而不是UNICODE码元()
    {
        // 以 UNICODE 方式发 U+000A 多数程序不认，必须发 VK_RETURN
        var events = Encode("\n");

        Assert.Equal(2, events.Count);
        Assert.Equal(Native.VK_RETURN, events[0].U.ki.wVk);
        Assert.Equal(0, events[0].U.ki.wScan);
        Assert.Equal(0u, events[0].U.ki.dwFlags);
        Assert.Equal(Native.KEYEVENTF_KEYUP, events[1].U.ki.dwFlags);
    }

    [Fact]
    public void 回车符被丢弃避免CRLF敲两次()
    {
        Assert.Empty(Encode("\r"));

        var crlf = Encode("\r\n");
        Assert.Equal(2, crlf.Count);
        Assert.Equal(Native.VK_RETURN, crlf[0].U.ki.wVk);
    }

    [Fact]
    public void 空文本不产生任何事件()
    {
        Assert.Equal(0, CountBatches(""));
    }

    [Fact]
    public void 超过批次上限的文本会被分批发送()
    {
        // 每个字符 2 个事件，缓冲是 ChunkChars*2，所以正好 ChunkChars 个字符是一批
        Assert.Equal(1, CountBatches(new string('x', Injector.ChunkChars)));
        Assert.Equal(2, CountBatches(new string('x', Injector.ChunkChars + 1)));
        Assert.Equal(3, CountBatches(new string('x', Injector.ChunkChars * 2 + 1)));
    }

    [Fact]
    public void 分批不会丢字符()
    {
        string text = new('x', Injector.ChunkChars * 2 + 37);
        Assert.Equal(text.Length * 2, Encode(text).Count);
    }

    [Fact]
    public void 焦点与预期不符时中止注入()
    {
        // 传一个不可能存在的窗口句柄，焦点校验必须失败
        var ex = Assert.Throws<InjectionAbortedException>(() =>
            Injector.TypeCore("secret", unchecked((nint)0xDEAD_BEEF), (_, count) => (uint)count));

        Assert.Contains("焦点已改变", ex.Message);
    }

    [Fact]
    public void 焦点校验发生在第一次发送之前()
    {
        // 焦点不对时一个事件都不能发出去 —— 否则密码的开头会打进错误的窗口
        bool sinkCalled = false;
        Assert.Throws<InjectionAbortedException>(() =>
            Injector.TypeCore("secret", unchecked((nint)0xDEAD_BEEF), (_, count) => { sinkCalled = true; return (uint)count; }));

        Assert.False(sinkCalled);
    }

    [Fact]
    public void 系统只接受了部分事件时抛出异常()
    {
        // SendInput 被 UIPI 拦截时返回 0 且不设错误码，不检查返回值就会误以为注入成功
        var ex = Assert.Throws<InjectionAbortedException>(() =>
            Injector.TypeCore("secret", 0, (_, _) => 0u));

        Assert.Contains("被拦截", ex.Message);
    }

    [Fact]
    public void 混合内容的完整编码()
    {
        var events = Encode("a密\n");

        Assert.Equal(6, events.Count);
        Assert.Equal('a', (char)events[0].U.ki.wScan);
        Assert.Equal(Native.KEYEVENTF_UNICODE, events[0].U.ki.dwFlags);
        Assert.Equal(0x5BC6, events[2].U.ki.wScan);
        Assert.Equal(Native.VK_RETURN, events[4].U.ki.wVk);
    }
}
