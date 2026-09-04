using System.Runtime.InteropServices;
using System.Windows.Forms;
using CredentialTyper.Core.Input;

namespace CredentialTyper.Cli;

/// <summary>
/// 非交互式验证注入路径：自己起一个带文本框的靶窗口，注入样本文本，再读回来比对。
/// 样本覆盖 ASCII、符号、中文、emoji（代理对）和换行 —— 这几类正是注入最容易出错的地方。
/// </summary>
internal static class SelfTest
{
    private const string Sample = "user@example.com\nP@ssw0rd!#$%^&*()\n中文密码测试\n🔐🎉";

    public static int Run()
    {
        int exit = 1;
        // WinForms 要求 STA，而 top-level statements 生成的入口点不是。
        var thread = new Thread(() => exit = RunSta());
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return exit;
    }

    private static int RunSta()
    {
        string? actual = null;
        Exception? failure = null;

        var form = new Form { Width = 640, Height = 360, Text = "注入靶窗口", TopMost = true };
        var box = new TextBox { Multiline = true, Dock = DockStyle.Fill, AcceptsReturn = true };
        form.Controls.Add(box);

        form.Shown += async (_, _) =>
        {
            try
            {
                form.Activate();
                SetForegroundWindow(form.Handle);
                box.Focus();
                await Task.Delay(400);

                // 注入必须在非 UI 线程：SendInput 是异步投递到消息队列的，
                // 在 UI 线程上同步阻塞会让消息泵没机会处理，字符永远进不来。
                await Task.Run(() => Injector.Type(Sample, form.Handle));

                actual = await WaitForStableText(box);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                form.Close();
            }
        };

        Application.Run(form);

        if (failure is not null)
        {
            Console.WriteLine($"❌ 注入抛出异常: {failure.Message}");
            return 1;
        }

        // TextBox 收到 VK_RETURN 会插入 \r\n，比对前规范化
        string normalized = (actual ?? "").Replace("\r\n", "\n");

        if (normalized == Sample)
        {
            Console.WriteLine($"✅ 注入正确，{Sample.Length} 个 UTF-16 码元全部还原");
            Console.WriteLine("   覆盖: ASCII / 符号 / 中文 / emoji 代理对 / 换行");
            return 0;
        }

        Console.WriteLine("❌ 注入结果与样本不符");
        Console.WriteLine($"   期望 ({Sample.Length} 码元): {Escape(Sample)}");
        Console.WriteLine($"   实际 ({normalized.Length} 码元): {Escape(normalized)}");
        return 1;
    }

    /// <summary>等文本长度连续若干次不再变化，说明消息泵已经处理完所有 WM_CHAR。</summary>
    private static async Task<string> WaitForStableText(TextBox box)
    {
        int last = -1, stable = 0;
        for (int i = 0; i < 120 && stable < 4; i++)
        {
            await Task.Delay(50);
            int len = box.TextLength;
            stable = len == last ? stable + 1 : 0;
            last = len;
        }
        return box.Text;
    }

    private static string Escape(string s) =>
        s.Replace("\r", "\\r").Replace("\n", "\\n");

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint hWnd);
}
