using System.Text;
using CredentialTyper.Core.Automation;
using CredentialTyper.Core.Diagnostics;
using CredentialTyper.Core.Input;

namespace CredentialTyper.Check;

/// <summary>
/// 注入路径的实机自检工具。
///
/// 存在的理由：SendInput 能否投递完全取决于运行环境（完整性级别、窗口站、桌面、
/// 输入锁、安全软件钩子），而失败时它返回 0 且不设置错误码。单元测试能锁住编码逻辑，
/// 锁不住「这台机器到底收不收」，所以需要一个能在任意机器上双击运行的验证程序。
/// </summary>
internal sealed class CheckForm : Form
{
    private const string Sample = "user@example.com\nP@ssw0rd!#$%^&*()\n中文密码测试\n🔐🎉";

    private readonly TextBox _diagnostics;
    private readonly TextBox _target;
    private readonly Label _status;
    private readonly Button _selfInject;
    private readonly Button _crossInject;
    private readonly Button _selfMsg;
    private readonly Button _crossMsg;
    private readonly Button _uiaProbe;
    private readonly Button _rediagnose;
    private readonly Button _copy;

    public CheckForm()
    {
        Text = "注入自检 — Credential Typer";
        Width = 780;
        Height = 660;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Microsoft YaHei UI", 9F);

        _diagnostics = new TextBox
        {
            Dock = DockStyle.Top,
            Height = 190,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = Color.FromArgb(250, 250, 250),
            Font = new Font("Consolas", 9F),
        };

        var hint = new Label
        {
            Dock = DockStyle.Top,
            Height = 56,
            Padding = new Padding(4, 8, 4, 4),
            Text = "下面是注入靶区。「自检」把样本注入这里再读回比对；「跨窗口」倒计时后打进你切过去的窗口。"
                 + "\nSendInput = 硬件输入队列（产品首选）；WM_CHAR = 消息级后备，SendInput 不通时试它。",
        };

        _target = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            AcceptsReturn = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 11F),
        };

        _status = new Label
        {
            Dock = DockStyle.Top,
            Height = 30,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(4, 0, 0, 0),
            Text = "就绪",
        };

        _selfInject = MakeButton("SendInput 自检（本窗口）", 210, OnSelfInject);
        _crossInject = MakeButton("SendInput 跨窗口（5 秒后）", 210, OnCrossInject);
        _selfMsg = MakeButton("WM_CHAR 自检（本窗口）", 210, OnSelfMessageInject);
        _crossMsg = MakeButton("WM_CHAR 跨窗口（5 秒后）", 210, OnCrossMessageInject);
        _uiaProbe = MakeButton("UIA 识别字段（5 秒后）", 210, OnUiaProbe);
        _rediagnose = MakeButton("重新诊断", 100, (_, _) => RunDiagnostics());
        _copy = MakeButton("复制诊断信息", 120, OnCopy);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 84,
            Padding = new Padding(2),
        };
        buttons.Controls.AddRange([_selfInject, _crossInject, _selfMsg, _crossMsg, _uiaProbe, _rediagnose, _copy]);

        var bottom = new Panel { Dock = DockStyle.Bottom, Height = 120 };
        bottom.Controls.Add(_status);
        bottom.Controls.Add(buttons);

        // Dock 按添加的逆序生效：先加 Fill，再加 Top，最后加 Bottom
        Controls.Add(_target);
        Controls.Add(hint);
        Controls.Add(_diagnostics);
        Controls.Add(bottom);

        Shown += (_, _) => RunDiagnostics();
    }

    private static Button MakeButton(string text, int width, EventHandler onClick)
    {
        var b = new Button { Text = text, Width = width, Height = 34, Margin = new Padding(4, 2, 4, 2) };
        b.Click += onClick;
        return b;
    }

    private void RunDiagnostics()
    {
        var sb = new StringBuilder();
        var report = InputEnvironment.Check();

        sb.AppendLine($"窗口站      : {report.WindowStation}");
        sb.AppendLine($"线程桌面    : {report.ThreadDesktop}");
        sb.AppendLine($"输入桌面    : {report.InputDesktop ?? "<打不开>"}");

        var mine = IntegrityLevel.OfCurrentProcess();
        sb.AppendLine($"本进程权限  : {IntegrityLevel.Describe(mine)}");

        var fg = WindowContext.CaptureForeground();
        if (fg is not null)
        {
            var theirs = IntegrityLevel.OfForegroundWindow(fg.Handle);
            sb.AppendLine($"前台窗口    : {fg.ProcessName} — {fg.Title}");
            sb.AppendLine($"前台权限    : {IntegrityLevel.Describe(theirs)}");
            if (mine != IntegrityLevel.Level.Unknown && theirs != IntegrityLevel.Level.Unknown && theirs > mine)
                sb.AppendLine("              ⚠ 目标权限高于本程序，UIPI 会静默拦截注入。"
                            + "请以管理员身份重新运行本程序。");
        }

        var (sent, err) = InputEnvironment.SendProbe();
        sb.AppendLine($"SendInput   : 探针被接受 {sent}/2（Win32 错误 {err}）");
        sb.AppendLine();

        if (!report.CanInject)
            sb.AppendLine($"❌ {report.Explain()}");
        else if (sent != 2)
            sb.AppendLine("❌ 窗口站与桌面都正常，但 SendInput 拒绝了探针。属于运行时阻塞："
                        + "UIPI、BlockInput、安全软件的输入钩子，或这台机器没有真实的输入栈"
                        + "（无头虚拟机 / 未连接显示器的云主机常见）。"
                        + "→ 试试下面的「WM_CHAR」两个按钮：消息级注入绕过输入队列，"
                        + "在 SendInput 不通的机器上常常仍能工作。");
        else
            sb.AppendLine("✅ 环境正常，SendInput 可用。可以运行自检。");

        _diagnostics.Text = sb.ToString();
        SetStatus(report.CanInject && sent == 2 ? "环境正常，点「运行自检」验证完整注入路径" : "环境异常，见上方诊断",
                  report.CanInject && sent == 2 ? Color.DarkGreen : Color.Firebrick);
    }

    private async void OnSelfInject(object? sender, EventArgs e)
    {
        SetButtons(false);
        try
        {
            _target.Clear();
            _target.Focus();
            SetStatus("注入中，请勿点击其他窗口…", Color.DarkBlue);
            await Task.Delay(300);

            nint expected = Handle;
            await Task.Run(() => Injector.Type(Sample, expected));

            string actual = (await WaitForStableText()).Replace("\r\n", "\n");

            if (actual == Sample)
                SetStatus($"✅ 通过 — {Sample.Length} 个 UTF-16 码元全部还原"
                        + "（ASCII / 符号 / 中文 / emoji 代理对 / 换行）", Color.DarkGreen);
            else
                SetStatus($"❌ 不符 — 期望 {Sample.Length} 码元，实得 {actual.Length}："
                        + Escape(actual), Color.Firebrick);
        }
        catch (InjectionAbortedException ex)
        {
            SetStatus("❌ " + ex.Message, Color.Firebrick);
        }
        catch (Exception ex)
        {
            SetStatus("❌ 异常: " + ex.Message, Color.Firebrick);
        }
        finally
        {
            SetButtons(true);
        }
    }

    private async void OnCrossInject(object? sender, EventArgs e)
    {
        string text = _target.Text.Length > 0 ? _target.Text : Sample;

        SetButtons(false);
        try
        {
            for (int i = 5; i > 0; i--)
            {
                SetStatus($"{i} 秒后注入 — 现在切到目标窗口（记事本、浏览器输入框…）", Color.DarkBlue);
                await Task.Delay(1000);
            }

            var target = WindowContext.CaptureForeground();
            if (target is null)
            {
                SetStatus("❌ 拿不到前台窗口", Color.Firebrick);
                return;
            }

            if (target.Handle == Handle)
            {
                SetStatus("⚠ 前台还是本窗口 —— 跨窗口注入需要你切到别的程序再等倒计时结束", Color.DarkOrange);
                return;
            }

            var theirs = IntegrityLevel.OfForegroundWindow(target.Handle);
            var mine = IntegrityLevel.OfCurrentProcess();

            await Task.Run(() => Injector.Type(text, target.Handle));
            SetStatus($"✅ 已注入 {text.Length} 个码元到 {target.ProcessName}"
                    + $"（对方权限 {IntegrityLevel.Describe(theirs)}）", Color.DarkGreen);
        }
        catch (InjectionAbortedException ex)
        {
            SetStatus("❌ " + ex.Message, Color.Firebrick);
        }
        catch (Exception ex)
        {
            SetStatus("❌ 异常: " + ex.Message, Color.Firebrick);
        }
        finally
        {
            SetButtons(true);
        }
    }

    private async void OnSelfMessageInject(object? sender, EventArgs e)
    {
        SetButtons(false);
        try
        {
            _target.Clear();
            _target.Focus();
            SetStatus("WM_CHAR 注入中…", Color.DarkBlue);
            await Task.Delay(200);

            // 直接投给靶区文本框的 HWND，不必解析焦点
            nint control = _target.Handle;
            await Task.Run(() => MessageInjector.Type(Sample, control));

            string actual = (await WaitForStableText()).Replace("\r\n", "\n");

            if (actual == Sample)
                SetStatus($"✅ WM_CHAR 通过 — {Sample.Length} 码元全部还原。"
                        + "这台机器可用消息级注入，即使 SendInput 不通。", Color.DarkGreen);
            else
                SetStatus($"❌ WM_CHAR 不符 — 期望 {Sample.Length}，实得 {actual.Length}："
                        + Escape(actual), Color.Firebrick);
        }
        catch (InjectionAbortedException ex)
        {
            SetStatus("❌ " + ex.Message, Color.Firebrick);
        }
        catch (Exception ex)
        {
            SetStatus("❌ 异常: " + ex.Message, Color.Firebrick);
        }
        finally
        {
            SetButtons(true);
        }
    }

    private async void OnCrossMessageInject(object? sender, EventArgs e)
    {
        string text = _target.Text.Length > 0 ? _target.Text : Sample;

        SetButtons(false);
        try
        {
            for (int i = 5; i > 0; i--)
            {
                SetStatus($"{i} 秒后 WM_CHAR 注入 — 现在切到目标窗口的输入框", Color.DarkBlue);
                await Task.Delay(1000);
            }

            var target = WindowContext.CaptureForeground();
            if (target is null) { SetStatus("❌ 拿不到前台窗口", Color.Firebrick); return; }
            if (target.Handle == Handle)
            {
                SetStatus("⚠ 前台还是本窗口 —— 跨窗口需要你切到别的程序再等倒计时结束", Color.DarkOrange);
                return;
            }

            nint control = 0;
            await Task.Run(() => control = MessageInjector.TypeToForegroundFocus(text));
            SetStatus($"✅ 已向 {target.ProcessName} 的焦点控件（HWND 0x{control:X}）投递 "
                    + $"{text.Length} 码元 WM_CHAR。请到那个窗口确认是否收到。", Color.DarkGreen);
        }
        catch (InjectionAbortedException ex)
        {
            SetStatus("❌ " + ex.Message, Color.Firebrick);
        }
        catch (Exception ex)
        {
            SetStatus("❌ 异常: " + ex.Message, Color.Firebrick);
        }
        finally
        {
            SetButtons(true);
        }
    }

    private async void OnUiaProbe(object? sender, EventArgs e)
    {
        SetButtons(false);
        try
        {
            for (int i = 5; i > 0; i--)
            {
                SetStatus($"{i} 秒后识别 — 切到登录页并点中密码框", Color.DarkBlue);
                await Task.Delay(1000);
            }

            // FlaUI 要求在 MTA 线程上跑；UI 线程是 STA，放到后台线程
            var (text, isPwd) = await Task.Run(() =>
            {
                using var locator = new FormLocator();
                var focused = locator.CaptureFocused();
                var fg = WindowContext.CaptureForeground();

                var sb = new StringBuilder();
                sb.Append(focused is null
                    ? "焦点字段: <取不到>"
                    : $"焦点字段: {focused.Kind}｜name=\"{Trunc(focused.Name)}\"｜HWND=0x{focused.NativeWindowHandle:X}");
                sb.Append("  ‖  ");
                sb.Append(fg is null ? "前台: <无>" : $"前台: {fg.ProcessName}");
                return (sb.ToString(), focused?.Kind == FormLocator.FieldKind.Password);
            });

            SetStatus((isPwd ? "✅ 密码框已识别  " : "ℹ ") + text,
                      isPwd ? Color.DarkGreen : Color.DarkBlue);
        }
        catch (Exception ex)
        {
            SetStatus("❌ UIA 异常: " + ex.Message, Color.Firebrick);
        }
        finally
        {
            SetButtons(true);
        }
    }

    private static string Trunc(string s) => s.Length <= 24 ? s : s[..24] + "…";

    private void OnCopy(object? sender, EventArgs e)
    {
        // 诊断信息里没有任何凭据，可以安全复制
        Clipboard.SetText(_diagnostics.Text + Environment.NewLine + _status.Text);
        SetStatus("诊断信息已复制到剪贴板", Color.DarkBlue);
    }

    /// <summary>等文本长度连续若干次不变，说明消息泵已经处理完所有 WM_CHAR。</summary>
    private async Task<string> WaitForStableText()
    {
        int last = -1, stable = 0;
        for (int i = 0; i < 120 && stable < 4; i++)
        {
            await Task.Delay(50);
            int len = _target.TextLength;
            stable = len == last ? stable + 1 : 0;
            last = len;
        }
        return _target.Text;
    }

    private void SetButtons(bool enabled)
    {
        _selfInject.Enabled = _crossInject.Enabled = _selfMsg.Enabled = _crossMsg.Enabled
            = _uiaProbe.Enabled = _rediagnose.Enabled = _copy.Enabled = enabled;
    }

    private void SetStatus(string text, Color color)
    {
        _status.Text = text;
        _status.ForeColor = color;
    }

    private static string Escape(string s) => s.Replace("\r", "\\r").Replace("\n", "\\n");
}
