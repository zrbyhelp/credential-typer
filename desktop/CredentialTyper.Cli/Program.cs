using System.Text;
using CredentialTyper.Cli;
using CredentialTyper.Core.Automation;
using CredentialTyper.Core.Diagnostics;
using CredentialTyper.Core.Input;
using CredentialTyper.Core.Service;
using CredentialTyper.Transport.Wire;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length == 0)
{
    Console.WriteLine("""
        开发期测试工具。

          ct selftest          非交互式验证注入路径（自建靶窗口，注入后读回比对）
          ct diagnose          打印输入环境诊断
          ct window            倒计时 3 秒后打印当时的前台窗口信息
          ct type <文本>       倒计时 5 秒后把文本注入当时的前台窗口

          ct serve [端口]      启动桌面 LAN 服务，出二维码文本（默认端口 47820）
          ct phone pair <码>   手机模拟器：用二维码文本配对，然后交互式发送 fill
          ct phone reconnect   手机模拟器：用上次配对信息重连

        端到端联调：一个终端 ct serve，另一个 ct phone pair <码>，
        聚焦记事本/浏览器输入框，在 phone 终端打字即注入到该框。
        """);
    return 0;
}

switch (args[0])
{
    case "selftest":
        return SelfTest.Run();

    case "diagnose":
    {
        var report = InputEnvironment.Check();
        Console.WriteLine($"窗口站    : {report.WindowStation}");
        Console.WriteLine($"线程桌面  : {report.ThreadDesktop}");
        Console.WriteLine($"输入桌面  : {report.InputDesktop ?? "<打不开>"}");
        Console.WriteLine($"可以注入  : {(report.CanInject ? "是" : "否")}");
        Console.WriteLine($"说明      : {report.Explain()}");

        var mine = IntegrityLevel.OfCurrentProcess();
        Console.WriteLine($"本进程    : {IntegrityLevel.Describe(mine)}");

        var fgCtx = WindowContext.CaptureForeground();
        if (fgCtx is not null)
        {
            var theirs = IntegrityLevel.OfForegroundWindow(fgCtx.Handle);
            Console.WriteLine($"前台窗口  : {fgCtx.ProcessName} — {fgCtx.Title}");
            Console.WriteLine($"前台进程  : {IntegrityLevel.Describe(theirs)}");
            if (mine != IntegrityLevel.Level.Unknown && theirs != IntegrityLevel.Level.Unknown && theirs > mine)
                Console.WriteLine("            ⚠ 目标级别高于本进程 —— UIPI 会静默拦截注入。");
        }

        var (sent, err) = InputEnvironment.SendProbe();
        Console.WriteLine($"探针      : SendInput 接受 {sent}/2 个事件，Win32 错误 {err}");
        if (sent != 2)
            Console.WriteLine("            环境检查通过但探针被拒 —— 属于运行时阻塞"
                + "（UIPI、BlockInput、或安全软件的输入钩子）。");

        if (sent != 2)
        {
            bool unblocked = InputEnvironment.TryUnblockInput();
            var (retry, retryErr) = InputEnvironment.SendProbe();
            Console.WriteLine($"解除阻塞  : BlockInput(false) 返回 {unblocked}，"
                + $"重试探针 {retry}/2（错误 {retryErr}）");
            if (retry == 2)
                Console.WriteLine("            确认原因是 BlockInput —— 有程序锁住了输入。");
        }

        return report.CanInject && sent == 2 ? 0 : 1;
    }

    case "window":
        Countdown(3);
        var ctx = WindowContext.CaptureForeground();
        if (ctx is null)
        {
            Console.WriteLine("拿不到前台窗口。");
            return 1;
        }
        Console.WriteLine($"句柄  : 0x{ctx.Handle:X}");
        Console.WriteLine($"标题  : {ctx.Title}");
        Console.WriteLine($"进程  : {ctx.ProcessName}");
        Console.WriteLine($"路径  : {ctx.ProcessPath}");
        return 0;

    case "type":
        if (args.Length < 2)
        {
            Console.WriteLine("用法: ct type <文本>");
            return 1;
        }

        string text = string.Join(' ', args[1..]);
        Countdown(5);

        var target = WindowContext.CaptureForeground();
        if (target is null)
        {
            Console.WriteLine("拿不到前台窗口。");
            return 1;
        }

        Console.WriteLine($"目标: {target.ProcessName} — {target.Title}");
        try
        {
            Injector.Type(text, target.Handle);
            Console.WriteLine($"已注入 {text.Length} 个字符。");
            return 0;
        }
        catch (InjectionAbortedException ex)
        {
            Console.WriteLine($"注入失败: {ex.Message}");
            return 1;
        }

    case "serve":
    {
        int p = args.Length > 1 && int.TryParse(args[1], out var parsed) ? parsed : 47820;
        return await ServeAsync(p);
    }

    case "phone":
        if (args.Length >= 3 && args[1] == "pair") return await PhoneSim.PairAsync(args[2]);
        if (args.Length >= 2 && args[1] == "reconnect") return await PhoneSim.ReconnectAsync();
        Console.WriteLine("用法: ct phone pair <二维码文本>  |  ct phone reconnect");
        return 1;

    default:
        Console.WriteLine($"未知命令: {args[0]}");
        return 1;
}

static async Task<int> ServeAsync(int port)
{
    var identity = DesktopIdentity.LoadOrCreate();
    var pairing = new PairingStore();
    using var server = new DesktopServer(identity, pairing)
    {
        OnLog = m => Console.WriteLine($"[服务] {m}"),
        OnInjected = path => Console.WriteLine($"[注入] 路径 = {path}"),
        OnPaired = () => Console.WriteLine("配对已保存到本机。"),
        OnPairingRequest = async (phonePub, _) =>
        {
            Console.WriteLine($"\n收到配对请求，手机指纹: {Protocol.Fingerprint(phonePub)}");
            Console.Write("与手机上显示的一致吗？接受配对 [y/N]: ");
            var ans = await Task.Run(Console.ReadLine);
            return ans?.Trim().ToLowerInvariant() is "y" or "yes";
        },
    };

    server.Start(port);
    Console.WriteLine($"桌面服务已启动，端口 {server.Port}。");
    Console.WriteLine($"桌面身份指纹: {server.DesktopFingerprint}");

    if (!pairing.HasPaired)
    {
        var qr = server.OpenPairing();
        Console.WriteLine("\n未配对。在另一个终端运行（把整行复制过去）：");
        Console.WriteLine($"\n  dotnet run --project CredentialTyper.Cli -- phone pair {qr.ToQrText()}\n");
        Console.WriteLine($"LAN 地址: {string.Join(", ", qr.Host)}   端口: {qr.Port}");
    }
    else
    {
        Console.WriteLine("本机已配对，手机端可直接 ct phone reconnect。");
    }

    Console.WriteLine("\n按 Enter 停止服务。");
    await Task.Run(Console.ReadLine);
    return 0;
}

static void Countdown(int seconds)
{
    for (int i = seconds; i > 0; i--)
    {
        Console.Write($"\r{i} 秒后执行，请切到目标窗口... ");
        Thread.Sleep(1000);
    }
    Console.WriteLine("\r开始                              ");
}
