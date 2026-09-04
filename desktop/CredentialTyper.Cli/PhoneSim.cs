using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CredentialTyper.Transport.Crypto;
using CredentialTyper.Transport.Wire;

namespace CredentialTyper.Cli;

/// <summary>
/// 手机端模拟器（开发测试用，代替尚未构建的 Flutter App）。
/// 复用与真机完全相同的 Wire 协议（连接前导 + Noise IK/KK + 分帧 + fill 帧），
/// 因此它能验证整条桌面管线；Flutter 端按同一 PROTOCOL.md 实现即可互通。
///
/// 注意：这是测试工具，身份明文存盘、密码走 Console string —— 真机手机端不这样做。
/// </summary>
public static class PhoneSim
{
    private sealed class State
    {
        [JsonPropertyName("priv")] public string Priv { get; set; } = "";
        [JsonPropertyName("desktopPub")] public string DesktopPub { get; set; } = "";
        [JsonPropertyName("host")] public string Host { get; set; } = "";
        [JsonPropertyName("port")] public int Port { get; set; }
    }

    private static string StatePath =>
        Path.Combine(AppContext.BaseDirectory, "phone-sim.json");

    private static (Dh.KeyPair Kp, State S) LoadOrCreate()
    {
        if (File.Exists(StatePath))
        {
            var s = JsonSerializer.Deserialize<State>(File.ReadAllText(StatePath))!;
            return (Dh.FromPrivate(Base64Url.Decode(s.Priv)), s);
        }
        var kp = Dh.Generate();
        var st = new State { Priv = Base64Url.Encode(kp.Private) };
        return (kp, st);
    }

    private static void Save(Dh.KeyPair kp, State s)
    {
        s.Priv = Base64Url.Encode(kp.Private);
        File.WriteAllText(StatePath, JsonSerializer.Serialize(s));
    }

    public static async Task<int> PairAsync(string qrText)
    {
        var (kp, s) = LoadOrCreate();
        QrPayload qr;
        try { qr = QrPayload.FromQrText(qrText); }
        catch (Exception e) { Console.WriteLine($"二维码解析失败: {e.Message}"); return 1; }

        Console.WriteLine($"桌面指纹（请与桌面端显示的核对）: {Protocol.Fingerprint(qr.SPubBytes)}");

        var tcp = await ConnectAnyAsync(qr.Host, qr.Port);
        if (tcp is null) { Console.WriteLine("无法连接桌面（所有地址均失败）。"); return 1; }

        using var client = tcp;
        var stream = client.GetStream();
        await stream.WriteAsync(new[] { Protocol.ConnectMode.Pair });   // 连接前导

        Session session;
        try
        {
            session = await Handshake.InitiatorPairAsync(stream, kp, qr.SPubBytes, qr.CodeBytes);
        }
        catch (Exception e) { Console.WriteLine($"配对握手失败: {e.Message}"); return 1; }

        s.DesktopPub = Base64Url.Encode(qr.SPubBytes);
        s.Host = client.Client.RemoteEndPoint is System.Net.IPEndPoint ep ? ep.Address.ToString() : qr.Host[0];
        s.Port = qr.Port;
        Save(kp, s);

        Console.WriteLine($"配对成功。手机指纹（桌面端应显示相同值）: {Protocol.Fingerprint(kp.Public)}");
        await InteractiveAsync(session);
        return 0;
    }

    public static async Task<int> ReconnectAsync()
    {
        var (kp, s) = LoadOrCreate();
        if (string.IsNullOrEmpty(s.DesktopPub)) { Console.WriteLine("尚未配对，先运行 ct phone pair <二维码>。"); return 1; }

        var tcp = await ConnectAnyAsync(new[] { s.Host }, s.Port);
        if (tcp is null) { Console.WriteLine($"无法连接 {s.Host}:{s.Port}。"); return 1; }

        using var client = tcp;
        var stream = client.GetStream();
        await stream.WriteAsync(new[] { Protocol.ConnectMode.Reconnect });

        Session session;
        try
        {
            session = await Handshake.InitiatorReconnectAsync(stream, kp, Base64Url.Decode(s.DesktopPub));
        }
        catch (Exception e) { Console.WriteLine($"重连握手失败: {e.Message}"); return 1; }

        Console.WriteLine("重连成功。");
        await InteractiveAsync(session);
        return 0;
    }

    private static async Task<TcpClient?> ConnectAnyAsync(IEnumerable<string> hosts, int port)
    {
        foreach (var h in hosts)
        {
            try
            {
                var c = new TcpClient();
                var connect = c.ConnectAsync(h, port);
                var done = await Task.WhenAny(connect, Task.Delay(1500));
                if (done == connect && c.Connected) { c.NoDelay = true; return c; }
                c.Dispose();
            }
            catch { /* 试下一个地址 */ }
        }
        return null;
    }

    /// <summary>
    /// 交互：后台收 ctx 打印当前焦点；前台读控制台每一行当作 fill 发出。
    /// 行首 "!" 表示注入后回车（如 "!admin" = 敲 admin 再回车）。输入空行退出。
    /// </summary>
    private static async Task InteractiveAsync(Session session)
    {
        using var cts = new CancellationTokenSource();
        var recv = Task.Run(async () =>
        {
            try
            {
                while (!cts.IsCancellationRequested)
                {
                    var frame = await session.ReceiveAsync(cts.Token);
                    if (frame.Length == 0) continue;
                    if (frame[0] == Session.Tag.Ctx)
                        Console.WriteLine($"\n[桌面焦点] {Encoding.UTF8.GetString(frame, 1, frame.Length - 1)}");
                    else if (frame[0] == Session.Tag.Pong)
                        Console.WriteLine("[pong]");
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception e) { Console.WriteLine($"\n连接断开: {e.Message}"); }
        }, cts.Token);

        Console.WriteLine("""

            —— 手机模拟器已连接 ——
            输入要注入到「桌面当前焦点框」的文本，回车发送。
            行首加 ! = 注入后再敲一个回车（如 !secret）。
            :ping 发心跳，空行退出。
            """);

        while (true)
        {
            var line = Console.ReadLine();
            if (string.IsNullOrEmpty(line)) break;

            if (line == ":ping")
            {
                await session.SendAsync(new[] { Session.Tag.Ping });
                continue;
            }

            bool enter = line.StartsWith('!');
            var text = enter ? line[1..] : line;
            var pw = Encoding.UTF8.GetBytes(text);

            var frame = new byte[2 + pw.Length];
            frame[0] = Session.Tag.Fill;
            frame[1] = (byte)(enter ? 0x01 : 0x00);
            pw.CopyTo(frame, 2);
            await session.SendAsync(frame);
            Array.Clear(frame);
            Console.WriteLine($"已发送 fill（{pw.Length} 字节{(enter ? " +回车" : "")}）");
        }

        cts.Cancel();
        try { await recv; } catch { }
        session.Dispose();
    }
}
