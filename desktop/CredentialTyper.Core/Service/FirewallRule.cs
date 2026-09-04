using System.Diagnostics;

namespace CredentialTyper.Core.Service;

/// <summary>
/// 在启动时用 netsh 幂等地放行本机 LAN 监听端口的入站 TCP。
///
/// 手机配对失败最常见的“电脑不可达”其实是 Windows 防火墙拦掉了入站连接：
/// 手机的 TCP SYN 到不了监听 socket，握手根本没机会开始。桌面进程本身以
/// 管理员权限运行（app.manifest requireAdministrator），因此可以直接写入
/// 防火墙规则，免去用户手动敲 netsh。
///
/// 规则按固定名字管理：每次启动先删同名旧规则再按“当前实际端口”新增，
/// 这样端口回退（47820→47821）后规则也会跟着更新，不会残留错端口。
/// 只放行 域/专用 网络（家庭/公司 LAN），不动公用网络。
/// </summary>
public static class FirewallRule
{
    private const string RuleName = "CredentialTyper-Pairing";

    /// <summary>确保入站 TCP <paramref name="port"/> 被放行。best-effort，不抛异常。</summary>
    /// <returns>是否成功（netsh 退出码 0）。失败时通过 <paramref name="log"/> 报告。</returns>
    public static bool EnsureAllowed(int port, Action<string>? log = null)
    {
        try
        {
            // 先删旧的同名规则（可能有多条/旧端口），忽略“未找到”的失败。
            RunNetsh($"advfirewall firewall delete rule name=\"{RuleName}\"", log, quietFail: true);

            var ok = RunNetsh(
                "advfirewall firewall add rule " +
                $"name=\"{RuleName}\" dir=in action=allow protocol=TCP " +
                $"localport={port} profile=domain,private " +
                "description=\"允许手机在局域网内扫码配对/重连凭据填充器\"",
                log);

            if (ok) log?.Invoke($"已放行入站 TCP {port}（域/专用网络）。");
            else log?.Invoke($"防火墙放行未成功，若手机连不上请手动放行 TCP {port}。");
            return ok;
        }
        catch (Exception e)
        {
            log?.Invoke($"配置防火墙失败：{e.Message}");
            return false;
        }
    }

    private static bool RunNetsh(string arguments, Action<string>? log, bool quietFail = false)
    {
        var psi = new ProcessStartInfo("netsh", arguments)
        {
            CreateNoWindow = true,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            if (!quietFail) log?.Invoke("无法启动 netsh 配置防火墙。");
            return false;
        }

        if (!proc.WaitForExit(5000))
        {
            try { proc.Kill(); } catch { /* 收尾忽略 */ }
            if (!quietFail) log?.Invoke("netsh 配置防火墙超时。");
            return false;
        }

        return proc.ExitCode == 0;
    }
}
