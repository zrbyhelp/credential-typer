using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace CredentialTyper.Core.Service;

/// <summary>枚举本机所有可用于局域网的 IPv4 地址，写进二维码供手机逐个尝试。</summary>
public static class LocalAddresses
{
    // Interface names/descriptions used by common virtual adapters.  These
    // addresses are not reachable from a phone on the physical LAN (for
    // example 172.29.x.x from WSL), yet they are often enumerated before the
    // real Ethernet/Wi‑Fi adapter and make QR pairing appear to fail.
    private static readonly string[] VirtualMarkers =
    {
        "vethernet", "hyper-v", "hyperv", "wsl", "docker", "podman",
        "vmware", "virtualbox", "host-only", "tap-windows", "tun",
        "wireguard", "tailscale", "zerotier", "vpn", "loopback",
        "virbr", "vboxnet", "br-", "veth", "bluetooth", "wan miniport",
        "teredo", "ip-https", "6to4", "kernel debug",
    };

    /// <summary>供测试和枚举逻辑共用：判断网卡是否明显是虚拟/隧道接口。</summary>
    internal static bool IsVirtualInterfaceName(string? name, string? description = null)
    {
        var text = $"{name} {description}".ToLowerInvariant();
        return VirtualMarkers.Any(text.Contains);
    }

    public static string[] LanIpv4()
    {
        var list = new List<string>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            if (IsVirtualInterfaceName(ni.Name, ni.Description)) continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (IPAddress.IsLoopback(ua.Address)) continue;
                if (ua.Address.ToString().StartsWith("169.254.")) continue; // APIPA，连不通
                list.Add(ua.Address.ToString());
            }
        }

        // A few OEM Wi‑Fi drivers expose a localized/opaque adapter name that
        // is unfortunately classified as virtual by the conservative marker
        // list above.  Do not generate an unusable QR in that case: fall back
        // to every active, non-loopback IPv4 (still excluding APIPA and tunnel
        // interfaces).  The phone already tries each address and the user can
        // see the actual address in the connection-code line.
        if (list.Count == 0)
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(ua.Address)) continue;
                    if (ua.Address.ToString().StartsWith("169.254.")) continue;
                    list.Add(ua.Address.ToString());
                }
            }
        }
        return list.Distinct().ToArray();
    }
}
