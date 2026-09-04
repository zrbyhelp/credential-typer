using System.Runtime.InteropServices;

namespace CredentialTyper.Core.Diagnostics;

/// <summary>
/// 检查当前进程是否处于能够注入输入的环境。
///
/// SendInput 失败时返回 0 且不设置错误码（MSDN 明确说明 UIPI 阻塞时
/// GetLastError 和返回值都不会指出原因），所以必须靠环境检查来给出可行动的诊断。
/// </summary>
public static class InputEnvironment
{
    private const int UOI_NAME = 2;
    private const uint DESKTOP_READOBJECTS = 0x0001;

    public sealed record Report(
        string WindowStation,
        string ThreadDesktop,
        string? InputDesktop,
        bool IsInteractiveStation,
        bool ThreadDesktopIsInput)
    {
        public bool CanInject => IsInteractiveStation && ThreadDesktopIsInput;

        public string Explain()
        {
            if (CanInject) return "环境正常，可以注入。";

            if (!IsInteractiveStation)
                return $"当前进程运行在非交互式窗口站 “{WindowStation}”（交互式会话应为 WinSta0）。" +
                       "服务、计划任务、以及部分后台启动方式会落到这里，SendInput 无法投递到用户桌面。" +
                       "需要在用户的交互式会话中启动本程序。";

            if (InputDesktop is null)
                return "无法打开输入桌面 —— 通常意味着屏幕已锁定、正在显示 UAC 提权对话框、" +
                       "或处于安全桌面（Ctrl+Alt+Del）。解锁后重试。";

            return $"当前线程在桌面 “{ThreadDesktop}”，但接收输入的桌面是 “{InputDesktop}”。" +
                   "两者不一致时 SendInput 会被静默丢弃。";
        }
    }

    public static Report Check()
    {
        string station = ReadObjectName(GetProcessWindowStation());
        string threadDesktop = ReadObjectName(GetThreadDesktop(GetCurrentThreadId()));

        string? inputDesktop = null;
        nint hInput = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        if (hInput != 0)
        {
            try { inputDesktop = ReadObjectName(hInput); }
            finally { CloseDesktop(hInput); }
        }

        // 交互式会话的窗口站固定叫 WinSta0；服务等非交互进程会拿到 Service-0x0-xxxx$ 这类名字
        bool interactive = station.Equals("WinSta0", StringComparison.OrdinalIgnoreCase);
        bool desktopMatches = inputDesktop is not null
            && threadDesktop.Equals(inputDesktop, StringComparison.OrdinalIgnoreCase);

        return new Report(station, threadDesktop, inputDesktop, interactive, desktopMatches);
    }

    /// <summary>
    /// 发一个无害的探针按键（F24，几乎没有程序会响应）看 SendInput 是否被接受。
    /// 环境检查通过但探针失败，说明是 UIPI 或 BlockInput 之类的运行时阻塞，
    /// 而不是窗口站/桌面配置问题。
    /// </summary>
    public static (uint Sent, int Error) SendProbe()
    {
        var probe = new[]
        {
            Interop.Native.VirtualKey(VK_F24, up: false),
            Interop.Native.VirtualKey(VK_F24, up: true),
        };
        uint sent = Interop.Native.SendInput(2, probe, Marshal.SizeOf<Interop.Native.INPUT>());
        return (sent, Marshal.GetLastWin32Error());
    }

    private const ushort VK_F24 = 0x87;

    /// <summary>
    /// 尝试解除输入阻塞。某个线程调用过 BlockInput(TRUE) 时，所有 SendInput
    /// 都会返回 0 且不设错误码。仅用于诊断 —— 正常运行时不该主动解除别的程序设的锁。
    /// </summary>
    public static bool TryUnblockInput() => BlockInput(false);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BlockInput([MarshalAs(UnmanagedType.Bool)] bool fBlockIt);


    private static string ReadObjectName(nint handle)
    {
        if (handle == 0) return "<null>";

        var buf = new char[256];
        return GetUserObjectInformationW(handle, UOI_NAME, buf, (uint)(buf.Length * sizeof(char)), out uint needed)
            ? new string(buf, 0, Math.Max(0, (int)(needed / sizeof(char)) - 1))
            : "<unknown>";
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint GetProcessWindowStation();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint GetThreadDesktop(uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint OpenInputDesktop(uint dwFlags, [MarshalAs(UnmanagedType.Bool)] bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseDesktop(nint hDesktop);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetUserObjectInformationW(nint hObj, int nIndex, [Out] char[] pvInfo, uint nLength, out uint lpnLengthNeeded);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
}
