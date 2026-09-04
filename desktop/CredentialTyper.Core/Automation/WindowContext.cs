using CredentialTyper.Core.Interop;

namespace CredentialTyper.Core.Automation;

/// <summary>
/// 前台窗口的基础信息。这部分不涉及 UIA，纯 Win32，开销很小，
/// 可以在焦点变化时高频调用。
/// </summary>
/// <param name="Handle">窗口句柄。注入时用它校验焦点没有被抢走。</param>
/// <param name="Title">窗口标题。无 URL 时用于模糊匹配，属于低置信度信号。</param>
/// <param name="ProcessName">进程名，如 chrome.exe。</param>
/// <param name="ProcessPath">进程完整路径。同名进程可能来自不同安装位置。</param>
public sealed record WindowContext(nint Handle, string Title, string ProcessName, string ProcessPath)
{
    public static WindowContext? CaptureForeground()
    {
        nint hwnd = Native.GetForegroundWindow();
        return hwnd == 0 ? null : Capture(hwnd);
    }

    public static WindowContext Capture(nint hwnd)
    {
        string title = ReadWindowText(hwnd);
        string path = ReadProcessPath(hwnd);
        string name = path.Length == 0 ? "" : Path.GetFileName(path);
        return new WindowContext(hwnd, title, name, path);
    }

    private static string ReadWindowText(nint hwnd)
    {
        int len = Native.GetWindowTextLengthW(hwnd);
        if (len <= 0) return "";

        var buf = new char[len + 1];
        int written = Native.GetWindowTextW(hwnd, buf, buf.Length);
        return written <= 0 ? "" : new string(buf, 0, written);
    }

    private static string ReadProcessPath(nint hwnd)
    {
        if (Native.GetWindowThreadProcessId(hwnd, out uint pid) == 0 || pid == 0)
            return "";

        // PROCESS_QUERY_LIMITED_INFORMATION 是能拿到路径的最小权限，
        // 对大多数其他用户/较高完整性级别的进程也能成功。
        nint handle = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == 0) return "";

        try
        {
            var buf = new char[1024];
            uint size = (uint)buf.Length;
            return Native.QueryFullProcessImageNameW(handle, 0, buf, ref size)
                ? new string(buf, 0, (int)size)
                : "";
        }
        finally
        {
            Native.CloseHandle(handle);
        }
    }
}
