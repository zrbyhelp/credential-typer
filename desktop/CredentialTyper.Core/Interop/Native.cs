using System.Runtime.InteropServices;

namespace CredentialTyper.Core.Interop;

/// <summary>
/// Win32 声明。
/// x64 下 sizeof(INPUT) == 40：type(4) + 4 字节对齐填充 + union(32，取 MOUSEINPUT 的大小)。
/// C# 的默认 Sequential 布局会自动算对，不需要手动填充。
/// </summary>
internal static class Native
{
    internal const uint INPUT_KEYBOARD = 1;
    internal const uint KEYEVENTF_KEYUP = 0x0002;
    internal const uint KEYEVENTF_UNICODE = 0x0004;
    internal const ushort VK_RETURN = 0x0D;
    internal const ushort VK_TAB = 0x09;

    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public nint dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct HARDWAREINPUT
    {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct INPUT
    {
        public uint type;
        public InputUnion U;
    }

    /// <summary>以 UNICODE 方式发送一个 UTF-16 码元。wVk 必须为 0，码元放在 wScan。</summary>
    internal static INPUT UnicodeUnit(char unit, bool up) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion
        {
            ki = new KEYBDINPUT
            {
                wVk = 0,
                wScan = unit,
                dwFlags = KEYEVENTF_UNICODE | (up ? KEYEVENTF_KEYUP : 0),
            },
        },
    };

    /// <summary>发送一个真实虚拟键（回车、Tab 等无法用 UNICODE 方式表达的键）。</summary>
    internal static INPUT VirtualKey(ushort vk, bool up) => new()
    {
        type = INPUT_KEYBOARD,
        U = new InputUnion
        {
            ki = new KEYBDINPUT
            {
                wVk = vk,
                wScan = 0,
                dwFlags = up ? KEYEVENTF_KEYUP : 0,
            },
        },
    };

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint SendInput(uint nInputs, [In] INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    internal static extern nint GetForegroundWindow();

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern int GetWindowTextW(nint hWnd, [Out] char[] lpString, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    internal static extern int GetWindowTextLengthW(nint hWnd);

    [DllImport("user32.dll", SetLastError = true)]
    internal static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern nint OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(nint hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(nint hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);

    // ── WM_CHAR 消息级注入 ──────────────────────────────────────────────
    // SendInput 走硬件输入队列；WM_CHAR 直接投递给控件，绕过那一层。
    internal const uint WM_CHAR = 0x0102;

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern nint SendMessageW(nint hWnd, uint msg, nint wParam, nint lParam);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessageW(nint hWnd, uint msg, nint wParam, nint lParam);

    // ── 定位前台窗口里真正获得焦点的子控件 ──────────────────────────────
    // 前台窗口是顶层窗口，文本实际进的是它内部那个获得焦点的编辑控件，
    // 得靠 GetGUIThreadInfo 拿到那个 HWND 才能把 WM_CHAR 投准。
    internal const uint GUI_THREADINFO_CB = 72; // x64 下 sizeof(GUITHREADINFO)

    [StructLayout(LayoutKind.Sequential)]
    internal struct RECT { public int left, top, right, bottom; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GUITHREADINFO
    {
        public uint cbSize;
        public uint flags;
        public nint hwndActive;
        public nint hwndFocus;
        public nint hwndCapture;
        public nint hwndMenuOwner;
        public nint hwndMoveSize;
        public nint hwndCaret;
        public RECT rcCaret;
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetGUIThreadInfo(uint idThread, ref GUITHREADINFO lpgui);

    /// <summary>返回指定顶层窗口内当前获得键盘焦点的子控件 HWND；拿不到则回退到窗口本身。</summary>
    internal static nint FocusedControlOf(nint topLevel)
    {
        uint tid = GetWindowThreadProcessId(topLevel, out _);
        var gti = new GUITHREADINFO { cbSize = GUI_THREADINFO_CB };
        if (GetGUIThreadInfo(tid, ref gti) && gti.hwndFocus != 0)
            return gti.hwndFocus;
        return topLevel;
    }
}
