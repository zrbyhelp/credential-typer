using System.Runtime.InteropServices;
using CredentialTyper.Core.Interop;

namespace CredentialTyper.Core.Diagnostics;

/// <summary>
/// 读取进程的强制完整性级别。
///
/// UIPI 规则：完整性级别较低的进程无法向较高进程的窗口投递输入，
/// 且 SendInput 失败时既不设置错误码也不做任何提示。所以要给用户可行动的
/// 错误信息（"目标程序以管理员身份运行，请同样以管理员身份重启本程序"），
/// 就必须能读到两侧的级别。
/// </summary>
public static class IntegrityLevel
{
    private const int TokenIntegrityLevel = 25;
    private const uint TOKEN_QUERY = 0x0008;

    public enum Level
    {
        Unknown = -1,
        Untrusted = 0x0000,
        Low = 0x1000,
        Medium = 0x2000,
        MediumPlus = 0x2100,
        High = 0x3000,
        System = 0x4000,
    }

    public static Level OfCurrentProcess() => OfProcessHandle(GetCurrentProcess());

    /// <summary>
    /// 读取指定进程的完整性级别。打不开目标进程的 token（通常因为对方级别更高）
    /// 时返回 <see cref="Level.Unknown"/> —— 这个失败本身就是「对方更高」的强信号。
    /// </summary>
    public static Level OfProcessId(uint pid)
    {
        nint process = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == 0) return Level.Unknown;

        try { return OfProcessHandle(process); }
        finally { Native.CloseHandle(process); }
    }

    /// <summary>读取某个窗口所属进程的完整性级别。</summary>
    public static Level OfForegroundWindow(nint hwnd)
    {
        if (Native.GetWindowThreadProcessId(hwnd, out uint pid) == 0 || pid == 0)
            return Level.Unknown;
        return OfProcessId(pid);
    }

    private static Level OfProcessHandle(nint process)
    {
        if (!OpenProcessToken(process, TOKEN_QUERY, out nint token) || token == 0)
            return Level.Unknown;

        nint buffer = 0;
        try
        {
            GetTokenInformation(token, TokenIntegrityLevel, 0, 0, out uint needed);
            if (needed == 0) return Level.Unknown;

            buffer = Marshal.AllocHGlobal((int)needed);
            if (!GetTokenInformation(token, TokenIntegrityLevel, buffer, needed, out _))
                return Level.Unknown;

            // TOKEN_MANDATORY_LABEL 的首字段就是 SID_AND_ATTRIBUTES.Sid
            nint sid = Marshal.ReadIntPtr(buffer);
            if (sid == 0) return Level.Unknown;

            byte count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
            if (count == 0) return Level.Unknown;

            // 完整性级别是最后一个子颁发机构（RID）
            uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
            return Enum.IsDefined(typeof(Level), (int)rid) ? (Level)rid : Level.Unknown;
        }
        finally
        {
            if (buffer != 0) Marshal.FreeHGlobal(buffer);
            CloseHandle(token);
        }
    }

    public static string Describe(Level level) => level switch
    {
        Level.Unknown => "未知（无权查询，通常意味着对方级别更高）",
        Level.Untrusted => "Untrusted",
        Level.Low => "Low（沙箱）",
        Level.Medium => "Medium（普通用户进程）",
        Level.MediumPlus => "Medium Plus",
        Level.High => "High（已提权为管理员）",
        Level.System => "System",
        _ => level.ToString(),
    };

    [DllImport("kernel32.dll")]
    private static extern nint GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(nint hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(nint ProcessHandle, uint DesiredAccess, out nint TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(nint TokenHandle, int TokenInformationClass,
        nint TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern nint GetSidSubAuthority(nint pSid, uint nSubAuthority);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern nint GetSidSubAuthorityCount(nint pSid);
}
