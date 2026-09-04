using System.Threading;

namespace CredentialTyper.App;

internal static class Program
{
    // Per-user single-instance guard.  Without it, a second launch (double
    // click, or starting again while the tray instance is still running)
    // creates a *second* TCP listener.  The second one falls back to another
    // port (47820→47821) and shows a QR whose port/instance may not be the one
    // the phone actually reaches — producing the phone-side EndOfStream /
    // "电脑不可达" that is not a protocol bug at all.
    private const string MutexName = @"Local\CredentialTyper.SingleInstance";
    private const string WakeEventName = @"Local\CredentialTyper.Wake";

    [STAThread]
    private static void Main()
    {
        using var mutex = new Mutex(initiallyOwned: true, MutexName, out var isFirst);
        if (!isFirst)
        {
            // 已有实例在跑：唤起它的窗口，然后本进程直接退出。
            try
            {
                if (EventWaitHandle.TryOpenExisting(WakeEventName, out var wake))
                {
                    using (wake) wake.Set();
                }
            }
            catch { /* 唤起失败也无所谓，至少不再起第二个监听器 */ }
            return;
        }

        using var wakeSignal = new EventWaitHandle(false, EventResetMode.AutoReset, WakeEventName);

        ApplicationConfiguration.Initialize();
        using var form = new MainForm();
        form.ListenForWake(wakeSignal);
        Application.Run(form);
    }
}
