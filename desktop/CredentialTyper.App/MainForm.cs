using System.Security.Cryptography;
using System.Text;
using CredentialTyper.Core.Service;
using CredentialTyper.Transport.Wire;
using QRCoder;

namespace CredentialTyper.App;

/// <summary>
/// 桌面主窗口：启动 LAN 服务、显示配对二维码与指纹、弹配对确认框、显示连接与注入日志。
/// 所有 DesktopServer 回调都在后台线程触发，统一用 BeginInvoke 切回 UI 线程。
/// </summary>
public sealed class MainForm : Form
{
    private const int DefaultPort = 47820;

    private readonly DesktopIdentity _identity;
    private readonly PairingStore _pairing;
    private readonly DesktopServer _server;

    private readonly Label _fpLabel = new();
    private readonly Label _statusLabel = new();
    private readonly PictureBox _qrBox = new();
    private readonly Label _qrHint = new();
    private readonly Label _lanLabel = new();
    private readonly Label _titleLabel = new();
    private readonly Label _logTitle = new();
    private readonly Button _copyLogBtn = new();
    private readonly TextBox _log = new();
    private readonly Button _repairBtn = new();
    private readonly Button _unpairBtn = new();
    private readonly Button _addAccountBtn = new();
    private readonly TextBox _syncSearch = new();
    private readonly Button _syncClearBtn = new();
    private readonly Label _syncSearchLabel = new();
    private readonly System.Windows.Forms.Timer _syncTimer = new() { Interval = 300 };
    private readonly NotifyIcon _tray = new();
    private bool _allowExit;

    public MainForm()
    {
        _identity = DesktopIdentity.LoadOrCreate();
        _pairing = new PairingStore();
        _server = new DesktopServer(_identity, _pairing)
        {
            OnLog = OnServerLog,
            OnPaired = OnServerPaired,
            OnInjected = path => AppendLog($"已注入（路径 {path}）"),
            OnPairingRequest = OnServerPairingRequest,
        };

        BuildUi();
        BuildTray();

        try
        {
            _server.Start(DefaultPort);
            _fpLabel.Text = $"本机指纹：{_server.DesktopFingerprint}";
            AppendLog($"服务已启动，监听端口 {_server.Port}。");

            // 本进程以管理员权限运行，直接放行入站端口，避免用户被 Windows
            // 防火墙拦在“电脑不可达”上。放到线程池，别卡住 UI 启动。
            var boundPort = _server.Port;
            Task.Run(() => FirewallRule.EnsureAllowed(boundPort, AppendLog));

            RefreshPairingState();
        }
        catch (Exception e)
        {
            _statusLabel.Text = "启动失败";
            _statusLabel.ForeColor = Color.Firebrick;
            AppendLog($"服务启动失败：{e.Message}");
            MessageBox.Show(this, $"服务启动失败：\n{e.Message}", "错误",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void BuildUi()
    {
        // Keep the build number in the title bar so an old tray instance is
        // immediately distinguishable during upgrades/pairing diagnostics.
        Text = "凭据填充器 · 桌面端 v1.0.6";
        Font = new Font("Microsoft YaHei UI", 9F);
        ClientSize = new Size(340, 360);
        MinimumSize = new Size(340, 360);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.Black;

        _titleLabel.Text = "凭据填充器";
        _titleLabel.Font = new Font("Microsoft YaHei UI", 16F, FontStyle.Bold);
        _titleLabel.AutoSize = true;
        _titleLabel.Location = new Point(24, 20);
        _titleLabel.ForeColor = Color.White;

        _fpLabel.Font = new Font("Consolas", 10F);
        _fpLabel.ForeColor = Color.DimGray;
        _fpLabel.AutoSize = true;
        _fpLabel.Location = new Point(26, 58);

        _statusLabel.Text = "初始化…";
        _statusLabel.Font = new Font("Microsoft YaHei UI", 10F, FontStyle.Bold);
        _statusLabel.AutoSize = true;
        _statusLabel.Location = new Point(26, 84);

        _qrBox.Size = new Size(280, 280);
        _qrBox.Location = new Point((ClientSize.Width - 280) / 2, 120);
        _qrBox.BorderStyle = BorderStyle.FixedSingle;
        _qrBox.SizeMode = PictureBoxSizeMode.Zoom;
        _qrBox.Anchor = AnchorStyles.Top;
        _qrBox.Cursor = Cursors.Hand;
        _qrBox.Click += (_, _) => { if (_qrBox.Visible) OpenPairing(); };

        _qrHint.Text = "用手机 App 扫描此二维码配对";
        _qrHint.Font = new Font("Microsoft YaHei UI", 10F);
        _qrHint.AutoSize = false;
        _qrHint.TextAlign = ContentAlignment.MiddleCenter;
        _qrHint.Size = new Size(ClientSize.Width - 48, 24);
        _qrHint.Location = new Point(24, 408);
        _qrHint.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        _lanLabel.Font = new Font("Consolas", 9F);
        _lanLabel.ForeColor = Color.Gray;
        _lanLabel.AutoSize = false;
        _lanLabel.TextAlign = ContentAlignment.MiddleCenter;
        _lanLabel.Size = new Size(ClientSize.Width - 48, 20);
        _lanLabel.Location = new Point(24, 434);
        _lanLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        _repairBtn.Text = "重新配对";
        _repairBtn.Size = new Size(120, 34);
        _repairBtn.Location = new Point(150, 462);
        _repairBtn.Anchor = AnchorStyles.Top;
        _repairBtn.Click += (_, _) => OpenPairing();

        _unpairBtn.Text = "取消连接";
        _unpairBtn.Visible = false;
        _unpairBtn.Size = new Size(120, 34);
        _unpairBtn.Location = new Point(290, 462);
        _unpairBtn.Anchor = AnchorStyles.Top;
        _unpairBtn.Click += (_, _) => Unpair();

        // Keep the action short so it remains legible in the compact card.
        // The account editor is intentionally separate from the search-sync
        // controls below.
        _addAccountBtn.Text = "添加账号";
        _addAccountBtn.Size = new Size(260, 34);
        _addAccountBtn.Location = new Point(150, 502);
        _addAccountBtn.Anchor = AnchorStyles.Top;
        _addAccountBtn.Click += (_, _) => ShowAddAccountDialog();

        _syncSearchLabel.Text = "同步手机搜索";
        _syncSearchLabel.ForeColor = Color.LightGray;
        _syncSearchLabel.AutoSize = true;
        _syncSearch.Location = new Point(18, 320);
        _syncSearch.Size = new Size(304, 28);
        _syncSearch.BackColor = Color.FromArgb(28, 28, 28);
        _syncSearch.ForeColor = Color.White;
        _syncSearch.BorderStyle = BorderStyle.FixedSingle;
        _syncSearch.PlaceholderText = "输入筛选内容，自动同步到手机";
        _syncSearch.TextChanged += (_, _) => { _syncTimer.Stop(); _syncTimer.Start(); };
        _syncClearBtn.Text = "清空";
        _syncClearBtn.Size = new Size(48, 28);
        _syncClearBtn.BackColor = Color.FromArgb(45, 45, 45);
        _syncClearBtn.ForeColor = Color.White;
        _syncClearBtn.FlatStyle = FlatStyle.Flat;
        _syncClearBtn.FlatAppearance.BorderColor = Color.FromArgb(90, 90, 90);
        _syncClearBtn.Cursor = Cursors.Hand;
        _syncClearBtn.TabStop = false;
        _syncClearBtn.Click += (_, _) =>
        {
            if (_syncSearch.TextLength == 0) return;
            _syncSearch.Clear();
            _syncSearch.Focus();
        };
        _syncTimer.Tick += async (_, _) =>
        {
            _syncTimer.Stop();
            if (_server.IsPhoneConnected)
            {
                try { await _server.SendFilterSyncAsync(_syncSearch.Text); } catch { /* 下次连接自动补发 */ }
            }
        };

        StyleButton(_repairBtn, Color.FromArgb(45, 45, 45));
        StyleButton(_unpairBtn, Color.FromArgb(120, 45, 45));
        StyleButton(_addAccountBtn, Color.FromArgb(35, 85, 145));

        _logTitle.Text = "配对 / 连接日志";
        _logTitle.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold);
        _logTitle.AutoSize = true;
        _logTitle.Location = new Point(24, 508);
        _logTitle.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _logTitle.ForeColor = Color.White;

        _copyLogBtn.Text = "复制日志";
        _copyLogBtn.Size = new Size(76, 24);
        _copyLogBtn.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _copyLogBtn.Cursor = Cursors.Hand;
        _copyLogBtn.TabStop = false;
        StyleButton(_copyLogBtn, Color.FromArgb(45, 45, 45));
        _copyLogBtn.Font = new Font("Microsoft YaHei UI", 8F);
        _copyLogBtn.Click += (_, _) =>
        {
            // 日志绝不含密码（OnLog 只写非敏感文本），复制到剪贴板供排障。
            if (_log.TextLength == 0) return;
            try { Clipboard.SetText(_log.Text); AppendLog("（日志已复制到剪贴板）"); }
            catch (Exception ex) { AppendLog($"复制失败：{ex.Message}"); }
        };

        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.ScrollBars = ScrollBars.Vertical;
        _log.BackColor = Color.FromArgb(28, 28, 28);
        _log.ForeColor = Color.White;
        _log.Font = new Font("Consolas", 9F);
        _log.Location = new Point(24, 530);
        _log.Size = new Size(ClientSize.Width - 48, ClientSize.Height - 530 - 20);
        _log.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;

        Controls.AddRange(new Control[]
        {
            _titleLabel, _fpLabel, _statusLabel, _qrBox, _qrHint, _lanLabel,
            _repairBtn, _unpairBtn, _addAccountBtn, _syncSearchLabel, _syncSearch,
            _syncClearBtn, _logTitle, _copyLogBtn, _log,
        });
        _qrHint.ForeColor = Color.LightGray;
        _lanLabel.ForeColor = Color.LightGray;
        ApplyPresentation(connected: false);
    }

    private static void StyleButton(Button button, Color backColor)
    {
        button.BackColor = backColor;
        button.ForeColor = Color.White;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderColor = Color.FromArgb(90, 90, 90);
    }

    private void ApplyPresentation(bool connected)
    {
        // The log panel is now always visible: it is the only way for the user
        // to see *why* a pairing attempt failed (wrong IP, refused, EndOfStream,
        // "当前不在配对窗口" …) and to copy that back for diagnosis.
        _titleLabel.Visible = connected;
        _fpLabel.Visible = false;
        _statusLabel.Visible = connected;
        _qrHint.Visible = false;
        _repairBtn.Visible = false;
        _unpairBtn.Visible = connected && _pairing.HasPaired;
        _addAccountBtn.Visible = connected;
        _logTitle.Visible = true;
        _copyLogBtn.Visible = true;
        _log.Visible = true;

        int logTop;
        if (!connected)
        {
            // 未连接：二维码 + 地址在上，日志在下。同步搜索没有对象，隐藏。
            ClientSize = new Size(360, 560);
            MinimumSize = new Size(360, 480);
            _qrBox.Size = new Size(200, 200);
            _qrBox.Location = new Point((ClientSize.Width - 200) / 2, 12);
            _lanLabel.Visible = true;
            _lanLabel.Location = new Point(12, 220);
            _lanLabel.Size = new Size(ClientSize.Width - 24, 40);
            _lanLabel.TextAlign = ContentAlignment.MiddleCenter;
            _syncSearchLabel.Visible = false;
            _syncSearch.Visible = false;
            _syncClearBtn.Visible = false;
            logTop = 266;
        }
        else
        {
            ClientSize = new Size(360, 520);
            MinimumSize = new Size(360, 440);
            _qrBox.Visible = false;
            _lanLabel.Visible = false;
            _titleLabel.Location = new Point(18, 14);
            _statusLabel.Location = new Point(18, 46);
            _unpairBtn.Location = new Point(18, 78);
            _unpairBtn.Size = new Size(150, 34);
            _addAccountBtn.Location = new Point(180, 78);
            _addAccountBtn.Size = new Size(162, 34);
            _syncSearchLabel.Visible = true;
            _syncSearchLabel.Location = new Point(18, 124);
            _syncSearch.Visible = true;
            _syncSearch.Location = new Point(18, 146);
            _syncSearch.Size = new Size(290, 28);
            _syncClearBtn.Visible = true;
            _syncClearBtn.Location = new Point(312, 146);
            _syncClearBtn.Size = new Size(44, 28);
            logTop = 188;
        }

        _logTitle.Location = new Point(18, logTop);
        _copyLogBtn.Location = new Point(ClientSize.Width - 94, logTop - 4);
        _log.Location = new Point(18, logTop + 24);
        _log.Size = new Size(ClientSize.Width - 36, ClientSize.Height - (logTop + 24) - 14);
    }

    private void BuildTray()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("打开主窗口", null, (_, _) => RestoreFromTray());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("退出程序", null, (_, _) =>
        {
            _allowExit = true;
            Close();
        });
        _tray.Icon = SystemIcons.Application;
        _tray.Text = "凭据填充器 v1.0.6";
        _tray.ContextMenuStrip = menu;
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        _tray.Visible = true;
    }

    private void RestoreFromTray()
    {
        Show();
        ShowInTaskbar = true;
        WindowState = FormWindowState.Normal;
        Activate();
    }

    /// <summary>
    /// 后台等待“第二次启动”信号：另一个实例被单实例守卫挡下时会 Set 这个事件，
    /// 收到就把本窗口从托盘唤起到前台。用后台线程等待，避免阻塞消息循环。
    /// </summary>
    public void ListenForWake(EventWaitHandle wake)
    {
        var thread = new Thread(() =>
        {
            while (true)
            {
                try
                {
                    wake.WaitOne();
                    if (IsDisposed) return;
                    BeginInvoke(RestoreFromTray);
                }
                catch (ObjectDisposedException) { return; }
                catch (InvalidOperationException) { return; }
            }
        })
        { IsBackground = true, Name = "wake-listener" };
        thread.Start();
    }

    // —— 配对状态 ——

    private void RefreshPairingState()
    {
        if (_pairing.HasPaired)
        {
            if (!_server.IsPhoneConnected)
            {
                OpenPairing();
                return;
            }
            ApplyPresentation(connected: _server.IsPhoneConnected);
            _repairBtn.Text = "重新配对";
            SetStatus("已配对，等待手机连接", Color.SeaGreen);
            ShowQr(null);
            _qrHint.Text = "本机已配对。手机 App 打开即自动重连。若要换手机，点“重新配对”。";
        }
        else
        {
            ApplyPresentation(connected: false);
            _repairBtn.Text = "刷新二维码";
            OpenPairing();
        }
    }

    private void OpenPairing()
    {
        try
        {
            var qr = _server.OpenPairing();
            ShowQr(qr.ToQrText());
            _qrHint.Text = "用手机 App 扫描此二维码配对";
            _lanLabel.Text = $"连接码：{string.Join(" / ", qr.Host)}:{qr.Port}";
            SetStatus("等待手机扫码配对", Color.DarkOrange);
            ApplyPresentation(connected: _server.IsPhoneConnected);
            AppendLog("已开启配对窗口，等待扫码。");
        }
        catch (Exception e)
        {
            AppendLog($"开启配对失败：{e.Message}");
        }
    }

    private void Unpair()
    {
        if (!_pairing.HasPaired)
        {
            OpenPairing();
            return;
        }
        var r = MessageBox.Show(this, "确定取消与当前手机的连接吗？之后需要重新扫码。",
            "取消连接", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
        if (r != DialogResult.Yes) return;
        _server.DisconnectPhone();
        _pairing.Clear();
        AppendLog("已取消配对。");
        OpenPairing();
    }

    private void ShowQr(string? text)
    {
        var old = _qrBox.Image;
        if (text is null)
        {
            _qrBox.Image = null;
            _qrBox.Visible = false;
            _lanLabel.Text = "";
        }
        else
        {
            _qrBox.Image = RenderQr(text);
            _qrBox.Visible = true;
        }
        old?.Dispose();
    }

    private static Bitmap RenderQr(string text)
    {
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(10);
        using var ms = new MemoryStream(png);
        using var tmp = new Bitmap(ms);
        return new Bitmap(tmp);   // 复制一份，摆脱“Bitmap 依赖流存活”的 GDI+ 限制
    }

    // —— 服务回调（后台线程 → UI 线程）——

    private Task<bool> OnServerPairingRequest(byte[] phonePub, CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>();
        BeginInvoke(() =>
        {
            var phoneFp = Protocol.Fingerprint(phonePub);
            AppendLog($"收到配对请求，手机指纹 {phoneFp}");
            var r = MessageBox.Show(this,
                $"手机端指纹：\n\n        {phoneFp}\n\n" +
                $"请核对：\n" +
                $"· 上面这串是否与手机屏幕上显示的“本机指纹”一致\n" +
                $"· 手机屏幕上的“桌面指纹”是否为  {_server.DesktopFingerprint}\n\n" +
                $"两者都一致才点“是”。",
                "确认配对", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            tcs.SetResult(r == DialogResult.Yes);
        });
        return tcs.Task;
    }

    private void OnServerPaired()
    {
        BeginInvoke(() =>
        {
            AppendLog("配对成功，已保存到本机。");
            SetStatus("已连接手机", Color.SeaGreen);
            ApplyPresentation(connected: true);
            ShowQr(null);
            _ = SyncSearchNow();
            _qrHint.Text = "已配对并连接。聚焦任意输入框，在手机上点“填账号 / 填密码”。";
        });
    }

    private async Task SyncSearchNow()
    {
        if (!_server.IsPhoneConnected) return;
        try { await _server.SendFilterSyncAsync(_syncSearch.Text); } catch { }
    }

    private void ShowAddAccountDialog()
    {
        if (!_pairing.HasPaired || !_server.IsPhoneConnected)
        {
            MessageBox.Show(this, "请先完成配对并等待手机连接。", "无法发送", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        using var dialog = new Form { Text = "添加账号", ClientSize = new Size(430, 420), StartPosition = FormStartPosition.CenterParent, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
        var title = new TextBox(); var username = new TextBox(); var website = new TextBox(); var password = new TextBox { UseSystemPasswordChar = true }; var note = new TextBox();
        // Website is a property of the account (not the desktop search box),
        // and is deliberately kept as the last field in the compact editor.
        var fields = new (string, Control)[]
        {
            ("名称", title),
            ("账号 / 邮箱", username),
            ("密码", password),
            ("备注", note),
            ("所属网站 / 域名", website),
        };
        var y = 18;
        foreach (var (label, control) in fields)
        {
            dialog.Controls.Add(new Label { Text = label, Location = new Point(20, y + 4), AutoSize = true });
            control.Location = new Point(125, y); control.Size = new Size(275, 28); dialog.Controls.Add(control); y += 48;
        }
        var send = new Button { Text = "发送到手机", DialogResult = DialogResult.None, Location = new Point(285, y + 12), Size = new Size(115, 34) }; dialog.Controls.Add(send); dialog.AcceptButton = send;
        send.Click += async (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(title.Text)) { MessageBox.Show(dialog, "请填写名称"); return; }
            var pw = Encoding.UTF8.GetBytes(password.Text);
            try
            {
                await _server.SendAccountImportAsync(title.Text.Trim(), username.Text.Trim(), website.Text.Trim(), note.Text.Trim(), pw);
                password.Clear();
                AppendLog("账号已加密发送到手机。");
                MessageBox.Show(dialog, "发送成功，手机已新增该账号。", "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                dialog.DialogResult = DialogResult.OK;
                dialog.Close();
            }
            catch (Exception ex) { CryptographicOperations.ZeroMemory(pw); MessageBox.Show(dialog, $"发送失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        };
        dialog.ShowDialog(this);
    }

    private void OnServerLog(string msg)
    {
        // 从日志文本推断连接态，驱动状态标签
        if (msg.Contains("进入会话") || msg.Contains("重连成功"))
            BeginInvoke(() => { SetStatus("已连接手机", Color.SeaGreen); ApplyPresentation(connected: true); _ = SyncSearchNow(); });
        else if (msg.Contains("会话读取结束") || msg.Contains("连接结束"))
            BeginInvoke(() =>
            {
                // A stale/failed client can finish after a newer phone session
                // has already been established. Never let that diagnostic
                // event replace the connected presentation or rotate the QR
                // code being scanned by another client.
                if (_server.IsPhoneConnected) return;

                SetStatus(_pairing.HasPaired ? "已配对，等待手机连接" : "等待配对", Color.SeaGreen);
                ApplyPresentation(connected: false);

                // Keep the current QR/code stable while a pairing attempt is
                // in flight. Generate a new one only after the previous
                // window has actually been closed (for example after a
                // successful pairing).
                if (!_server.IsPairingOpen) OpenPairing();
            });
        AppendLog(msg);
    }

    // —— 小工具 ——

    private void SetStatus(string text, Color color)
    {
        _statusLabel.Text = $"● {text}";
        _statusLabel.ForeColor = color;
    }

    private void AppendLog(string msg)
    {
        if (InvokeRequired) { BeginInvoke(() => AppendLog(msg)); return; }
        var ts = DateTime.Now.ToString("HH:mm:ss");
        _log.AppendText($"[{ts}] {msg}{Environment.NewLine}");
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!_allowExit)
        {
            e.Cancel = true;
            Hide();
            ShowInTaskbar = false;
            _tray.ShowBalloonTip(1500, "凭据填充器", "程序已缩小到系统托盘，服务仍在运行。", ToolTipIcon.Info);
            return;
        }
        try { _server.Dispose(); } catch { /* 收尾忽略 */ }
        _syncTimer.Dispose();
        _tray.Visible = false;
        _tray.Dispose();
        base.OnFormClosing(e);
    }
}
