// Karantén kezelő - Microsoft Defender karanténjának grafikus, NVDA-barát kezelője.
// C# 5 / .NET Framework 4.x kompatibilis (a Windowsban meglévő csc.exe lefordítja).
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Management;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace Karanten
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
#if NET5_0_OR_GREATER
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
#endif
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (!IsAdmin())
            {
                // A kivételek felvételéhez és a visszaállításhoz rendszergazdai jog kell.
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath);
                    psi.UseShellExecute = true;
                    psi.Verb = "runas";
                    Process.Start(psi);
                }
                catch (Win32Exception)
                {
                    MessageBox.Show("A program rendszergazdai jogosultság nélkül nem működik. Indítsd újra, és a felugró ablakban engedélyezd.",
                        "Karantén kezelő", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                return;
            }

            string report = Folders.EnsureAll();
            Application.Run(new MainForm(report));
        }

        static bool IsAdmin()
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }

    // ---------- Segédfüggvények a külső programokhoz ----------
    class ProcResult
    {
        public int Code;
        public string Output;
    }

    static class Proc
    {
        public static string Quote(string s)
        {
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        public static ProcResult Run(string exe, string args)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            try
            {
                Encoding oem = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
                psi.StandardOutputEncoding = oem;
                psi.StandardErrorEncoding = oem;
            }
            catch (Exception) { }

            StringBuilder sb = new StringBuilder();
            object gate = new object();
            using (Process p = new Process())
            {
                p.StartInfo = psi;
                p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null) { lock (gate) { sb.AppendLine(e.Data); } }
                };
                p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null) { lock (gate) { sb.AppendLine(e.Data); } }
                };
                p.Start();
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                p.WaitForExit();
                p.WaitForExit();
                ProcResult r = new ProcResult();
                r.Code = p.ExitCode;
                r.Output = sb.ToString();
                return r;
            }
        }

        // A legfrissebb Defender platform MpCmdRun.exe-je, ennek hiányában a Program Files-os.
        public static string FindMpCmdRun()
        {
            try
            {
                string platform = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(platform))
                {
                    string best = null;
                    Version bestVer = null;
                    foreach (string dir in Directory.GetDirectories(platform))
                    {
                        string name = Path.GetFileName(dir);
                        int dash = name.IndexOf('-');
                        if (dash > 0) name = name.Substring(0, dash);
                        Version v;
                        if (!Version.TryParse(name, out v)) continue;
                        if (!File.Exists(Path.Combine(dir, "MpCmdRun.exe"))) continue;
                        if (bestVer == null || v > bestVer) { bestVer = v; best = dir; }
                    }
                    if (best != null) return Path.Combine(best, "MpCmdRun.exe");
                }
            }
            catch (Exception) { }

            string pf = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Windows Defender\MpCmdRun.exe");
            return File.Exists(pf) ? pf : null;
        }
    }

    // ---------- Mappák és kivételek ----------
    static class Folders
    {
        public static string UserDir
        {
            get { return Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); }
        }
        public static string Karanten { get { return Path.Combine(UserDir, "karanten"); } }
        public static string Karanten2 { get { return Path.Combine(UserDir, "karanten2"); } }

        // Minden futásnál: ha mindkét mappa megvan, nem csinál semmit.
        // Ha valamelyik hiányzik, létrehozza, és felveszi a kivételek közé (a programmal együtt).
        // Visszatérés: üres szöveg, ha nem történt semmi; egyébként az eredmény leírása.
        public static string EnsureAll()
        {
            bool miss1 = !Directory.Exists(Karanten);
            bool miss2 = !Directory.Exists(Karanten2);
            if (!miss1 && !miss2) return "";

            List<string> toExclude = new List<string>();
            StringBuilder sb = new StringBuilder();
            try
            {
                if (miss1) { Directory.CreateDirectory(Karanten); toExclude.Add(Karanten); sb.AppendLine("Létrehozva: " + Karanten); }
                if (miss2) { Directory.CreateDirectory(Karanten2); toExclude.Add(Karanten2); sb.AppendLine("Létrehozva: " + Karanten2); }
            }
            catch (Exception ex)
            {
                sb.AppendLine("Mappa létrehozási hiba: " + ex.Message);
                return sb.ToString();
            }
            toExclude.Add(Application.ExecutablePath);

            foreach (string p in toExclude)
            {
                string err = AddExclusion(p);
                if (err == null) sb.AppendLine("Kivételhez adva: " + p);
                else sb.AppendLine("Kivétel felvétele sikertelen (" + p + "): " + err);
            }
            return sb.ToString();
        }

        // Defender WMI: root\Microsoft\Windows\Defender, MSFT_MpPreference.Add(ExclusionPath[], ..., Force).
        // Null = siker, különben a hibaüzenet.
        static string AddExclusion(string path)
        {
            try
            {
                ManagementClass mc = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);
                ManagementBaseObject inParams = mc.GetMethodParameters("Add");
                inParams["ExclusionPath"] = new string[] { path };
                inParams["Force"] = true;
                mc.InvokeMethod("Add", inParams, null);
                return IsExcluded(path) ? null : "a Defender nem fogadta el (Tamper Protection?)";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        static bool IsExcluded(string path)
        {
            using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                @"root\Microsoft\Windows\Defender", "SELECT ExclusionPath FROM MSFT_MpPreference"))
            {
                foreach (ManagementBaseObject o in s.Get())
                {
                    string[] arr = o["ExclusionPath"] as string[];
                    if (arr == null) continue;
                    foreach (string e in arr)
                        if (string.Equals(e, path, StringComparison.OrdinalIgnoreCase)) return true;
                }
            }
            return false;
        }
    }

    // ---------- Karantén elem ----------
    class QItem
    {
        public string Threat = "";
        public string Path = "";
        public string Time = "";

        public string FileName { get { return System.IO.Path.GetFileName(Path); } }
        public string Dir
        {
            get
            {
                try { return System.IO.Path.GetDirectoryName(Path) ?? ""; }
                catch (Exception) { return ""; }
            }
        }
        public string Key { get { return Threat + "|" + Path; } }
    }

    static class Quarantine
    {
        static readonly Regex FileLine = new Regex(@"^\s*(file|containerfile)\s*:\s*(.+?)\s*$", RegexOptions.IgnoreCase);

        public static List<QItem> Parse(string output)
        {
            List<QItem> list = new List<QItem>();
            string threat = "";
            foreach (string raw in output.Split(new char[] { '\n' }))
            {
                string line = raw.TrimEnd('\r');
                string t = line.Trim();
                if (t.StartsWith("ThreatName", StringComparison.OrdinalIgnoreCase))
                {
                    int eq = t.IndexOf('=');
                    threat = eq >= 0 ? t.Substring(eq + 1).Trim() : "";
                    continue;
                }
                Match m = FileLine.Match(line);
                if (!m.Success) continue;
                string rest = m.Groups[2].Value;
                string time = "";
                int q = rest.IndexOf(" quarantined at ", StringComparison.OrdinalIgnoreCase);
                if (q >= 0)
                {
                    time = rest.Substring(q + " quarantined at ".Length).Trim();
                    rest = rest.Substring(0, q).Trim();
                }
                QItem it = new QItem();
                it.Threat = threat;
                it.Path = rest;
                it.Time = time;
                list.Add(it);
            }
            return list;
        }
    }

    // ---------- Főablak ----------
    class MainForm : Form
    {
        ListView list;
        TextBox status;
        Button btnRestore, btnDetails, btnRefresh, btnRaw, btnOpen, btnExit;
        string startupReport;
        string lastRaw = "";
        string mpcmd;

        public MainForm(string report)
        {
            startupReport = report;
            mpcmd = Proc.FindMpCmdRun();

            Text = "Karantén kezelő";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(960, 560);
            MinimumSize = new Size(640, 420);

            TableLayoutPanel t = new TableLayoutPanel();
            t.Dock = DockStyle.Fill;
            t.ColumnCount = 1;
            t.RowCount = 5;
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.Padding = new Padding(8);
            Controls.Add(t);

            Label l1 = new Label();
            l1.Text = "&Karanténban lévő fájlok:";
            l1.AutoSize = true;
            l1.TabIndex = 0;
            l1.Margin = new Padding(0, 0, 0, 4);

            list = new ListView();
            list.View = View.Details;
            list.FullRowSelect = true;
            list.MultiSelect = true;
            list.HideSelection = false;
            list.Dock = DockStyle.Fill;
            list.TabIndex = 1;
            list.AccessibleName = "Karanténban lévő fájlok";
            list.Columns.Add("Fájlnév", 200);
            list.Columns.Add("Eredeti hely", 360);
            list.Columns.Add("Vírus / fenyegetés", 220);
            list.Columns.Add("Karanténba helyezve", 160);
            list.ItemActivate += delegate { ShowDetails(); };
            list.SelectedIndexChanged += delegate { UpdateButtons(); };

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.Dock = DockStyle.Fill;
            buttons.TabIndex = 2;
            btnRestore = MakeButton("&Visszaállítás a karanten mappába", 3, delegate { RestoreSelected(); });
            btnDetails = MakeButton("&Részletek", 4, delegate { ShowDetails(); });
            btnRefresh = MakeButton("&Frissítés", 5, delegate { RefreshList(); });
            btnRaw = MakeButton("&Nyers kimenet", 6, delegate { ShowText("Nyers kimenet", lastRaw); });
            btnOpen = MakeButton("&Mappa megnyitása", 7, delegate { OpenFolder(); });
            btnExit = MakeButton("&Kilépés", 8, delegate { Close(); });
            buttons.Controls.AddRange(new Control[] { btnRestore, btnDetails, btnRefresh, btnRaw, btnOpen, btnExit });

            Label l2 = new Label();
            l2.Text = "Á&llapot:";
            l2.AutoSize = true;
            l2.TabIndex = 9;
            l2.Margin = new Padding(0, 8, 0, 4);

            status = new TextBox();
            status.ReadOnly = true;
            status.Multiline = true;
            status.ScrollBars = ScrollBars.Vertical;
            status.Height = 70;
            status.Dock = DockStyle.Fill;
            status.TabIndex = 10;
            status.AccessibleName = "Állapot";

            t.Controls.Add(l1, 0, 0);
            t.Controls.Add(list, 0, 1);
            t.Controls.Add(buttons, 0, 2);
            t.Controls.Add(l2, 0, 3);
            t.Controls.Add(status, 0, 4);

            AcceptButton = null;
            CancelButton = btnExit;
            Shown += delegate { OnFirstShown(); };
        }

        Button MakeButton(string text, int tab, EventHandler click)
        {
            Button b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.TabIndex = tab;
            b.UseMnemonic = true;
            b.Click += click;
            return b;
        }

        void OnFirstShown()
        {
            if (startupReport.Length > 0)
            {
                SetStatus(startupReport);
            }
            RefreshList();
            if (startupReport.Length > 0)
            {
                MessageBox.Show(this, startupReport, "Mappák és kivételek", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            list.Focus();
        }

        void SetStatus(string s)
        {
            status.Text = s.Replace("\r\n", "\n").Replace("\n", "\r\n");
        }

        void UpdateButtons()
        {
            bool any = list.SelectedItems.Count > 0;
            btnRestore.Enabled = any;
            btnDetails.Enabled = any;
        }

        List<QItem> LoadItems()
        {
            if (mpcmd == null)
            {
                lastRaw = "Az MpCmdRun.exe nem található. A Microsoft Defender nincs telepítve vagy le van tiltva.";
                return new List<QItem>();
            }
            ProcResult r = Proc.Run(mpcmd, "-Restore -ListAll");
            lastRaw = r.Output;
            return Quarantine.Parse(r.Output);
        }

        void Fill(List<QItem> items)
        {
            list.BeginUpdate();
            list.Items.Clear();
            foreach (QItem it in items)
            {
                ListViewItem li = new ListViewItem(new string[] { it.FileName, it.Dir, it.Threat, it.Time });
                li.Tag = it;
                list.Items.Add(li);
            }
            list.EndUpdate();
            if (list.Items.Count > 0)
            {
                list.Items[0].Selected = true;
                list.Items[0].Focused = true;
            }
            UpdateButtons();
        }

        void RefreshList()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                List<QItem> items = LoadItems();
                Fill(items);
                string msg;
                if (mpcmd == null) msg = lastRaw;
                else if (items.Count == 0) msg = "Nincs karanténban lévő elem.";
                else msg = items.Count + " elem van karanténban.";
                SetStatus(msg);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            list.Focus();
        }

        void ShowDetails()
        {
            if (list.SelectedItems.Count == 0) return;
            QItem it = (QItem)list.SelectedItems[0].Tag;
            string s = "Fájlnév: " + it.FileName + "\r\n" +
                       "Eredeti hely: " + it.Dir + "\r\n" +
                       "Vírus / fenyegetés: " + it.Threat + "\r\n" +
                       "Karanténba helyezve: " + it.Time;
            MessageBox.Show(this, s, "Részletek", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        void RestoreSelected()
        {
            if (list.SelectedItems.Count == 0 || mpcmd == null) return;

            Folders.EnsureAll(); // ha időközben törölték a mappát, újra létrejön
            string dest = Folders.Karanten;

            List<QItem> chosen = new List<QItem>();
            foreach (ListViewItem li in list.SelectedItems) chosen.Add((QItem)li.Tag);

            DialogResult dr = MessageBox.Show(this,
                chosen.Count + " elem visszaállítása ide: " + dest + "\r\nFolytatod?",
                "Visszaállítás", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) { list.Focus(); return; }

            StringBuilder log = new StringBuilder();
            Cursor = Cursors.WaitCursor;
            try
            {
                foreach (QItem it in chosen)
                {
                    ProcResult r = Proc.Run(mpcmd, "-Restore -FilePath " + Proc.Quote(it.Path) + " -Path " + Proc.Quote(dest));
                    log.AppendLine(it.FileName + " - " + r.Output.Trim());
                }
                List<QItem> after = LoadItems();
                Fill(after);

                HashSet<string> still = new HashSet<string>();
                foreach (QItem a in after) still.Add(a.Key);

                StringBuilder sum = new StringBuilder();
                int ok = 0;
                foreach (QItem it in chosen)
                {
                    if (still.Contains(it.Key)) sum.AppendLine("Sikertelen: " + it.FileName);
                    else { ok++; sum.AppendLine("Visszaállítva: " + it.FileName); }
                }
                string result = ok + " / " + chosen.Count + " elem visszaállítva ide: " + dest + "\r\n" + sum.ToString();
                if (ok < chosen.Count) result += "\r\nA Defender kimenete:\r\n" + log.ToString();
                SetStatus(result);
                MessageBox.Show(this, result, "Visszaállítás eredménye", MessageBoxButtons.OK,
                    ok == chosen.Count ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            list.Focus();
        }

        void OpenFolder()
        {
            Folders.EnsureAll();
            try { Process.Start("explorer.exe", Proc.Quote(Folders.Karanten)); }
            catch (Exception ex) { MessageBox.Show(this, ex.Message, "Hiba", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        void ShowText(string title, string text)
        {
            Form f = new Form();
            f.Text = title;
            f.StartPosition = FormStartPosition.CenterParent;
            f.Size = new Size(800, 500);
            TextBox tb = new TextBox();
            tb.Multiline = true;
            tb.ReadOnly = true;
            tb.ScrollBars = ScrollBars.Both;
            tb.WordWrap = false;
            tb.Dock = DockStyle.Fill;
            tb.AccessibleName = title;
            tb.Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n");
            f.Controls.Add(tb);
            f.KeyPreview = true;
            f.KeyDown += delegate(object s, KeyEventArgs e) { if (e.KeyCode == Keys.Escape) f.Close(); };
            f.Shown += delegate { tb.Focus(); tb.SelectionStart = 0; tb.SelectionLength = 0; };
            f.ShowDialog(this);
        }
    }
}
