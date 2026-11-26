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
        static void Main(string[] args)
        {
            try
            {
#if NET5_0_OR_GREATER
                Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
#endif
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
                Application.ThreadException += delegate(object s, System.Threading.ThreadExceptionEventArgs e) { Fail(e.Exception); };
                AppDomain.CurrentDomain.UnhandledException += delegate(object s, UnhandledExceptionEventArgs e) { Fail(e.ExceptionObject as Exception); };

                // Az ablak mindig megnyílik. A rendszergazdai jogot a manifest kéri (UAC);
                // ha mégsem emelt jogú, egyszer újraindítjuk emelve, utána így is megnyílik az ablak.
                bool admin = IsAdmin();
                if (!admin && Array.IndexOf(args, "--emelt") < 0)
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath, "--emelt");
                        psi.UseShellExecute = true;
                        psi.Verb = "runas";
                        Process.Start(psi);
                        return;
                    }
                    catch (Win32Exception) { }
                }

                Application.Run(new MainForm(admin));
            }
            catch (Exception ex)
            {
                Fail(ex);
            }
        }

        // Hiba esetén naplófájl a felhasználói mappában, és egy ablak, amit a képernyőolvasó felolvas.
        static void Fail(Exception ex)
        {
            string text = ex == null ? "Ismeretlen hiba." : ex.ToString();
            try
            {
                string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Karanten-hiba.txt");
                File.WriteAllText(log, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "\r\n" + text);
            }
            catch (Exception) { }
            try
            {
                MessageBox.Show("A program hibát észlelt. A részletek a felhasználói mappában lévő Karanten-hiba.txt fájlban vannak.\r\n\r\n" + text,
                    "Karantén kezelő - hiba", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch (Exception) { }
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

        // Az összes MpCmdRun.exe, a legfrissebb platform elől; almappákban (pl. X64) is keres.
        public static List<string> FindAllMpCmdRun()
        {
            List<string> result = new List<string>();
            try
            {
                string platform = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(platform))
                {
                    List<KeyValuePair<Version, string>> dirs = new List<KeyValuePair<Version, string>>();
                    foreach (string dir in Directory.GetDirectories(platform))
                    {
                        string name = Path.GetFileName(dir);
                        int dash = name.IndexOf('-');
                        if (dash > 0) name = name.Substring(0, dash);
                        Version v;
                        if (Version.TryParse(name, out v)) dirs.Add(new KeyValuePair<Version, string>(v, dir));
                    }
                    dirs.Sort(delegate(KeyValuePair<Version, string> x, KeyValuePair<Version, string> y) { return y.Key.CompareTo(x.Key); });
                    foreach (KeyValuePair<Version, string> d in dirs)
                    {
                        string direct = Path.Combine(d.Value, "MpCmdRun.exe");
                        if (File.Exists(direct)) result.Add(direct);
                        else
                        {
                            foreach (string f in Directory.GetFiles(d.Value, "MpCmdRun.exe", SearchOption.AllDirectories))
                                result.Add(f);
                        }
                        if (result.Count >= 2) break;
                    }
                }
            }
            catch (Exception) { }

            string pf = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                @"Windows Defender\MpCmdRun.exe");
            if (File.Exists(pf) && !result.Contains(pf)) result.Add(pf);
            return result;
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
        public string Source = "quarantine";
        public string Action = "";
        public string Success = "";
        public bool IsQuarantineAction;

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
        static readonly Regex PathStart = new Regex(@"(?:[A-Za-z]:\\|\\\\)", RegexOptions.None);
        static readonly Regex TimeStart = new Regex(@"\d{4}[./\-]\s?\d{1,2}[./\-]\s?\d{1,2}|\d{1,2}[./\-]\d{1,2}[./\-]\d{4}", RegexOptions.None);
        static readonly Regex Label = new Regex(@"^\s*([^\s:\\]{2,})\s*:\s*(.*)$", RegexOptions.None);

        // Tűrő értelmezés: a címkék lehetnek lefordítva. Fenyegetés-sor: '=' van benne, és előbb mint egy útvonal.
        // Utána minden "file:" / "containerfile:" sor (vagy meghajtóútvonalat tartalmazó sor) egy elem.
        // Az útvonalat úgy tartjuk meg, ahogy a Defender kiírta (a visszaállításhoz pontosan ez kell).
        public static List<QItem> Parse(string output)
        {
            List<QItem> list = new List<QItem>();
            string threat = null;
            foreach (string raw in output.Split(new char[] { '\n' }))
            {
                string line = raw.TrimEnd('\r').Trim();
                if (line.Length == 0) continue;
                Match pm = PathStart.Match(line);
                int eq = line.IndexOf('=');
                if (eq > 0 && eq < line.Length - 1 && (!pm.Success || eq < pm.Index))
                {
                    threat = line.Substring(eq + 1).Trim();
                    continue;
                }
                if (threat == null) continue;

                string lower = line.ToLowerInvariant();
                if (lower.StartsWith("regkey")) continue;

                string rest = null;
                Match lm = Label.Match(line);
                if (lm.Success)
                {
                    string lab = lm.Groups[1].Value.ToLowerInvariant();
                    if (lab == "file" || lab == "containerfile" || lab == "fájl" || pm.Success) rest = lm.Groups[2].Value;
                }
                else if (pm.Success) rest = line.Substring(pm.Index);
                if (rest == null || rest.Trim().Length == 0) continue;

                string time = "";
                Match tm = TimeStart.Match(rest);
                if (tm.Success)
                {
                    time = rest.Substring(tm.Index).Trim();
                    rest = rest.Substring(0, tm.Index).TrimEnd();
                    for (int i = 0; i < 5; i++)
                    {
                        int sp = rest.LastIndexOf(' ');
                        if (sp < 0) break;
                        string word = rest.Substring(sp + 1);
                        if (word.IndexOf('\\') >= 0 || word.IndexOf('.') >= 0) break;
                        rest = rest.Substring(0, sp).TrimEnd();
                    }
                }
                if (rest.Length == 0) continue;
                QItem it = new QItem();
                it.Threat = threat;
                it.Path = rest;
                it.Time = time;
                list.Add(it);
            }
            return list;
        }

        // Védelmi előzmények (WMI: MSFT_MpThreatDetection + MSFT_MpThreat). Csak a karanténba helyezett (CleaningActionID 2) elemek.
        public static List<QItem> FromHistory(out string note)
        {
            List<QItem> list = new List<QItem>();
            note = "";
            try
            {
                Dictionary<long, string> names = new Dictionary<long, string>();
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender", "SELECT ThreatID, ThreatName FROM MSFT_MpThreat"))
                {
                    foreach (ManagementBaseObject o in s.Get())
                        names[Convert.ToInt64(o["ThreatID"])] = Convert.ToString(o["ThreatName"]);
                }
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender", "SELECT ThreatID, Resources, InitialDetectionTime, CleaningActionID, ActionSuccess FROM MSFT_MpThreatDetection"))
                {
                    foreach (ManagementBaseObject o in s.Get())
                    {
                        int action = o["CleaningActionID"] == null ? 0 : Convert.ToInt32(o["CleaningActionID"]);
                        long id = Convert.ToInt64(o["ThreatID"]);
                        string name;
                        if (!names.TryGetValue(id, out name)) name = "ThreatID " + id;
                        string time = "";
                        try { time = ManagementDateTimeConverter.ToDateTime(Convert.ToString(o["InitialDetectionTime"])).ToString("yyyy-MM-dd HH:mm:ss"); }
                        catch (Exception) { }
                        string[] res = o["Resources"] as string[];
                        if (res == null) continue;
                        foreach (string r in res)
                        {
                            string rl = r.ToLowerInvariant();
                            if (rl.StartsWith("regkey")) continue;
                            Match pm = PathStart.Match(r);
                            if (!pm.Success) continue;
                            QItem it = new QItem();
                            it.Threat = name;
                            it.Path = r.Substring(pm.Index);
                            it.Time = time;
                            it.Source = "history";
                            it.Action = ActionName(action);
                            it.IsQuarantineAction = action == 2;
                            it.Success = (o["ActionSuccess"] != null && Convert.ToBoolean(o["ActionSuccess"])) ? "igen" : "nem";
                            list.Add(it);
                        }
                    }
                }
            }
            catch (Exception ex) { note = "Védelmi előzmények (WMI) hiba: " + ex.Message; }
            return list;
        }

        // MSFT_MpThreatDetection.CleaningActionID értékei
        static string ActionName(int id)
        {
            switch (id)
            {
                case 1: return "tisztítás";
                case 2: return "karanténba helyezés";
                case 3: return "törlés";
                case 6: return "engedélyezés";
                case 8: return "felhasználói döntés";
                case 9: return "nincs művelet";
                case 10: return "blokkolás";
                default: return "azonosító: " + id;
            }
        }

        public static void AddUnique(List<QItem> target, List<QItem> more)
        {
            foreach (QItem m in more)
            {
                bool dup = false;
                foreach (QItem t in target)
                    if (string.Equals(t.Path, m.Path, StringComparison.OrdinalIgnoreCase)) { dup = true; break; }
                if (!dup) target.Add(m);
            }
        }
    }

    // ---------- Fenyegetés részletei (WMI: root\Microsoft\Windows\Defender, MSFT_MpThreat) ----------
    class ThreatInfo
    {
        public string Category = "";
        public string Severity = "";
        public bool IsActive;
        public bool DidExecute;

        static readonly string[] Sev = { "ismeretlen", "alacsony", "közepes", "magas", "súlyos" };
        static readonly Dictionary<int, string> Cat = new Dictionary<int, string>
        {
            {1,"reklámprogram (adware)"},{2,"kémprogram (spyware)"},{3,"jelszólopó"},{4,"trójai letöltő"},
            {5,"féreg (worm)"},{6,"hátsó kapu (backdoor)"},{7,"távoli elérésű trójai"},{8,"trójai"},
            {10,"billentyűzetfigyelő (keylogger)"},{12,"megfigyelő szoftver"},{13,"böngészőmódosító"},
            {18,"biztonsági beállítást letiltó"},{27,"potenciálisan nemkívánatos szoftver"},
            {33,"eszköz"},{36,"trójai dropper"},{40,"vírus"},{43,"ismeretlen"},{45,"viselkedés alapú"}
        };

        public static ThreatInfo Lookup(string threatName)
        {
            try
            {
                using (ManagementObjectSearcher s = new ManagementObjectSearcher(
                    @"root\Microsoft\Windows\Defender",
                    "SELECT ThreatName, SeverityID, CategoryID, IsActive, DidThreatExecute FROM MSFT_MpThreat"))
                {
                    foreach (ManagementBaseObject o in s.Get())
                    {
                        string n = Convert.ToString(o["ThreatName"]);
                        if (!string.Equals(n, threatName, StringComparison.OrdinalIgnoreCase)) continue;
                        ThreatInfo ti = new ThreatInfo();
                        int sev = Convert.ToInt32(o["SeverityID"]);
                        int cat = Convert.ToInt32(o["CategoryID"]);
                        ti.Severity = sev >= 0 && sev < Sev.Length ? Sev[sev] : sev.ToString();
                        string cs;
                        ti.Category = Cat.TryGetValue(cat, out cs) ? cs : ("azonosító: " + cat);
                        ti.IsActive = o["IsActive"] != null && Convert.ToBoolean(o["IsActive"]);
                        ti.DidExecute = o["DidThreatExecute"] != null && Convert.ToBoolean(o["DidThreatExecute"]);
                        return ti;
                    }
                }
            }
            catch (Exception) { }
            return null;
        }

        // A Defender-nevek felépítése: Típus:Platform/Család.változat, pl. Trojan:Win32/Wacatac.B!ml
        public static string TypeFromName(string name)
        {
            int c = name.IndexOf(':');
            int sl = name.IndexOf('/');
            string type = c > 0 ? name.Substring(0, c) : "";
            string platform = (c > 0 && sl > c) ? name.Substring(c + 1, sl - c - 1) : "";
            if (type.Length == 0) return "nem állapítható meg a névből";
            return platform.Length > 0 ? type + " (platform: " + platform + ")" : type;
        }
    }

    // ---------- Főablak ----------
    class MainForm : Form
    {
        ListView listQ, listH;
        TabControl tabs;
        List<QItem> qItems = new List<QItem>();
        List<QItem> hItems = new List<QItem>();
        ListView list { get { return tabs.SelectedIndex == 1 ? listH : listQ; } }
        TextBox status;
        Button btnRestore, btnDetails, btnRefresh, btnRaw, btnOpen, btnHelp, btnExit;
        string startupReport = "";
        bool isAdmin;
        string lastRaw = "";
        string mpcmd;
        List<string> candidates;

        public MainForm(bool admin)
        {
            isAdmin = admin;
            candidates = Proc.FindAllMpCmdRun();
            mpcmd = candidates.Count > 0 ? candidates[0] : null;

            Text = "Karantén kezelő";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(960, 560);
            MinimumSize = new Size(640, 420);

            TableLayoutPanel t = new TableLayoutPanel();
            t.Dock = DockStyle.Fill;
            t.ColumnCount = 2;
            t.RowCount = 4;
            t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            t.Padding = new Padding(8);
            Controls.Add(t);

            Label l1 = new Label();
            l1.Text = "Fájlok (a fülek között Ctrl+Tab vagy Ctrl+1, Ctrl+2 vált):";
            l1.AutoSize = true;
            l1.TabIndex = 0;
            l1.Margin = new Padding(0, 0, 0, 4);

            tabs = new TabControl();
            tabs.Dock = DockStyle.Fill;
            tabs.TabIndex = 1;
            tabs.AccessibleName = "Fülek";
            TabPage pageQ = new TabPage("Karantén");
            TabPage pageH = new TabPage("Előzmények");
            listQ = MakeList(false);
            listH = MakeList(true);
            pageQ.Controls.Add(listQ);
            pageH.Controls.Add(listH);
            tabs.TabPages.Add(pageQ);
            tabs.TabPages.Add(pageH);
            tabs.SelectedIndexChanged += delegate { UpdateButtons(); };

            // A gombok a lista mellett, jobbra; Tab-bal a listából egyenként elérhetők.
            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.FlowDirection = FlowDirection.TopDown;
            buttons.WrapContents = false;
            buttons.AutoSize = true;
            buttons.Dock = DockStyle.Top;
            buttons.TabIndex = 2;
            buttons.Margin = new Padding(8, 0, 0, 0);
            btnRestore = MakeButton("&Visszaállítás", 3, delegate { RestoreSelected(); });
            btnDetails = MakeButton("&Részletek", 4, delegate { ShowDetails(); });
            btnRefresh = MakeButton("&Frissítés", 5, delegate { RefreshList(); });
            btnRaw = MakeButton("&Nyers kimenet", 6, delegate { ShowText("Nyers kimenet", lastRaw); });
            btnOpen = MakeButton("&Mappa megnyitása", 7, delegate { OpenFolder(); });
            btnHelp = MakeButton("&Súgó (F1)", 8, delegate { ShowHelp(); });
            btnExit = MakeButton("&Kilépés", 9, delegate { Close(); });
            Button[] all = new Button[] { btnRestore, btnDetails, btnRefresh, btnRaw, btnOpen, btnHelp, btnExit };
            foreach (Button bt in all) { bt.AutoSize = false; bt.Size = new Size(170, 32); }
            buttons.Controls.AddRange(all);

            Label l2 = new Label();
            l2.Text = "Á&llapot:";
            l2.AutoSize = true;
            l2.TabIndex = 10;
            l2.Margin = new Padding(0, 8, 0, 4);

            status = new TextBox();
            status.ReadOnly = true;
            status.Multiline = true;
            status.ScrollBars = ScrollBars.Vertical;
            status.Height = 70;
            status.Dock = DockStyle.Fill;
            status.TabIndex = 11;
            status.AccessibleName = "Állapot";

            t.Controls.Add(l1, 0, 0);
            t.SetColumnSpan(l1, 2);
            t.Controls.Add(tabs, 0, 1);
            t.Controls.Add(buttons, 1, 1);
            t.Controls.Add(l2, 0, 2);
            t.SetColumnSpan(l2, 2);
            t.Controls.Add(status, 0, 3);
            t.SetColumnSpan(status, 2);

            AcceptButton = null;
            CancelButton = btnExit;
            KeyPreview = true;
            KeyDown += delegate(object sender, KeyEventArgs e) { if (e.KeyCode == Keys.F1) { e.Handled = true; ShowHelp(); }
                else if (e.Control && e.KeyCode == Keys.D1) { e.Handled = true; tabs.SelectedIndex = 0; listQ.Focus(); }
                else if (e.Control && e.KeyCode == Keys.D2) { e.Handled = true; tabs.SelectedIndex = 1; listH.Focus(); } };
            Shown += delegate { OnFirstShown(); };
        }

        ListView MakeList(bool history)
        {
            ListView lv = new ListView();
            lv.View = View.Details;
            lv.FullRowSelect = true;
            lv.MultiSelect = true;
            lv.HideSelection = false;
            lv.Dock = DockStyle.Fill;
            lv.TabIndex = 0;
            lv.AccessibleName = history ? "Előzmények listája" : "Karanténban lévő fájlok";
            lv.Columns.Add("Fájlnév", 170);
            lv.Columns.Add("Eredeti hely", 320);
            lv.Columns.Add("Vírus / fenyegetés", 190);
            if (history)
            {
                lv.Columns.Add("Észlelés ideje", 140);
                lv.Columns.Add("Művelet", 130);
                lv.Columns.Add("Sikeres", 70);
            }
            else
            {
                lv.Columns.Add("Karanténba helyezve", 160);
            }
            lv.ItemActivate += delegate { ShowDetails(); };
            lv.SelectedIndexChanged += delegate { UpdateButtons(); };
            return lv;
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
            try
            {
                if (isAdmin) startupReport = Folders.EnsureAll();
                else startupReport = "Nincs rendszergazdai jog: a kivételek felvétele és a visszaállítás nem fog működni. Indítsd újra a programot, és engedélyezd a felugró ablakot.";
            }
            catch (Exception ex)
            {
                startupReport = "Induláskori hiba: " + ex.Message;
            }
            if (startupReport.Length > 0)
            {
                SetStatus(startupReport);
            }
            try { RefreshList(); }
            catch (Exception ex) { SetStatus("A lista olvasása sikertelen: " + ex.Message); }
            if (startupReport.Length > 0)
            {
                MessageBox.Show(this, startupReport, "Mappák és kivételek", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            list.Focus();
        }

        static string FirstLines(string s, int n)
        {
            string[] ls = s.Replace("\r", "").Split('\n');
            StringBuilder sb = new StringBuilder();
            int c = 0;
            foreach (string l in ls) { if (l.Trim().Length == 0) continue; sb.AppendLine(l); if (++c >= n) break; }
            return sb.ToString();
        }

        void SetStatus(string s)
        {
            status.Text = s.Replace("\r\n", "\n").Replace("\n", "\r\n");
        }

        void UpdateButtons()
        {
            bool any = list.SelectedItems.Count > 0;
            bool canRestore = any;
            if (any && tabs.SelectedIndex == 1)
            {
                foreach (ListViewItem li in list.SelectedItems)
                    if (!((QItem)li.Tag).IsQuarantineAction) { canRestore = false; break; }
            }
            btnRestore.Enabled = canRestore;
            btnDetails.Enabled = any;
        }

        void LoadItems()
        {
            StringBuilder raw = new StringBuilder();
            List<QItem> items = new List<QItem>();
            if (candidates.Count == 0)
            {
                raw.AppendLine("Az MpCmdRun.exe nem található. A Microsoft Defender nincs telepítve vagy le van tiltva.");
            }
            foreach (string exe in candidates)
            {
                ProcResult r = Proc.Run(exe, "-Restore -ListAll");
                raw.AppendLine("== " + exe + " -Restore -ListAll (kilépési kód: " + r.Code + ") ==");
                raw.AppendLine(r.Output);
                List<QItem> found = Quarantine.Parse(r.Output);

                // A -Output kapcsoló UTF-8 fájlba írja a karantén elemeit (ékezetes útvonalakhoz is megbízható).
                string tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "karanten-lista.txt");
                try
                {
                    if (File.Exists(tmp)) File.Delete(tmp);
                    ProcResult r2 = Proc.Run(exe, "-Restore -ListAll -Output " + Proc.Quote(tmp));
                    raw.AppendLine("== " + exe + " -Output (kilépési kód: " + r2.Code + ") ==");
                    raw.AppendLine(r2.Output);
                    if (File.Exists(tmp))
                    {
                        string fileText = File.ReadAllText(tmp, Encoding.UTF8);
                        raw.AppendLine("-- a kimeneti fájl tartalma --");
                        raw.AppendLine(fileText);
                        Quarantine.AddUnique(found, Quarantine.Parse(fileText));
                    }
                }
                catch (Exception ex) { raw.AppendLine("-Output hiba: " + ex.Message); }

                if (found.Count > 0) { Quarantine.AddUnique(items, found); if (items.Count == found.Count) mpcmd = exe; }
            }
            string note;
            List<QItem> hist = Quarantine.FromHistory(out note);
            raw.AppendLine("== Védelmi előzmények (WMI) ==");
            raw.AppendLine(note.Length > 0 ? note : (hist.Count + " találat"));
            hist.Sort(delegate(QItem x, QItem y) { return string.CompareOrdinal(y.Time, x.Time); });
            qItems = items;
            hItems = hist;
            lastRaw = raw.ToString();
        }

        void FillList(ListView lv, List<QItem> items, bool history)
        {
            lv.BeginUpdate();
            lv.Items.Clear();
            foreach (QItem it in items)
            {
                string[] cols = history
                    ? new string[] { it.FileName, it.Dir, it.Threat, it.Time, it.Action, it.Success }
                    : new string[] { it.FileName, it.Dir, it.Threat, it.Time };
                ListViewItem li = new ListViewItem(cols);
                li.Tag = it;
                lv.Items.Add(li);
            }
            lv.EndUpdate();
            if (lv.Items.Count > 0)
            {
                lv.Items[0].Selected = true;
                lv.Items[0].Focused = true;
            }
        }

        void ReloadAll()
        {
            LoadItems();
            FillList(listQ, qItems, false);
            FillList(listH, hItems, true);
            UpdateButtons();
        }

        void RefreshList()
        {
            Cursor = Cursors.WaitCursor;
            try
            {
                ReloadAll();
                string msg;
                if (candidates.Count == 0) msg = lastRaw;
                else
                {
                    msg = "Karantén: " + qItems.Count + " elem. Előzmények: " + hItems.Count + " elem.";
                    if (qItems.Count == 0) msg += "\r\nA karanténból nem jött elem. A Nyers kimenet gomb megmutatja, mit adott vissza a Defender.\r\n" + FirstLines(lastRaw, 6);
                }
                SetStatus(msg);
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            list.Focus();
        }

        const string HelpText =
"KARANTÉN KEZELŐ - SÚGÓ\n" +
"\n" +
"Mire való\n" +
"A program a Microsoft Defender karanténjában lévő fájlokat listázza, megmutatja a részleteiket, és a karanten nevű mappába visszaállítja őket.\n" +
"\n" +
"Billentyűk\n" +
"F1: ez a súgó.\n" +
"Tab / Shift+Tab: lépés a fülek, a lista, a gombok és az állapot mező között.\n" +
"Ctrl+1 / Ctrl+2: ugrás a Karantén illetve az Előzmények fülre.\n" +
"Fel és Le nyíl: lépés a lista elemei között. Ctrl+Space vagy Shift+nyilak: több elem kijelölése.\n" +
"Enter a listán: részletek.\n" +
"Escape: kilépés a főablakból; a súgó és a részletek ablakot bezárja.\n" +
"Alt + a gombok aláhúzott betűje: a gomb közvetlen elérése.\n" +
"\n" +
"A lista\n" +
"Két füle van. Váltás: Ctrl+Tab, a fül nevén a nyilak, vagy Ctrl+1 és Ctrl+2.\n" +
"1. Karantén: a Defender karanténjában most is meglévő elemek. Oszlopok: fájlnév, eredeti hely, vírus / fenyegetés neve, karanténba helyezés ideje. Ezek állíthatók vissza.\n" +
"2. Előzmények: a Defender védelmi előzményei, vagyis minden észlelés, a legfrissebb elöl. Oszlopok: fájlnév, eredeti hely, vírus / fenyegetés neve, észlelés ideje, művelet (például karanténba helyezés, törlés, engedélyezés), sikeres-e. Visszaállítás csak a karanténba helyezés műveletű elemekre elérhető; a többinél a gomb le van tiltva. A Részletek mindkét fülön működik.\n" +
"Egyszerre több elem is kijelölhető.\n" +
"\n" +
"Gombok, a lista mellett, Tab sorrendben\n" +
"Visszaállítás (Alt+V): a kijelölt elemeket a felhasználói mappában lévő karanten mappába állítja vissza. Előtte megerősítést kér. Elemenként három módszert próbál (útvonal alapján, név és útvonal alapján, végül a fenyegetés neve alapján), és akkor tekinti sikeresnek, ha új fájl jelent meg a karanten mappában. Az eredmény külön olvasható ablakban jelenik meg, benne a Defender teljes kimenetével. A Defender a -Path használatakor az elemet a karanténban is megtartja.\n" +
"Részletek (Alt+R): külön ablakban, olvasható szövegmezőben mutatja a fájlnevet, az eredeti helyet, a teljes útvonalat, a vírus nevét és típusát, a Defender szerinti kategóriát és súlyosságot, hogy aktív-e, lefutott-e a fájl, és mikor került karanténba. Az ablakot a Bezárás gomb vagy az Escape zárja be.\n" +
"Frissítés (Alt+F): újraolvassa a karantén tartalmát.\n" +
"Nyers kimenet (Alt+N): megmutatja a Defender listázó parancsának változtatás nélküli kimenetét. Ha a lista üres, de a karanténban van fájl, itt látszik, mit adott vissza a Defender.\n" +
"Mappa megnyitása (Alt+M): megnyitja a karanten mappát a Fájlkezelőben.\n" +
"Súgó (Alt+S): ez az ablak.\n" +
"Kilépés (Alt+K): bezárja a programot.\n" +
"\n" +
"Állapot mező\n" +
"A lista alatt található, csak olvasható. Az utolsó művelet eredményét írja ki: hány elem van karanténban, mi sikerült a visszaállításból, mi történt induláskor.\n" +
"\n" +
"Mappák és kivételek\n" +
"Minden induláskor a program megnézi, hogy a felhasználói mappában megvan-e a karanten és a karanten2 mappa. Ha mindkettő megvan, semmit nem csinál. Ha valamelyik hiányzik, létrehozza, és a hiányzó mappát meg a programot felveszi a Defender kivételei közé. A karanten2 mappa üres marad. A Visszaállítás és a Mappa megnyitása is újra létrehozza a karanten mappát, ha közben letörölték.\n" +
"\n" +
"Jogosultság\n" +
"A program rendszergazdai jogot kér (UAC ablak). Enélkül sem a kivételek felvétele, sem a visszaállítás nem működik.\n" +
"\n" +
"Korlátok\n" +
"A karantén listázását és a visszaállítást a Microsoft csak a Defender saját MpCmdRun.exe programjával teszi lehetővé, ezért a program ezt indítja háttérben, ablak nélkül. Ha a Defender Tamper Protection funkciója be van kapcsolva, a kivételek felvétele sikertelen lehet; ezt az induláskor kiírt üzenet jelzi.\n";

        void ShowHelp()
        {
            ShowText("Súgó", HelpText);
        }

        void ShowDetails()
        {
            if (list.SelectedItems.Count == 0) return;
            QItem it = (QItem)list.SelectedItems[0].Tag;
            ThreatInfo ti = ThreatInfo.Lookup(it.Threat);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Fájlnév: " + it.FileName);
            sb.AppendLine("Eredeti hely: " + it.Dir);
            sb.AppendLine("Teljes eredeti útvonal: " + it.Path);
            sb.AppendLine("Vírus / fenyegetés neve: " + it.Threat);
            sb.AppendLine("Vírus típusa: " + ThreatInfo.TypeFromName(it.Threat));
            if (ti != null)
            {
                sb.AppendLine("Kategória (Defender): " + ti.Category);
                sb.AppendLine("Súlyosság: " + ti.Severity);
                sb.AppendLine("Aktív: " + (ti.IsActive ? "igen" : "nem"));
                sb.AppendLine("Lefutott a fájl: " + (ti.DidExecute ? "igen" : "nem"));
            }
            if (it.Source == "history")
            {
                sb.AppendLine("Észlelés ideje: " + it.Time);
                sb.AppendLine("Művelet: " + it.Action);
                sb.AppendLine("A művelet sikeres volt: " + it.Success);
                sb.AppendLine("Forrás: védelmi előzmények");
            }
            else
            {
                sb.AppendLine("Karanténba helyezve: " + it.Time);
                sb.AppendLine("Forrás: karantén");
            }
            ShowText("Részletek - " + it.FileName, sb.ToString());
            list.Focus();
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
            StringBuilder sum = new StringBuilder();
            int ok = 0;
            Cursor = Cursors.WaitCursor;
            try
            {
                foreach (QItem it in chosen)
                {
                    bool restored = TryRestore(it, dest, log);
                    if (restored) { ok++; sum.AppendLine("Visszaállítva: " + it.FileName); }
                    else sum.AppendLine("Sikertelen: " + it.FileName);
                }
                ReloadAll();
            }
            finally
            {
                Cursor = Cursors.Default;
            }
            string result = ok + " / " + chosen.Count + " elem visszaállítva ide: " + dest + "\r\n" + sum.ToString() +
                "\r\nA -Path használatakor a Defender a karanténban is megtartja az elemet.\r\n\r\nA Defender kimenete:\r\n" + log.ToString();
            SetStatus(ok + " / " + chosen.Count + " elem visszaállítva ide: " + dest);
            ShowText("Visszaállítás eredménye", result);
            list.Focus();
        }

        static Dictionary<string, long> Snapshot(string dir)
        {
            Dictionary<string, long> d = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (string f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                    d[f] = File.GetLastWriteTimeUtc(f).Ticks + new FileInfo(f).Length;
            }
            catch (Exception) { }
            return d;
        }

        static bool Changed(Dictionary<string, long> before, Dictionary<string, long> after)
        {
            foreach (KeyValuePair<string, long> kv in after)
            {
                long old;
                if (!before.TryGetValue(kv.Key, out old) || old != kv.Value) return true;
            }
            return false;
        }

        // Több próbálkozás, amíg új fájl nem jelenik meg a célmappában (a Defender kimenete nyelvfüggő, ezért nem azt olvassuk).
        bool TryRestore(QItem it, string dest, StringBuilder log)
        {
            List<string> attempts = new List<string>();
            attempts.Add("-Restore -FilePath " + Proc.Quote(it.Path) + " -Path " + Proc.Quote(dest));
            if (it.Threat.Length > 0)
            {
                attempts.Add("-Restore -Name " + Proc.Quote(it.Threat) + " -FilePath " + Proc.Quote(it.Path) + " -Path " + Proc.Quote(dest));
                attempts.Add("-Restore -Name " + Proc.Quote(it.Threat) + " -All -Path " + Proc.Quote(dest));
            }
            foreach (string args in attempts)
            {
                Dictionary<string, long> before = Snapshot(dest);
                ProcResult r = Proc.Run(mpcmd, args);
                log.AppendLine("> MpCmdRun " + args);
                log.AppendLine("  kilépési kód: " + r.Code);
                log.AppendLine("  " + r.Output.Trim().Replace("\n", "\n  "));
                if (Changed(before, Snapshot(dest)))
                {
                    log.AppendLine("  -> sikerült (új fájl a célmappában)");
                    return true;
                }
            }
            return false;
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
            tb.TabIndex = 0;
            tb.AccessibleName = title;
            tb.Text = text.Replace("\r\n", "\n").Replace("\n", "\r\n");
            Button close = new Button();
            close.Text = "&Bezárás";
            close.Dock = DockStyle.Bottom;
            close.Height = 34;
            close.TabIndex = 1;
            close.DialogResult = DialogResult.Cancel;
            f.Controls.Add(tb);
            f.Controls.Add(close);
            f.CancelButton = close;
            f.Shown += delegate { tb.Focus(); tb.SelectionStart = 0; tb.SelectionLength = 0; };
            f.ShowDialog(this);
        }
    }
}
