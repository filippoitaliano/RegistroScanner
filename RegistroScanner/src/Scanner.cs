using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace RegistroScanner
{
    /// <summary>Motore di scansione: ogni chiave è aperta in sola lettura con vista Registry64.</summary>
    public sealed class Scanner
    {
        const string HKLM = "HKLM", HKCU = "HKCU";

        readonly CancellationToken _ct;
        readonly Action<ScanProgress> _progress;
        readonly List<Row> _rows = new List<Row>();
        readonly Dictionary<string, Row> _seen = new Dictionary<string, Row>(StringComparer.OrdinalIgnoreCase);
        readonly PathProbe _probe = new PathProbe();
        readonly Corpus _corpus = new Corpus();
        readonly HashSet<string> _clsids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> _classNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> _vsInstances = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<int> _vsMajors = new HashSet<int>();
        int _vsReadErrors;
        RegistryKey _hklm, _hkcu;
        int _denied;

        readonly string _windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
        readonly string _pf = Environment.GetEnvironmentVariable("ProgramW6432") ?? @"C:\Program Files";
        readonly string _pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)";
        readonly string _programData = Environment.GetEnvironmentVariable("ProgramData") ?? @"C:\ProgramData";
        readonly string _local = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
        readonly string _roaming = Environment.GetEnvironmentVariable("APPDATA") ?? "";
        readonly string _profile = Environment.GetEnvironmentVariable("USERPROFILE") ?? "";
        string _localLow { get { return string.IsNullOrEmpty(_profile) ? "" : Path.Combine(_profile, @"AppData\LocalLow"); } }

        public Scanner(CancellationToken ct, Action<ScanProgress> progress)
        {
            _ct = ct;
            _progress = progress ?? (p => { });
        }

        // ------------------------------------------------------------ entry

        public ScanResult Run()
        {
            var sw = Stopwatch.StartNew();
            var res = new ScanResult();
            _hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            _hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64);
            _probe.MsiProductExists = MsiProductExists;

            var sections = new List<KeyValuePair<string, Action>>
            {
                S("Universo CLSID e classi", ScanUniverse),
                S("Pacchetti Appx", ScanAppx),
                S("Steam, Epic e Visual Studio", ScanManifests),
                S("Cartelle dei programmi", ScanDirs),
                S("Programmi installati", ScanUninstall),
                S("Servizi", ScanServices),
                S("Prodotti MSI", ScanMsi),
                S("Corpus installato", () => _corpus.Seal()),
                S("Avvio automatico", ScanAutoruns),
                S("COM: CLSID", ScanClsid),
                S("COM: TypeLib", ScanTypeLib),
                S("COM: interfacce", ScanInterfaces),
                S("Classi, protocolli ed estensioni", ScanClasses),
                S("App Paths, SharedDLLs, cartelle Installer", ScanMiscPaths),
                S("Font, ODBC, pannello di controllo, native messaging", ScanFontsOdbc),
                S("Estensioni della shell", ScanShellRegs),
                S("Firewall", ScanFirewall),
                S("Tracce di utilizzo", ScanTraces),
                S("Ambiente, profili, IFEO, app registrate", ScanEnvEtc),
                S("Operazioni pianificate", ScanTasks),
                S("Chiavi dei produttori", ScanVendors),
            };

            try
            {
                for (int i = 0; i < sections.Count; i++)
                {
                    _ct.ThrowIfCancellationRequested();
                    _progress(new ScanProgress { Section = sections[i].Key, Percent = i * 100 / sections.Count, Rows = _rows.Count });
                    try { sections[i].Value(); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception) { _denied++; } // una sezione guasta non ferma la scansione
                }
            }
            catch (OperationCanceledException) { res.Cancelled = true; }
            finally
            {
                ApplySubtreeProtection(_rows);
                _hklm.Dispose();
                _hkcu.Dispose();
            }
            _progress(new ScanProgress { Section = res.Cancelled ? "Annullata" : "Completata", Percent = 100, Rows = _rows.Count });
            res.Rows = _rows;
            for (int i = 0; i < _rows.Count; i++) _rows[i].Seq = i;
            res.DeniedKeys = _denied;
            res.Elapsed = sw.Elapsed;
            return res;
        }

        static KeyValuePair<string, Action> S(string n, Action a) { return new KeyValuePair<string, Action>(n, a); }

        // ------------------------------------------------------------ helpers registro

        RegistryKey Base(string hive) { return hive == HKLM ? _hklm : _hkcu; }

        RegistryKey Open(string hive, string path)
        {
            try { return Base(hive).OpenSubKey(path, false); }
            catch (SecurityException) { _denied++; return null; }
            catch (UnauthorizedAccessException) { _denied++; return null; }
            catch (IOException) { _denied++; return null; }
        }

        RegistryKey OpenSub(RegistryKey k, string sub)
        {
            try { return k.OpenSubKey(sub, false); }
            catch (SecurityException) { _denied++; return null; }
            catch (UnauthorizedAccessException) { _denied++; return null; }
            catch (IOException) { _denied++; return null; }
        }

        string[] SubNames(RegistryKey k)
        {
            try { return k.GetSubKeyNames(); }
            catch (Exception) { _denied++; return new string[0]; }
        }

        string[] ValNames(RegistryKey k)
        {
            try { return k.GetValueNames(); }
            catch (Exception) { _denied++; return new string[0]; }
        }

        static object Val(RegistryKey k, string name)
        {
            try { return k.GetValue(name); } catch (Exception) { return null; }
        }

        static string Str(RegistryKey k, string name)
        {
            object o = Val(k, name);
            return o as string;
        }

        /// <summary>Esegue a su ogni sottochiave leggibile; le eccezioni restano confinate alla chiave.</summary>
        void ForEachSub(string hive, string path, Action<string, RegistryKey> a)
        {
            using (RegistryKey root = Open(hive, path))
            {
                if (root == null) return;
                ForEachSub(root, a);
            }
        }

        void ForEachSub(RegistryKey root, Action<string, RegistryKey> a)
        {
            foreach (string n in SubNames(root))
            {
                _ct.ThrowIfCancellationRequested();
                using (RegistryKey k = OpenSub(root, n))
                {
                    if (k == null) continue;
                    try { a(n, k); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception) { _denied++; }
                }
            }
        }

        bool KeyExists(string hive, string path)
        {
            using (RegistryKey k = Open(hive, path)) return k != null;
        }

        // ------------------------------------------------------------ costruzione righe

        Row Add(string groupId, string hive, string keyPath, string valueName, ActionKind action, string deleteRoot, string item, string detail, ProbeResult? pr = null, string extra = null, int? capTo = null)
        {
            GroupDef g = Groups.Get(groupId);
            int? conf = g.Conf;
            string reason = g.Why;

            if (conf != null && pr != null)
            {
                string why = _probe.ExplainStatus(pr.Value.Status);
                if (pr.Value.Status == PathStatus.DriveAbsent || pr.Value.Status == PathStatus.Network) { conf = Math.Min(conf.Value, 50); reason = why + " " + reason; }
                else if (pr.Value.Status == PathStatus.AppxUnverified) { conf = Math.Min(conf.Value, 70); reason = why + " " + reason; }
            }
            if (conf != null && capTo != null) conf = Math.Min(conf.Value, capTo.Value);
            int? readCap = CapForReadErrors(groupId, _corpus.SteamReadErrors, _vsReadErrors);
            if (conf != null && readCap != null && conf.Value > readCap.Value)
            {
                conf = readCap;
                reason = "Manifest o istanze non leggibili: verifica incompleta. " + reason;
            }
            if (!string.IsNullOrEmpty(extra)) reason = reason + " " + extra;

            var r = new Row
            {
                Confidence = conf,
                Tier = Tiers.Of(conf),
                Area = g.Area,
                Group = g.Title,
                GroupId = g.Id,
                Hive = hive,
                KeyPath = keyPath,
                ValueName = valueName,
                Action = action,
                DeleteRoot = deleteRoot ?? "",
                Item = item ?? "",
                Detail = detail ?? "",
                Reason = reason,
                How = g.How,
            };
            if (pr != null && pr.Value.IsOrphan && pr.Value.Status != PathStatus.MsiMissing && pr.Value.Status != PathStatus.BareMissing)
            {
                r.ProbePath = pr.Value.Target;
                r.ProbeStatus = pr.Value.Status;
            }

            string why2;
            r.Deletable = Tiers.IsDeletable(r.Tier) && g.RegistryDeletable && !string.IsNullOrEmpty(hive) && !string.IsNullOrEmpty(deleteRoot);
            if (r.Deletable && !DeleteGuard.Check(hive, deleteRoot, action, valueName, out why2))
                Demote(r, "Esclusa dalla protezione: " + why2 + ".", why2);

            if (r.Deletable)
            {
                string key = hive + "\\" + deleteRoot + "|" + (valueName ?? "") + "|" + action;
                Row prev;
                if (_seen.TryGetValue(key, out prev))
                {
                    if ((r.Confidence ?? 0) < (prev.Confidence ?? 0))
                    {
                        prev.Confidence = r.Confidence; prev.Tier = r.Tier; prev.Area = r.Area; prev.Group = r.Group; prev.GroupId = r.GroupId;
                        prev.Reason = r.Reason; prev.How = r.How;
                        prev.Deletable = r.Deletable;
                    }
                    return prev;
                }
                _seen[key] = r;
                StampContent(r);
            }
            _rows.Add(r);
            return r;
        }

        /// <summary>Registra l'impronta del contenuto; ciò che non è leggibile o è un collegamento non è eliminabile.</summary>
        void StampContent(Row r)
        {
            try
            {
                if (RegNative.IsLinkPath(Base(r.Hive), r.DeleteRoot)) { Demote(r, "La chiave è un collegamento del registro.", "collegamento del registro"); return; }
                string text = DeleteEngine.Serialize(Base(r.Hive), r.Hive, r.DeleteRoot, r.Action, r.ValueName);
                if (text == null) { Demote(r, "La voce non è leggibile.", "voce non leggibile"); return; }
                r.ContentHash = DeleteEngine.Hash(text);
            }
            catch (Exception ex)
            {
                Demote(r, "Contenuto non serializzabile, quindi senza backup possibile.", "contenuto non serializzabile: " + ex.Message);
            }
        }

        /// <summary>Toglie l'eliminabilità e abbassa il livello, così etichetta e casella restano coerenti.</summary>
        public static void Demote(Row r, string text, string rejection)
        {
            r.Deletable = false;
            r.Checked = false;
            r.GuardRejection = rejection;
            if (r.Confidence != null) r.Confidence = Math.Min(r.Confidence.Value, 35);
            r.Tier = Tiers.Of(r.Confidence);
            r.Reason = r.Reason + " " + text;
        }

        /// <summary>Tetto di sicurezza per i gruppi che dipendono da manifest o istanze non letti.</summary>
        public static int? CapForReadErrors(string groupId, int steamErrors, int vsErrors)
        {
            if (steamErrors > 0 && (groupId == "un-steam" || groupId == "ve-unknown")) return 60;
            if (vsErrors > 0 && (groupId == "ve-vs" || groupId == "pr-ext-vs")) return 60;
            return null;
        }

        /// <summary>Una chiave che su sé stessa o nel sottoalbero ha un verdetto non eliminabile non può essere eliminata.</summary>
        public static int ApplySubtreeProtection(List<Row> rows)
        {
            int demoted = 0;
            for (int pass = 0; pass < 4; pass++)
            {
                var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var vals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (Row r in rows)
                {
                    if (r.Deletable || string.IsNullOrEmpty(r.Hive)) continue;
                    string cur = r.Hive + "\\" + r.KeyPath;
                    if (r.ValueName != null) vals.Add(cur + "|" + r.ValueName);
                    while (true)
                    {
                        keys.Add(cur);
                        int i = cur.LastIndexOf('\\');
                        if (i <= 0) break;
                        cur = cur.Substring(0, i);
                    }
                }
                int changed = 0;
                foreach (Row r in rows)
                {
                    if (!r.Deletable) continue;
                    string full = r.Hive + "\\" + r.DeleteRoot;
                    bool hit = r.Action == ActionKind.DeleteKey ? keys.Contains(full) : vals.Contains(full + "|" + r.ValueName);
                    if (!hit) continue;
                    Demote(r, "Contiene voci da non toccare, quindi non si elimina per intero.", "sottoalbero con voci non eliminabili");
                    changed++;
                }
                demoted += changed;
                if (changed == 0) break;
            }
            return demoted;
        }

        void AddFp(string hive, string keyPath, string valueName, string note, string detail)
        {
            string extra = note != null && note.IndexOf(PathProbe.NoteProtected, StringComparison.Ordinal) >= 0
                ? "Il percorso non è verificabile senza amministratore: la posizione non è elencabile con questi permessi, quindi la voce non si considera orfana."
                : null;
            Add("fp", hive, keyPath, valueName, valueName != null ? ActionKind.DeleteValue : ActionKind.DeleteKey, keyPath, note, detail, null, extra);
        }

        /// <summary>Se la voce è stata salvata da una regola di probing, la registra come falso positivo.</summary>
        bool MaybeFp(ProbeResult r, string hive, string keyPath, string valueName, string detail)
        {
            if (r.FpNote == null) return false;
            AddFp(hive, keyPath, valueName, r.FpNote, detail);
            return true;
        }

        // ------------------------------------------------------------ path helpers

        bool UnderDir(string p, string dir)
        {
            return !string.IsNullOrEmpty(dir) && p.Length > dir.Length && p.StartsWith(dir, StringComparison.OrdinalIgnoreCase) && p[dir.Length] == '\\';
        }

        bool IsSystemPath(string p)
        {
            return UnderDir(p, _windir) || p.IndexOf(@"\Common Files\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        bool IsTransientPath(string p)
        {
            return Regex.IsMatch(p, @"\\(Downloads|Desktop|Temp|Tmp)\\", RegexOptions.IgnoreCase);
        }

        bool IsUserPath(string p)
        {
            return Regex.IsMatch(p, @"^[A-Za-z]:\\Users\\", RegexOptions.IgnoreCase);
        }

        static readonly Regex SteamCommon = new Regex(@"\\steamapps\\common\\([^\\]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly HashSet<string> Containers = new HashSet<string>(new[] { "Microsoft", "Common Files", "Packages", "Programs", "WindowsApps", "Windows" }, StringComparer.OrdinalIgnoreCase);

        /// <summary>La cartella radice del programma esiste e contiene eseguibili? Steam: serve il manifest.</summary>
        bool ProgramPresent(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            Match s = SteamCommon.Match(path);
            if (s.Success) return _corpus.SteamInstallDirs.Contains(s.Groups[1].Value);

            foreach (string b in new[] { _pf, _pf86, _programData, _local, _roaming, _localLow })
            {
                if (!UnderDir(path, b)) continue;
                string root = RootBelow(path, b);
                return root != null && DirWithExe(root);
            }
            if (path.Length > 3 && path[1] == ':' && path[2] == '\\')
            {
                int i = path.IndexOf('\\', 3);
                if (i < 0) return false;
                string seg = path.Substring(3, i - 3);
                if (seg.Equals("Users", StringComparison.OrdinalIgnoreCase) || seg.Equals("Windows", StringComparison.OrdinalIgnoreCase)) return false;
                return DirWithExe(path.Substring(0, i));
            }
            return false;
        }

        static string RootBelow(string path, string b)
        {
            string rest = path.Substring(b.Length + 1);
            string[] segs = rest.Split('\\');
            if (segs.Length < 2) return null; // il percorso è la cartella stessa o un file in radice
            string root = Path.Combine(b, segs[0]);
            if (Containers.Contains(segs[0]))
            {
                if (segs.Length < 3) return null;
                root = Path.Combine(root, segs[1]);
            }
            return root;
        }

        bool DirWithExe(string d)
        {
            try { return Directory.Exists(d) && _corpus.HasExecutable(d); } catch (Exception) { return false; }
        }

        // ------------------------------------------------------------ MSI

        public static string Squish(string guid)
        {
            string x = guid.Replace("{", "").Replace("}", "").Replace("-", "");
            if (x.Length != 32) return x.ToUpperInvariant();
            var c = new char[32];
            int o = 0;
            foreach (var seg in new[] { new[] { 0, 8 }, new[] { 8, 4 }, new[] { 12, 4 } })
                for (int i = seg[0] + seg[1] - 1; i >= seg[0]; i--) c[o++] = x[i];
            for (int i = 16; i < 32; i += 2) { c[o++] = x[i + 1]; c[o++] = x[i]; }
            return new string(c).ToUpperInvariant();
        }

        bool MsiProductExists(string guid)
        {
            string sq = Squish(guid);
            return KeyExists(HKLM, @"SOFTWARE\Classes\Installer\Products\" + sq)
                || KeyExists(HKCU, @"Software\Microsoft\Installer\Products\" + sq)
                || KeyExists(HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\" + sq);
        }

        // ------------------------------------------------------------ universi

        static readonly string[][] ClsidRoots = { new[] { HKLM, @"SOFTWARE\Classes\CLSID" }, new[] { HKLM, @"SOFTWARE\WOW6432Node\Classes\CLSID" }, new[] { HKCU, @"Software\Classes\CLSID" } };
        static readonly string[][] ClassRoots = { new[] { HKLM, @"SOFTWARE\Classes" }, new[] { HKCU, @"Software\Classes" } };

        void ScanUniverse()
        {
            foreach (var r in ClsidRoots)
                using (RegistryKey k = Open(r[0], r[1]))
                    if (k != null) foreach (string n in SubNames(k)) _clsids.Add(n);
            foreach (var r in ClassRoots)
                using (RegistryKey k = Open(r[0], r[1]))
                    if (k != null) foreach (string n in SubNames(k)) _classNames.Add(n);
        }

        void ScanAppx()
        {
            var roots = new[] {
                new[] { HKCU, @"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" },
                new[] { HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications" },
                new[] { HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications" },
            };
            foreach (var r in roots)
                using (RegistryKey k = Open(r[0], r[1]))
                {
                    if (k == null) continue;
                    foreach (string n in SubNames(k))
                    {
                        _probe.AppxInstalled.Add(n);
                        int u = n.IndexOf('_');
                        _corpus.AddStrong(u > 0 ? n.Substring(0, u) : n);
                    }
                }

            // Prove per le chiavi dei produttori: solo pacchetti installati per questo utente, secondo Windows.
            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string full in _probe.AppxInstalled) families.Add(Corpus.PackageFamily(full));
            foreach (string fam in families)
            {
                _ct.ThrowIfCancellationRequested();
                try
                {
                    foreach (string full in Corpus.InstalledFullNames(fam))
                        _liveNames.Add(new KeyValuePair<string, string>(Corpus.PackageName(full), "pacchetto " + full));
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception) { }
            }
        }

        readonly List<KeyValuePair<string, string>> _liveNames = new List<KeyValuePair<string, string>>();

        public int LiveNameCount { get { return _liveNames.Count; } }

        /// <summary>Pacchetto installato o servizio vivo il cui nucleo corrisponde al nome, o null.</summary>
        string FindLiveOwner(string name)
        {
            foreach (var kv in _liveNames)
                if (Corpus.CoreMatch(name, kv.Key)) return kv.Value;
            return null;
        }

        void ScanManifests()
        {
            var steamRoots = new List<string> { Path.Combine(_pf86, "Steam") };
            using (RegistryKey k = Open(HKCU, @"Software\Valve\Steam")) if (k != null) steamRoots.Add(Str(k, "SteamPath"));
            using (RegistryKey k = Open(HKLM, @"SOFTWARE\WOW6432Node\Valve\Steam")) if (k != null) steamRoots.Add(Str(k, "InstallPath"));
            using (RegistryKey k = Open(HKLM, @"SOFTWARE\Valve\Steam")) if (k != null) steamRoots.Add(Str(k, "InstallPath"));
            _corpus.LoadSteam(steamRoots);
            _corpus.LoadEpic(_programData);

            try
            {
                string inst = Path.Combine(_programData, @"Microsoft\VisualStudio\Packages\_Instances");
                if (Directory.Exists(inst))
                    foreach (string d in Directory.GetDirectories(inst))
                    {
                        _vsInstances.Add(Path.GetFileName(d));
                        try
                        {
                            Match m = Regex.Match(File.ReadAllText(Path.Combine(d, "state.json")), "\"installationVersion\"\\s*:\\s*\"(\\d+)\\.");
                            if (m.Success) _vsMajors.Add(int.Parse(m.Groups[1].Value));
                            else _vsReadErrors++;
                        }
                        catch (Exception) { _vsReadErrors++; }
                    }
            }
            catch (Exception) { _vsReadErrors++; }
        }

        void ScanDirs()
        {
            _corpus.LoadDirs(_pf, true);
            _ct.ThrowIfCancellationRequested();
            if (!string.Equals(_pf, _pf86, StringComparison.OrdinalIgnoreCase)) _corpus.LoadDirs(_pf86, true);
            _ct.ThrowIfCancellationRequested();
            foreach (string d in new[] { _programData, _local, _roaming, _localLow, Path.Combine(_local, "Programs"), Path.Combine(_pf, "Common Files"), Path.Combine(_pf86, "Common Files") })
            {
                _ct.ThrowIfCancellationRequested();
                _corpus.LoadDirs(d, false);
            }
            _ct.ThrowIfCancellationRequested();
            _corpus.LoadVolumeRoots();
        }

        // ------------------------------------------------------------ 1. disinstallazione

        static readonly Regex StubNames = new Regex("^(AddressBook|Connection Manager|DirectDrawEx|DXM_Runtime|Fontcore|IE40|IE4Data|IE5BAKEX|IEData|MobileOptionPack|MPlayer2|SchedulingAgent|WIC)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex SteamApp = new Regex(@"^Steam App (\d+)$", RegexOptions.Compiled);
        static readonly Regex KbName = new Regex(@"\.KB\d+$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        bool LocationHasExe(string loc)
        {
            try
            {
                if (File.Exists(loc)) return Regex.IsMatch(loc, @"\.(exe|dll)$", RegexOptions.IgnoreCase);
                return DirWithExe(loc);
            }
            catch (Exception) { return false; }
        }

        /// <summary>Una voce di disinstallazione prova un programma installato solo se è viva.</summary>
        public static bool UninstallAlive(PathStatus uninstaller, bool locationHasExe, bool iconExists, bool msiRegistered)
        {
            return uninstaller == PathStatus.Exists || locationHasExe || iconExists || msiRegistered;
        }

        /// <summary>Tabella di decisione per le voci visibili con UninstallString. null: nessuna riga.</summary>
        public static string UninstallGroupFor(PathStatus uninstaller, PathStatus location, bool programFilesFound, bool msiRegistered)
        {
            if (msiRegistered) return null;
            if (uninstaller == PathStatus.DriveAbsent) return "un-offline";
            if (uninstaller != PathStatus.Missing && uninstaller != PathStatus.MsiMissing) return null; // esiste, o non è verificabile
            if (programFilesFound) return "un-present";
            switch (location)
            {
                case PathStatus.Missing:
                case PathStatus.Empty:
                    return "un-orphan";
                case PathStatus.DriveAbsent:
                    return "un-offline";
                case PathStatus.Exists:
                    return "un-partial"; // resta una cartella senza eseguibili
            }
            return null; // cartella non verificabile
        }

        void ScanUninstall()
        {
            var roots = new[] { new[] { HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }, new[] { HKLM, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }, new[] { HKCU, @"Software\Microsoft\Windows\CurrentVersion\Uninstall" } };
            foreach (var r in roots)
            {
                string hive = r[0], rootPath = r[1];
                ForEachSub(hive, rootPath, (n, k) =>
                {
                    string dn = Str(k, "DisplayName"), us = Str(k, "UninstallString"), il = Str(k, "InstallLocation"), pub = Str(k, "Publisher"), di = Str(k, "DisplayIcon");
                    string path = rootPath + "\\" + n;
                    int vc = k.ValueCount, sc = k.SubKeyCount;
                    object sysComp = Val(k, "SystemComponent");
                    bool isSys = sysComp is int && (int)sysComp == 1;

                    ProbeResult u = us != null ? _probe.ProbeCommand(us) : new ProbeResult(PathStatus.Empty, "");
                    ProbeResult l = !string.IsNullOrWhiteSpace(il) ? _probe.ProbeFile(_probe.Normalize(il)) : new ProbeResult(PathStatus.Empty, "");
                    object wi = Val(k, "WindowsInstaller");
                    bool isMsi = wi is int && (int)wi == 1;
                    bool msiRegistered = isMsi && GuidOnly.IsMatch(n) && MsiProductExists(n);
                    bool locExe = l.Status == PathStatus.Exists && LocationHasExe(l.Target);
                    ProbeResult ic = !string.IsNullOrWhiteSpace(di) ? _probe.ProbeCommand(di) : new ProbeResult(PathStatus.Empty, "");
                    // Un'icona di sistema generica non dimostra nulla sul programma.
                    bool iconOk = ic.Status == PathStatus.Exists && (!UnderDir(ic.Target, _windir) || ic.Target.IndexOf(@"\Installer\", StringComparison.OrdinalIgnoreCase) >= 0);
                    bool iconExe = iconOk && Regex.IsMatch(ic.Target, @"\.(exe|dll)$", RegexOptions.IgnoreCase);

                    Match sa = SteamApp.Match(n);
                    bool steamGhost = sa.Success && !_corpus.SteamAppIds.Contains(sa.Groups[1].Value);
                    if (!string.IsNullOrEmpty(dn))
                    {
                        if (!steamGhost && UninstallAlive(u.Status, locExe, iconOk, msiRegistered)) { _corpus.AddStrong(dn); _corpus.AddStrong(pub); }
                        else _corpus.AddWeak(dn);
                    }

                    if (sa.Success)
                    {
                        if (_corpus.SteamAppIds.Contains(sa.Groups[1].Value)) return;
                        ProbeResult? pr = _corpus.SteamLibraryOffline ? new ProbeResult(PathStatus.DriveAbsent, "") : (ProbeResult?)null;
                        Add("un-steam", hive, path, null, ActionKind.DeleteKey, path, dn ?? n, u.Target, pr);
                        return;
                    }
                    if (StubNames.IsMatch(n)) { Add("un-stub", hive, path, null, ActionKind.DeleteKey, path, n, ""); return; }
                    if (KbName.IsMatch(n)) { Add("un-vc", hive, path, null, ActionKind.DeleteKey, path, n, ""); return; }
                    if (vc == 0 && sc == 0) { Add("un-stub", hive, path, null, ActionKind.DeleteKey, path, n, ""); return; }

                    if (us == null)
                    {
                        AddFp(hive, path, null, dn ?? n, "Senza stringa di disinstallazione: normale");
                        return;
                    }
                    if (MaybeFp(u, hive, path, null, u.Target)) return;
                    if (l.FpNote != null && l.Status == PathStatus.Exists) { AddFp(hive, path, null, dn ?? n, l.FpNote); }
                    if (!string.IsNullOrEmpty(dn) && !isSys)
                    {
                        string g = UninstallGroupFor(u.Status, l.Status, locExe || iconExe || ProgramPresent(u.Target), msiRegistered);
                        if (g != null)
                            Add(g, hive, path, null, ActionKind.DeleteKey, path, dn, u.Target, u.Status == PathStatus.DriveAbsent || g != "un-offline" ? u : l);
                        return;
                    }
                    if (!u.IsOrphan) return;

                    bool partial = l.Status == PathStatus.Exists || isSys || ProgramPresent(u.Target);
                    Add(partial ? "un-partial" : "un-dead", hive, path, null, ActionKind.DeleteKey, path, dn ?? n, u.Target, u);
                });
            }
        }

        // ------------------------------------------------------------ 2. avvio automatico

        readonly HashSet<string> _runNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void ScanAutoruns()
        {
            foreach (string hive in new[] { HKLM, HKCU })
                foreach (string b in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" })
                    foreach (string sub in new[] { "Run", "RunOnce", "RunOnceEx", "RunServices", "RunServicesOnce", @"Policies\Explorer\Run" })
                    {
                        string p = b + "\\" + sub;
                        using (RegistryKey k = Open(hive, p))
                        {
                            if (k == null) continue;
                            foreach (string v in ValNames(k))
                            {
                                if (string.IsNullOrEmpty(v)) continue;
                                _runNames.Add(v);
                                string d = Val(k, v) as string;
                                if (d == null) continue;
                                ProbeResult t = _probe.ProbeCommand(d);
                                if (MaybeFp(t, hive, p, v, d)) continue;
                                if (t.IsOrphan) Add("st-run", hive, p, v, ActionKind.DeleteValue, p, v, t.Target, t);
                            }
                        }
                    }

            var startupFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string d in new[] { Path.Combine(_roaming, @"Microsoft\Windows\Start Menu\Programs\Startup"), Path.Combine(_programData, @"Microsoft\Windows\Start Menu\Programs\Startup") })
            {
                try { foreach (string f in Directory.EnumerateFiles(d)) startupFiles.Add(Path.GetFileName(f)); } catch (Exception) { }
            }
            foreach (string hive in new[] { HKLM, HKCU })
                foreach (string sub in new[] { "Run", "Run32", "StartupFolder" })
                {
                    string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\" + sub;
                    using (RegistryKey k = Open(hive, p))
                    {
                        if (k == null) continue;
                        foreach (string v in ValNames(k))
                        {
                            if (string.IsNullOrEmpty(v)) continue;
                            bool present = sub == "StartupFolder" ? startupFiles.Contains(v) : _runNames.Contains(v);
                            if (present) continue;
                            byte[] b = Val(k, v) as byte[];
                            string en = (b != null && b.Length > 0 && b[0] % 2 == 0) ? "attivo" : "disattivo";
                            Add(_corpus.MatchStrong(v) ? "st-installed" : "st-orphan", hive, p, v, ActionKind.DeleteValue, p, v, "stato: " + en);
                        }
                    }
                }

            using (RegistryKey k = Open(HKLM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"))
                if (k != null)
                    foreach (string v in new[] { "Shell", "Userinit", "Taskman", "AppSetup" })
                    {
                        string d = Str(k, v);
                        if (string.IsNullOrEmpty(d)) continue;
                        ProbeResult t = _probe.ProbeCommand(d);
                        if (t.IsOrphan) Add("sh-winlogon", HKLM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", v, ActionKind.DeleteValue, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", v, t.Target, t);
                    }
            foreach (string p in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" })
                using (RegistryKey k = Open(HKLM, p))
                    if (k != null)
                    {
                        string d = Str(k, "AppInit_DLLs");
                        if (string.IsNullOrWhiteSpace(d)) continue;
                        ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                        if (t.IsOrphan) Add("sh-winlogon", HKLM, p, "AppInit_DLLs", ActionKind.DeleteValue, p, "AppInit_DLLs", t.Target, t);
                    }
            foreach (string hive in new[] { HKLM, HKCU })
                foreach (string p in new[] { @"SOFTWARE\Microsoft\Active Setup\Installed Components", @"SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" })
                    ForEachSub(hive, p, (n, k) =>
                    {
                        string d = Str(k, "StubPath");
                        if (string.IsNullOrEmpty(d)) return;
                        string path = p + "\\" + n;
                        string name = Str(k, "");
                        ProbeResult t = _probe.ProbeCommand(d);
                        if (t.FpNote != null) { AddFp(hive, path, "StubPath", string.IsNullOrEmpty(name) ? t.FpNote : name, t.FpNote); return; }
                        if (t.IsOrphan) Add("sh-activesetup", hive, path, "StubPath", ActionKind.DeleteValue, path, name ?? n, t.Target, t);
                    });
        }

        // ------------------------------------------------------------ 3. servizi

        void ScanServices()
        {
            const string root = @"SYSTEM\CurrentControlSet\Services";
            ForEachSub(HKLM, root, (n, k) =>
            {
                string img = Val(k, "ImagePath") as string;
                string path = root + "\\" + n;
                string disp = Str(k, "DisplayName");
                if (!string.IsNullOrEmpty(img))
                {
                    ProbeResult t = _probe.ProbeCommand(img);
                    if (t.Status == PathStatus.Exists)
                    {
                        _corpus.AddStrong(n);
                        _liveNames.Add(new KeyValuePair<string, string>(n, "servizio " + n));
                    }
                    if (t.FpNote != null) AddFp(HKLM, path, "ImagePath", t.FpNote, img);
                    else if (t.IsOrphan) Add("se-svc", HKLM, path, null, ActionKind.DeleteKey, path, disp != null && !disp.StartsWith("@") ? n + " (" + disp + ")" : n, t.Target, t);
                }
                using (RegistryKey par = OpenSub(k, "Parameters"))
                {
                    if (par == null) return;
                    string sd = Val(par, "ServiceDll") as string;
                    if (string.IsNullOrEmpty(sd)) return;
                    ProbeResult s = _probe.ProbeFile(_probe.Normalize(sd));
                    if (s.IsOrphan) Add("se-svc", HKLM, path + @"\Parameters", "ServiceDll", ActionKind.DeleteValue, path + @"\Parameters", n, s.Target, s);
                }
            });
        }

        void ScanMsi()
        {
            const string root = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
            using (RegistryKey r = Open(HKLM, root))
            {
                if (r == null) return;
                ForEachSub(r, (n, k) =>
                {
                    string path = root + "\\" + n;
                    using (RegistryKey ip = OpenSub(k, "InstallProperties"))
                    {
                        if (ip == null) { Add("ms-cached", HKLM, path, null, ActionKind.DeleteKey, path, n, "Manca InstallProperties"); return; }
                        string lp = Str(ip, "LocalPackage"), dn = Str(ip, "DisplayName"), il = Str(ip, "InstallLocation");
                        if (!string.IsNullOrEmpty(dn)) _corpus.AddStrong(dn);
                        if (!string.IsNullOrEmpty(lp))
                        {
                            ProbeResult t = _probe.ProbeFile(_probe.Normalize(lp));
                            if (t.IsOrphan) Add("ms-cached", HKLM, path, "LocalPackage", ActionKind.DeleteValue, path, dn ?? n, t.Target, t);
                        }
                        if (!string.IsNullOrEmpty(il))
                        {
                            ProbeResult t = _probe.ProbeFile(_probe.Normalize(il));
                            if (t.IsOrphan) Add("ms-cached", HKLM, path, "InstallLocation", ActionKind.DeleteValue, path, dn ?? n, t.Target, t);
                        }
                    }
                });
            }
        }

        // ------------------------------------------------------------ 4. COM

        string ComGroup(string target, PathStatus st)
        {
            string t = target ?? "";
            if (st == PathStatus.BareMissing) return "co-win";
            if (IsSystemPath(t)) return "co-win"; // mai eliminabile, prima di ogni suggerimento
            if (t.IndexOf(@"\EdgeUpdate\", StringComparison.OrdinalIgnoreCase) >= 0 || t.IndexOf(@"\Google\Update\", StringComparison.OrdinalIgnoreCase) >= 0) return "co-stale";
            if (t.IndexOf("devenv", StringComparison.OrdinalIgnoreCase) >= 0) return "co-vs";
            if (t.IndexOf(@"\AppData\Local\Packages\", StringComparison.OrdinalIgnoreCase) >= 0) return "co-pkg";
            if (t.IndexOf(@"\Microsoft", StringComparison.OrdinalIgnoreCase) >= 0 || t.IndexOf(@"\Windows ", StringComparison.OrdinalIgnoreCase) >= 0) return "co-ms";
            if (ProgramPresent(t)) return "co-stale";
            return "co-removed";
        }

        void ScanClsid()
        {
            foreach (var r in ClsidRoots)
            {
                string hive = r[0], root = r[1];
                ForEachSub(hive, root, (n, k) =>
                {
                    string clsidPath = root + "\\" + n;
                    int live = 0;
                    var dead = new List<KeyValuePair<string, ProbeResult>>();
                    foreach (string sv in new[] { "InprocServer32", "LocalServer32", "InprocHandler32" })
                    {
                        using (RegistryKey s = OpenSub(k, sv))
                        {
                            if (s == null) continue;
                            string d = Val(s, "") as string;
                            if (string.IsNullOrEmpty(d)) continue;
                            ProbeResult t = _probe.ProbeCommand(d);
                            if (t.IsOrphan) { dead.Add(new KeyValuePair<string, ProbeResult>(sv, t)); continue; }
                            live++;
                            MaybeFp(t, hive, clsidPath + "\\" + sv, null, t.Target == "" ? d : t.Target);
                        }
                    }
                    if (dead.Count == 0) return;
                    string name = Str(k, "");

                    string group = null; ProbeResult first = dead[0].Value; string firstSv = dead[0].Key;
                    foreach (var kv in dead)
                    {
                        string g = ComGroup(kv.Value.Target, kv.Value.Status);
                        if (group == null || (Groups.Get(g).Conf ?? 0) < (Groups.Get(group).Conf ?? 0)) { group = g; first = kv.Value; firstSv = kv.Key; }
                    }
                    if (live > 0) group = "co-partial";
                    string detail = string.Join(" ; ", dead.Select(x => x.Value.Target).Distinct());
                    Add(group, hive, clsidPath + "\\" + firstSv, null, ActionKind.DeleteKey, clsidPath, name, detail, first);
                });
            }
        }

        void ScanTypeLib()
        {
            foreach (var r in new[] { new[] { HKLM, @"SOFTWARE\Classes\TypeLib" }, new[] { HKLM, @"SOFTWARE\WOW6432Node\Classes\TypeLib" }, new[] { HKCU, @"Software\Classes\TypeLib" } })
            {
                string hive = r[0], root = r[1];
                ForEachSub(hive, root, (g, gk) =>
                {
                    ForEachSub(gk, (ver, vk) =>
                    {
                        string verPath = root + "\\" + g + "\\" + ver;
                        string name = Str(vk, "");
                        int live = 0;
                        var dead = new List<KeyValuePair<string, ProbeResult>>();
                        foreach (string lcid in SubNames(vk))
                        {
                            if (!Regex.IsMatch(lcid, @"^\d+$")) continue;
                            using (RegistryKey lk = OpenSub(vk, lcid))
                            {
                                if (lk == null) continue;
                                foreach (string plat in SubNames(lk))
                                {
                                    using (RegistryKey pk = OpenSub(lk, plat))
                                    {
                                        if (pk == null) continue;
                                        string d = Val(pk, "") as string;
                                        if (string.IsNullOrEmpty(d)) continue;
                                        ProbeResult t = _probe.ProbeTypeLib(d);
                                        string sub = verPath + "\\" + lcid + "\\" + plat;
                                        if (t.IsOrphan) { dead.Add(new KeyValuePair<string, ProbeResult>(sub, t)); continue; }
                                        live++;
                                        MaybeFp(t, hive, sub, null, t.Target);
                                    }
                                }
                            }
                        }
                        if (dead.Count == 0) return;
                        string group = null; ProbeResult first = dead[0].Value; string firstKey = dead[0].Key;
                        foreach (var kv in dead)
                        {
                            string gg = ComGroup(kv.Value.Target, kv.Value.Status);
                            if (group == null || (Groups.Get(gg).Conf ?? 0) < (Groups.Get(group).Conf ?? 0)) { group = gg; first = kv.Value; firstKey = kv.Key; }
                        }
                        if (live > 0) group = "co-partial";
                        Add(group, hive, firstKey, null, ActionKind.DeleteKey, verPath, name, string.Join(" ; ", dead.Select(x => x.Value.Target).Distinct()), first);
                    });
                });
            }
        }

        void ScanInterfaces()
        {
            foreach (string p in new[] { @"SOFTWARE\Classes\Interface", @"SOFTWARE\WOW6432Node\Classes\Interface" })
                ForEachSub(HKLM, p, (n, k) =>
                {
                    using (RegistryKey ps = OpenSub(k, "ProxyStubClsid32"))
                    {
                        if (ps == null) return;
                        string c = Val(ps, "") as string;
                        if (!string.IsNullOrEmpty(c) && !_clsids.Contains(c))
                            Add("pr-win", HKLM, p + "\\" + n, null, ActionKind.DeleteKey, p + "\\" + n, Str(k, ""), c);
                    }
                });
        }

        // ------------------------------------------------------------ 5. classi

        static readonly HashSet<string> ClassSkip = new HashSet<string>(new[] { "CLSID", "Interface", "TypeLib", "Installer", "AppID", "WOW6432Node", "Local Settings", "Record", "Licenses", "MIME", "Media Type", "PackagedCom", "ActivatableClasses", "Extensions" }, StringComparer.OrdinalIgnoreCase);
        static readonly Regex VsClass = new Regex(@"^VisualStudio\.[^.]+\.([0-9a-f]{8})$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        string ProgIdGroup(string n, ProbeResult t)
        {
            if (n.StartsWith("VisualStudio.", StringComparison.OrdinalIgnoreCase)) return "pr-vs";
            if (IsTransientPath(t.Target)) return "pr-sec";
            if (t.Status == PathStatus.BareMissing) return "pr-bare";
            if (UnderDir(t.Target, _windir)) return "pr-win";
            if (ProgramPresent(t.Target)) return "pr-stale";
            return "pr-removed";
        }

        void ScanShell(string hive, string classesRoot, string classPath, string n, RegistryKey k, bool isApplication)
        {
            using (RegistryKey sh = OpenSub(k, "shell"))
            {
                if (sh != null)
                {
                    int live = 0;
                    var dead = new List<KeyValuePair<string, ProbeResult>>();
                    foreach (string verb in SubNames(sh))
                    {
                        using (RegistryKey vk = OpenSub(sh, verb))
                        {
                            if (vk == null) continue;
                            using (RegistryKey c = OpenSub(vk, "command"))
                            {
                                if (c == null) continue;
                                string d = Val(c, "") as string;
                                if (string.IsNullOrEmpty(d)) continue;
                                string sub = classPath + @"\shell\" + verb + @"\command";
                                ProbeResult t = _probe.ProbeCommand(d);
                                if (t.IsOrphan) { dead.Add(new KeyValuePair<string, ProbeResult>(sub, t)); continue; }
                                live++;
                                MaybeFp(t, hive, sub, null, d);
                            }
                        }
                    }
                    if (dead.Count > 0)
                    {
                        var f = dead[0];
                        if (Hints.IsSystemClass(n) && !isApplication)
                            AddFp(hive, f.Key, null, PathProbe.NotePlaceholder, f.Value.Target);
                        else
                        {
                            string g = live > 0 ? "pr-partial" : ProgIdGroup(n, f.Value);
                            Add(g, hive, f.Key, null, ActionKind.DeleteKey, classPath, n, string.Join(" ; ", dead.Select(x => x.Value.Target).Distinct()), f.Value);
                        }
                    }
                }
            }
            using (RegistryKey sx = OpenSub(k, "shellex"))
            {
                if (sx == null) return;
                foreach (string hdl in SubNames(sx))
                {
                    using (RegistryKey hk = OpenSub(sx, hdl))
                    {
                        if (hk == null) continue;
                        CheckHandler(hive, classPath + @"\shellex\" + hdl, Val(hk, "") as string);
                        foreach (string sn in SubNames(hk))
                        {
                            string val = sn;
                            if (!sn.StartsWith("{", StringComparison.Ordinal))
                                using (RegistryKey sub = OpenSub(hk, sn)) val = sub == null ? null : Val(sub, "") as string;
                            CheckHandler(hive, classPath + @"\shellex\" + hdl + "\\" + sn, val);
                        }
                    }
                }
            }
        }

        static readonly Regex GuidOnly = new Regex(@"^\{[0-9A-Fa-f-]{36}\}$", RegexOptions.Compiled);

        void CheckHandler(string hive, string path, string val)
        {
            if (val == null || !GuidOnly.IsMatch(val) || _clsids.Contains(val)) return;
            Add("sh-win", hive, path, null, ActionKind.DeleteKey, path, "", val);
        }

        void ScanClasses()
        {
            foreach (var r in ClassRoots)
            {
                string hive = r[0], root = r[1];
                ForEachSub(hive, root, (n, k) =>
                {
                    if (ClassSkip.Contains(n)) return;
                    string classPath = root + "\\" + n;
                    if (n.Equals("Applications", StringComparison.OrdinalIgnoreCase))
                    {
                        ForEachSub(k, (a, ak) => ScanShell(hive, root, classPath + "\\" + a, a, ak, true));
                        return;
                    }
                    if (n.StartsWith(".", StringComparison.Ordinal))
                    {
                        string d = Val(k, "") as string;
                        bool sharedLive = false;
                        using (RegistryKey ow = OpenSub(k, "OpenWithProgids"))
                        {
                            if (ow != null)
                                foreach (string v in ValNames(ow))
                                {
                                    if (string.IsNullOrEmpty(v)) continue;
                                    if (_classNames.Contains(v) || v.StartsWith("AppX", StringComparison.OrdinalIgnoreCase)) sharedLive = true;
                                    else Add(v.IndexOf("VisualStudio", StringComparison.OrdinalIgnoreCase) >= 0 ? "pr-vs" : "pr-ext-win", hive, classPath + @"\OpenWithProgids", v, ActionKind.DeleteValue, classPath + @"\OpenWithProgids", v, "");
                                }
                        }
                        if (!string.IsNullOrEmpty(d) && !_classNames.Contains(d))
                            Add(ExtGroup(n, d, sharedLive), hive, classPath, null, ActionKind.DeleteKey, classPath, n, d);
                    }
                    ScanShell(hive, root, classPath, n, k, false);
                    using (RegistryKey cl = OpenSub(k, "CLSID"))
                    {
                        if (cl == null) return;
                        string c = Val(cl, "") as string;
                        if (!string.IsNullOrEmpty(c) && !_clsids.Contains(c))
                            Add(n.IndexOf("VisualStudio", StringComparison.OrdinalIgnoreCase) >= 0 ? "pr-vs" : "pr-win", hive, classPath + @"\CLSID", null, ActionKind.DeleteKey, classPath + @"\CLSID", n, c);
                    }
                });
            }
        }

        string ExtGroup(string ext, string progId, bool sharedLive)
        {
            if (Hints.IsSystemClass(ext) || Hints.IsSystemClass(progId) || progId.StartsWith(@"CLSID\", StringComparison.OrdinalIgnoreCase) || progId.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase))
                return "pr-ext-win";
            if (sharedLive) return "pr-ext-shared";
            Match vs = VsClass.Match(progId);
            if (vs.Success) return _vsInstances.Contains(vs.Groups[1].Value) ? "pr-vs" : "pr-ext-vs";
            string head = progId.Split(new[] { '.', ' ', '_' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? progId;
            if (_corpus.MatchStrong(head)) return "pr-ext-win";
            return "pr-ext-unknown";
        }

        // ------------------------------------------------------------ 6. percorsi vari

        void ScanMiscPaths()
        {
            foreach (var r in new[] { new[] { HKLM, @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" }, new[] { HKLM, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths" }, new[] { HKCU, @"Software\Microsoft\Windows\CurrentVersion\App Paths" } })
            {
                string hive = r[0], root = r[1];
                ForEachSub(hive, root, (n, k) =>
                {
                    string d = Val(k, "") as string;
                    if (string.IsNullOrEmpty(d)) return;
                    string path = root + "\\" + n;
                    ProbeResult t = _probe.ProbeCommand(d);
                    if (MaybeFp(t, hive, path, null, d)) return;
                    if (t.IsOrphan) Add("sh-apppaths", hive, path, null, ActionKind.DeleteKey, path, n, t.Target, t);
                });
            }
            foreach (string p in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs" })
                using (RegistryKey k = Open(HKLM, p))
                {
                    if (k == null) continue;
                    foreach (string v in ValNames(k))
                    {
                        _ct.ThrowIfCancellationRequested();
                        if (string.IsNullOrEmpty(v)) continue;
                        ProbeResult t = _probe.ProbeFile(_probe.Normalize(v));
                        if (t.IsOrphan) Add("ms-shared", HKLM, p, v, ActionKind.DeleteValue, p, Path.GetFileName(v), t.Target, t);
                    }
                }
            const string fold = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";
            using (RegistryKey k = Open(HKLM, fold))
            {
                if (k == null) return;
                foreach (string v in ValNames(k))
                {
                    _ct.ThrowIfCancellationRequested();
                    if (string.IsNullOrEmpty(v)) continue;
                    ProbeResult t = _probe.ProbeFile(_probe.Normalize(v.TrimEnd('\\')));
                    if (t.FpNote != null) { AddFp(HKLM, fold, v, t.FpNote, v); continue; }
                    if (!t.IsOrphan) continue;
                    string g;
                    if (IsSystemPath(t.Target)) g = "ms-win";
                    else if (ProgramPresent(v.TrimEnd('\\') + @"\x")) g = "ms-present";
                    else g = "ms-other";
                    var tt = t; tt.Target = v; // ProbePath: la cartella, com'è scritta
                    Add(g, HKLM, fold, v, ActionKind.DeleteValue, fold, "", v, tt);
                }
            }
        }

        void ScanFontsOdbc()
        {
            foreach (var r in new[] { new[] { HKLM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" }, new[] { HKCU, @"Software\Microsoft\Windows NT\CurrentVersion\Fonts" } })
                using (RegistryKey k = Open(r[0], r[1]))
                {
                    if (k == null) continue;
                    foreach (string v in ValNames(k))
                    {
                        string d = Val(k, v) as string;
                        if (string.IsNullOrEmpty(d)) continue;
                        ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                        if (t.IsOrphan) Add("sh-win", r[0], r[1], v, ActionKind.DeleteValue, r[1], v, d, t);
                    }
                }
            foreach (string p in new[] { @"SOFTWARE\ODBC\ODBCINST.INI", @"SOFTWARE\WOW6432Node\ODBC\ODBCINST.INI" })
                ForEachSub(HKLM, p, (n, k) =>
                {
                    string d = Str(k, "Driver");
                    if (string.IsNullOrEmpty(d)) return;
                    ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                    if (t.IsOrphan) Add("sh-odbc", HKLM, p + "\\" + n, "Driver", ActionKind.DeleteValue, p + "\\" + n, n, d, t);
                });
            foreach (string h in new[] { HKLM, HKCU })
            {
                string p = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls";
                using (RegistryKey k = Open(h, p))
                {
                    if (k != null)
                        foreach (string v in ValNames(k))
                        {
                            string d = Val(k, v) as string;
                            if (string.IsNullOrEmpty(d)) continue;
                            ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                            if (t.IsOrphan) Add("sh-cpl", h, p, v, ActionKind.DeleteValue, p, v, d, t);
                        }
                }
                foreach (string q in new[] { @"SOFTWARE\Google\Chrome\NativeMessagingHosts", @"SOFTWARE\WOW6432Node\Google\Chrome\NativeMessagingHosts", @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts", @"SOFTWARE\WOW6432Node\Microsoft\Edge\NativeMessagingHosts", @"SOFTWARE\Mozilla\NativeMessagingHosts", @"SOFTWARE\BraveSoftware\Brave-Browser\NativeMessagingHosts" })
                    ForEachSub(h, q, (n, k) =>
                    {
                        string d = Val(k, "") as string;
                        if (string.IsNullOrEmpty(d)) return;
                        ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                        if (t.IsOrphan) Add("sh-native", h, q + "\\" + n, null, ActionKind.DeleteKey, q + "\\" + n, n, d, t);
                    });
            }
        }

        void ScanShellRegs()
        {
            foreach (string h in new[] { HKLM, HKCU })
                foreach (string b in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion" })
                {
                    string ov = b + @"\Explorer\ShellIconOverlayIdentifiers";
                    ForEachSub(h, ov, (n, k) =>
                    {
                        string c = Val(k, "") as string;
                        if (!string.IsNullOrEmpty(c) && !_clsids.Contains(c))
                            Add("sh-overlay", h, ov + "\\" + n, null, ActionKind.DeleteKey, ov + "\\" + n, n.Trim(), c);
                    });
                    string bho = b + @"\Explorer\Browser Helper Objects";
                    using (RegistryKey k = Open(h, bho))
                        if (k != null)
                            foreach (string n in SubNames(k))
                                if (!_clsids.Contains(n)) Add("sh-bho", h, bho + "\\" + n, null, ActionKind.DeleteKey, bho + "\\" + n, n, n);
                    string ap = b + @"\Shell Extensions\Approved";
                    using (RegistryKey k = Open(h, ap))
                        if (k != null)
                            foreach (string v in ValNames(k))
                                if (v.StartsWith("{", StringComparison.Ordinal) && !_clsids.Contains(v))
                                    Add("sh-win", h, ap, v, ActionKind.DeleteValue, ap, Val(k, v) as string, v);
                }
        }

        static readonly Regex FwApp = new Regex(@"\|App=([^|]+)\|", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex FwName = new Regex(@"\|Name=([^|]*)\|", RegexOptions.Compiled);

        void ScanFirewall()
        {
            const string p = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
            using (RegistryKey k = Open(HKLM, p))
            {
                if (k == null) return;
                foreach (string v in ValNames(k))
                {
                    _ct.ThrowIfCancellationRequested();
                    string d = Val(k, v) as string;
                    if (d == null) continue;
                    Match m = FwApp.Match(d);
                    if (!m.Success) continue;
                    string app = _probe.Normalize(m.Groups[1].Value);
                    if (app.Equals("System", StringComparison.OrdinalIgnoreCase)) continue;
                    ProbeResult t = _probe.ProbeFile(app);
                    if (t.FpNote != null) { Match n0 = FwName.Match(d); AddFp(HKLM, p, v, n0.Success ? n0.Groups[1].Value : t.FpNote, app); continue; }
                    if (!t.IsOrphan) continue;
                    Match n = FwName.Match(d);
                    string name = n.Success ? n.Groups[1].Value : "";
                    string g;
                    if (t.Target.IndexOf("EdgeWebView", StringComparison.OrdinalIgnoreCase) >= 0) g = "fw-webview";
                    else if (t.Target.IndexOf(@"steam\bin\cef", StringComparison.OrdinalIgnoreCase) >= 0) g = "fw-steam";
                    else if (UnderDir(t.Target, _windir)) g = "fw-win";
                    else if (IsUserPath(t.Target)) g = "fw-user";
                    else if (ProgramPresent(t.Target)) g = "fw-stale";
                    else g = "fw-apps";
                    Add(g, HKLM, p, v, ActionKind.DeleteValue, p, name, app, t);
                }
            }
        }

        static readonly Regex MuiRx = new Regex(@"^([A-Za-z]:\\.+?)\.(FriendlyAppName|ApplicationCompany)$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        void ScanTraces()
        {
            foreach (var r in new[] { new[] { HKCU, @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" }, new[] { HKLM, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" }, new[] { HKCU, @"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" } })
                using (RegistryKey k = Open(r[0], r[1]))
                {
                    if (k == null) continue;
                    foreach (string v in ValNames(k))
                    {
                        _ct.ThrowIfCancellationRequested();
                        if (v.Length < 3 || v[1] != ':' || !char.IsLetter(v[0])) continue;
                        ProbeResult t = _probe.ProbeFile(v);
                        if (t.IsOrphan) Add("tr-appcompat", r[0], r[1], v, ActionKind.DeleteValue, r[1], SafeName(v), v, t);
                    }
                }
            const string mui = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
            using (RegistryKey k = Open(HKCU, mui))
            {
                if (k == null) return;
                foreach (string v in ValNames(k))
                {
                    _ct.ThrowIfCancellationRequested();
                    Match m = MuiRx.Match(v);
                    if (!m.Success) continue;
                    ProbeResult t = _probe.ProbeFile(m.Groups[1].Value);
                    if (t.IsOrphan) Add("tr-mui", HKCU, mui, v, ActionKind.DeleteValue, mui, SafeName(m.Groups[1].Value), m.Groups[1].Value, t);
                }
            }
        }

        static string SafeName(string p)
        {
            int i = p.LastIndexOf('\\');
            return i >= 0 ? p.Substring(i + 1) : p;
        }

        void ScanEnvEtc()
        {
            foreach (var r in new[] { new[] { HKLM, @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment" }, new[] { HKCU, @"Environment" } })
                using (RegistryKey k = Open(r[0], r[1]))
                {
                    if (k == null) continue;
                    foreach (string v in ValNames(k))
                    {
                        string d = Val(k, v) as string;
                        if (d == null) continue;
                        if (v.Equals("Path", StringComparison.OrdinalIgnoreCase) || v.Equals("PSModulePath", StringComparison.OrdinalIgnoreCase))
                        {
                            foreach (string e in d.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                if (e.Trim().Length == 0) continue;
                                ProbeResult t = _probe.ProbeFile(_probe.Normalize(e));
                                if (t.IsOrphan) Add("sh-env", r[0], r[1], v, ActionKind.DeleteValue, r[1], v, e, t);
                            }
                        }
                        else if (Regex.IsMatch(d, @"^[A-Za-z]:\\[^;]*$"))
                        {
                            ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                            if (t.IsOrphan) Add("sh-env", r[0], r[1], v, ActionKind.DeleteValue, r[1], v, d, t);
                        }
                    }
                }

            const string prof = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
            ForEachSub(HKLM, prof, (n, k) =>
            {
                string d = Val(k, "ProfileImagePath") as string;
                if (string.IsNullOrEmpty(d)) return;
                ProbeResult t = _probe.ProbeFile(_probe.Normalize(d));
                if (t.FpNote != null) { AddFp(HKLM, prof + "\\" + n, "ProfileImagePath", "Profilo protetto: " + t.FpNote, d); return; }
                if (t.IsOrphan) Add("sh-profile", HKLM, prof + "\\" + n, null, ActionKind.DeleteKey, prof + "\\" + n, n, d, t);
            });

            foreach (string p in new[] { @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" })
                ForEachSub(HKLM, p, (n, k) =>
                {
                    string d = Val(k, "Debugger") as string;
                    if (string.IsNullOrEmpty(d)) return;
                    ProbeResult t = _probe.ProbeCommand(d);
                    if (t.IsOrphan) Add("sh-winlogon", HKLM, p + "\\" + n, "Debugger", ActionKind.DeleteValue, p + "\\" + n, n, t.Target, t);
                });

            foreach (var r in new[] { new[] { HKLM, @"SOFTWARE\RegisteredApplications" }, new[] { HKCU, @"Software\RegisteredApplications" } })
                using (RegistryKey k = Open(r[0], r[1]))
                {
                    if (k == null) continue;
                    foreach (string v in ValNames(k))
                    {
                        string d = Val(k, v) as string;
                        if (string.IsNullOrEmpty(d) || string.IsNullOrEmpty(v)) continue;
                        if (KeyExists(r[0], d) || KeyExists(HKLM, d)) continue;
                        string g;
                        if (v.IndexOf("VisualStudio", StringComparison.OrdinalIgnoreCase) >= 0) g = "pr-vs";
                        else if (v.StartsWith("AppX", StringComparison.Ordinal)) g = "tr-regappx";
                        else g = "tr-regapp";
                        string det = d;
                        int pk = d.IndexOf(@"Packages\", StringComparison.OrdinalIgnoreCase);
                        if (g == "tr-regappx" && pk >= 0) det = d.Substring(pk + 9);
                        Add(g, r[0], r[1], v, ActionKind.DeleteValue, r[1], v, det);
                    }
                }
        }

        // ------------------------------------------------------------ operazioni pianificate (sola lettura, COM)

        void ScanTasks()
        {
            Type t = Type.GetTypeFromProgID("Schedule.Service");
            if (t == null) return;
            dynamic svc = Activator.CreateInstance(t);
            svc.Connect();
            WalkTasks(svc.GetFolder("\\"));
        }

        void WalkTasks(dynamic folder)
        {
            _ct.ThrowIfCancellationRequested();
            try
            {
                foreach (dynamic task in folder.GetTasks(1))
                {
                    _ct.ThrowIfCancellationRequested();
                    try
                    {
                        string taskPath = task.Path;
                        foreach (dynamic a in task.Definition.Actions)
                        {
                            if ((int)a.Type != 0) continue;
                            string exe = a.Path;
                            if (string.IsNullOrEmpty(exe)) continue;
                            ProbeResult c = _probe.ProbeCommand(exe);
                            if (c.IsOrphan) Add("sh-task", "", taskPath, null, ActionKind.DeleteKey, "", SafeName(taskPath), c.Target, c);
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception) { _denied++; }
                }
                foreach (dynamic sub in folder.GetFolders(0)) WalkTasks(sub);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { _denied++; }
        }

        // ------------------------------------------------------------ produttori

        sealed class Walk
        {
            public int Items, Live, DataOk, Missing, Offline, Budget = 40000;
            public string FirstMissing, FirstOffline, NameHit;
            public bool HasNative;
        }

        static readonly Regex DrivePath = new Regex(@"^""?[A-Za-z]:[\\/]", RegexOptions.Compiled);
        static readonly Regex ExePart = new Regex(@"^(.+?\.(?:exe|dll|ini|cfg|sys))(\s|,|""|$)", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        void WalkKey(RegistryKey k, Walk w, int depth)
        {
            _ct.ThrowIfCancellationRequested();
            if (w.Budget <= 0 || depth > 12) return;
            foreach (string vn in ValNames(k))
            {
                w.Items++;
                if (--w.Budget <= 0) return;
                string x = Val(k, vn) as string;
                if (x != null && w.NameHit == null && (vn.Equals("DisplayName", StringComparison.OrdinalIgnoreCase) || vn.Equals("ProductName", StringComparison.OrdinalIgnoreCase)) && _corpus.MatchProduct(x))
                    w.NameHit = x;
                if (x == null || !DrivePath.IsMatch(x)) continue;
                string p = x.Trim().Trim('"').Replace('/', '\\');
                Match m = ExePart.Match(p);
                if (m.Success) p = m.Groups[1].Value;
                p = Regex.Replace(p, "\"\\s.*$", "");
                ProbeResult r = _probe.ProbeFile(p);
                switch (r.Status)
                {
                    case PathStatus.Exists:
                        if (IsLivePath(r.Target)) w.Live++; else w.DataOk++;
                        break;
                    case PathStatus.Missing:
                        w.Missing++;
                        if (w.FirstMissing == null) w.FirstMissing = r.Target;
                        break;
                    case PathStatus.DriveAbsent:
                    case PathStatus.Network:
                        w.Offline++;
                        if (w.FirstOffline == null) w.FirstOffline = r.Target;
                        break;
                }
            }
            foreach (string s in SubNames(k))
            {
                w.Items++;
                if (--w.Budget <= 0) return;
                if (s.Equals("NativeMessagingHosts", StringComparison.OrdinalIgnoreCase)) w.HasNative = true;
                using (RegistryKey c = OpenSub(k, s)) if (c != null) WalkKey(c, w, depth + 1);
            }
        }

        /// <summary>Percorso che dimostra un programma vivo: eseguibile o cartella con eseguibili, fuori da Windows e cartelle utente.</summary>
        bool IsLivePath(string p)
        {
            if (UnderDir(p, _windir) || IsTransientPath(p)) return false;
            if (p.Length <= 3) return false;
            if (Regex.IsMatch(p, @"\\(Documents|Documenti|Pictures|Videos|Music)(\\|$)", RegexOptions.IgnoreCase)) return false;
            if (string.Equals(p, _profile, StringComparison.OrdinalIgnoreCase)) return false;
            if (SteamCommon.IsMatch(p) && !ProgramPresent(p)) return false;
            string ext = Path.GetExtension(p);
            if (ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) || ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return true;
            return DirWithExe(p);
        }

        static readonly Regex GuidName = new Regex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.Compiled);

        void ScanVendors()
        {
            foreach (var r in new[] { new[] { HKCU, "Software" }, new[] { HKLM, "SOFTWARE" }, new[] { HKLM, @"SOFTWARE\WOW6432Node" } })
            {
                string hive = r[0], root = r[1];
                ForEachSub(hive, root, (n, k) => ClassifyVendor(hive, root, n, k));
            }
            ScanVsUserKeys();
        }

        /// <summary>Gruppo di una chiave senza programma vivo. Decidono solo le prove raccolte a runtime.</summary>
        public static string VendorGroupFor(string n, bool weakMatch, int dataPaths)
        {
            if (weakMatch || dataPaths > 0 || GuidName.IsMatch(n)) return "ve-unsure";
            return "ve-unknown";
        }

        void ClassifyVendor(string hive, string root, string n, RegistryKey k)
        {
            if (n.Equals(DeleteGuard.SandboxName, StringComparison.OrdinalIgnoreCase)) return;
            string path = root + "\\" + n;
            string[] subs = SubNames(k);
            string sub12 = string.Join(",", subs.Take(12));
            sub12 = Regex.Replace(sub12, @"[A-Za-z0-9_-]{32,}", m => m.Value.Substring(0, 8) + "…"); // nomi simili a token: non mostrarli per intero
            string detail = sub12.Length > 0 ? "contiene: " + sub12 : "";

            if (Hints.SystemKeys.Contains(n))
            {
                Add("ve-keep", hive, path, null, ActionKind.DeleteKey, path, "", detail);
                return;
            }

            var w = new Walk();
            WalkKey(k, w, 0);
            string label = w.Items + " elementi";
            string extra = null;
            if (w.Missing > 0) extra = "Percorsi mancanti nella chiave: " + w.Missing + " (es. " + w.FirstMissing + ").";

            ProbeResult? offline = w.Offline > 0 ? new ProbeResult(PathStatus.DriveAbsent, w.FirstOffline) : (ProbeResult?)null;
            ProbeResult? pr = offline ?? (w.FirstMissing != null ? new ProbeResult(PathStatus.Missing, w.FirstMissing) : (ProbeResult?)null);

            string owner = FindLiveOwner(n);
            if (owner != null)
            {
                Add("ve-keep", hive, path, null, ActionKind.DeleteKey, path, label, detail, null, "Il nome corrisponde a un elemento installato: " + owner + ".");
                return;
            }

            string hit, why = null;
            if (_corpus.MatchStrong(n, out hit)) why = "Corrisponde a un programma rilevato: " + hit + ".";
            else
                foreach (string s in subs)
                    if (_corpus.MatchStrongExact(s)) { why = "La sottochiave " + s + " corrisponde a un programma rilevato."; break; }
            if (why == null && w.NameHit != null) why = "Contiene il nome di un programma rilevato: " + w.NameHit + ".";
            if (why == null && w.Live > 0) why = "Contiene percorsi di programmi esistenti (" + w.Live + ").";
            if (why == null && _corpus.MatchVendorEvidence(n)) why = "Il nome richiama un programma rilevato.";

            if (why != null)
            {
                Add("ve-keep", hive, path, null, ActionKind.DeleteKey, path, label, detail, null, why);
                return;
            }

            string group = VendorGroupFor(n, _corpus.MatchWeak(n), w.DataOk);
            if (w.Budget <= 0)
            {
                group = "ve-unsure";
                extra = (extra == null ? "" : extra + " ") + "Chiave troppo grande: verificata solo in parte.";
            }

            if (w.HasNative)
            {
                OfferExcludingNative(hive, path, k, group, extra, pr);
                return;
            }
            Add(group, hive, path, null, ActionKind.DeleteKey, path, label, detail, pr, extra);
        }

        void OfferExcludingNative(string hive, string path, RegistryKey k, string group, string extra, ProbeResult? pr)
        {
            foreach (string s in SubNames(k))
            {
                if (s.Equals("NativeMessagingHosts", StringComparison.OrdinalIgnoreCase)) continue;
                using (RegistryKey c = OpenSub(k, s))
                {
                    if (c == null) continue;
                    var w = new Walk();
                    WalkKey(c, w, 0);
                    string p = path + "\\" + s;
                    if (w.HasNative) { OfferExcludingNative(hive, p, c, group, extra, pr); continue; }
                    int capped = Groups.Get(group).Conf ?? 0;
                    Add(capped >= 80 ? "ve-subkey" : group, hive, p, null, ActionKind.DeleteKey, p, s, "sottochiave: la chiave contiene NativeMessagingHosts", pr, extra);
                }
            }
        }

        static readonly Regex VsKey = new Regex(@"^(\d+)\.\d+(?:_([0-9a-f]{8}))?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        void ScanVsUserKeys()
        {
            const string p = @"Software\Microsoft\VisualStudio";
            using (RegistryKey k = Open(HKCU, p))
            {
                if (k == null) return;
                foreach (string n in SubNames(k))
                {
                    Match m = VsKey.Match(n);
                    if (!m.Success) continue;
                    int major = int.Parse(m.Groups[1].Value);
                    if (major < 15) continue;
                    bool inUse = m.Groups[2].Success ? _vsInstances.Contains(m.Groups[2].Value) : _vsMajors.Contains(major);
                    if (!inUse) Add("ve-vs", HKCU, p + "\\" + n, null, ActionKind.DeleteKey, p + "\\" + n, n, "");
                }
            }
        }
    }
}
