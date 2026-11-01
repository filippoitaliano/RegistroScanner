using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace RegistroScanner
{
    /// <summary>
    /// Corpus dei programmi installati, costruito a runtime.
    /// Forte: disinstallazione valida, MSI, servizi con immagine viva, pacchetti Appx, manifest Steam/Epic, cartelle con eseguibili.
    /// Debole: cartelle senza eseguibili (dati residui).
    /// </summary>
    public sealed class Corpus
    {
        readonly HashSet<string> _strong = new HashSet<string>(StringComparer.Ordinal);
        readonly HashSet<string> _strongWord = new HashSet<string>(StringComparer.Ordinal);
        readonly HashSet<string> _weak = new HashSet<string>(StringComparer.Ordinal);
        string _strongBlob, _weakBlob;
        readonly Dictionary<string, bool> _exeCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);

        public readonly HashSet<string> SteamAppIds = new HashSet<string>(StringComparer.Ordinal);
        public readonly HashSet<string> SteamInstallDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public bool SteamLibraryOffline;
        public int SteamReadErrors;

        static readonly HashSet<string> Stop = new HashSet<string>(new[] {
            "microsoft", "windows", "program", "programs", "software", "common", "commonfiles", "games", "game", "local", "system", "update", "updates",
            "tools", "tool", "service", "services", "driver", "drivers", "users", "files", "data", "settings", "config", "temp", "cache", "logs", "default",
            "shared", "support", "corporation", "company", "application", "applications", "packages", "client", "server", "the", "app", "runtime", "setup", "installer", "install", "uninstall",
            "launcher", "updater", "diagnostics", "telemetry", "interface", "schedule", "manager", "plugin", "plugins", "helper", "agent", "browser", "network", "security", "display", "audio", "video", "storage", "device"
        }, StringComparer.Ordinal);

        static readonly HashSet<string> CoreGeneric = new HashSet<string>(new[] { "store", "service", "services", "app", "desktop", "x64" }, StringComparer.Ordinal);

        /// <summary>Nucleo di un nome: minuscolo, alfanumerico, senza parole generiche né prefissi microsoft/ms iniziali.</summary>
        public static string Core(string s)
        {
            if (s == null) return "";
            var words = new List<string>();
            var cur = new StringBuilder();
            foreach (char c in s + " ")
            {
                char l = char.ToLowerInvariant(c);
                if ((l >= 'a' && l <= 'z') || (l >= '0' && l <= '9')) { cur.Append(l); continue; }
                if (cur.Length > 0) { if (!CoreGeneric.Contains(cur.ToString())) words.Add(cur.ToString()); cur.Clear(); }
            }
            string z = string.Concat(words);
            while (true)
            {
                if (z.StartsWith("microsoft", StringComparison.Ordinal)) z = z.Substring(9);
                else if (z.StartsWith("ms", StringComparison.Ordinal)) z = z.Substring(2);
                else return z;
            }
        }

        /// <summary>Un nucleo contiene l'altro e il più corto ha almeno 6 caratteri.</summary>
        public static bool CoreMatch(string a, string b)
        {
            string x = Core(a), y = Core(b);
            if (Math.Min(x.Length, y.Length) < 6) return false;
            return x.IndexOf(y, StringComparison.Ordinal) >= 0 || y.IndexOf(x, StringComparison.Ordinal) >= 0;
        }

        /// <summary>Name_Versione_Arch_Risorsa_Editore -> Name.</summary>
        public static string PackageName(string fullName)
        {
            int u = (fullName ?? "").IndexOf('_');
            return u > 0 ? fullName.Substring(0, u) : fullName ?? "";
        }

        /// <summary>Name_Versione_Arch_Risorsa_Editore -> Name_Editore.</summary>
        public static string PackageFamily(string fullName)
        {
            string[] p = (fullName ?? "").Split('_');
            return p.Length >= 2 ? p[0] + "_" + p[p.Length - 1] : fullName ?? "";
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern int GetPackagesByPackageFamily(string family, ref uint count, IntPtr names, ref uint bufferLength, IntPtr buffer);

        /// <summary>Pacchetti della famiglia installati per l'utente corrente, secondo Windows (non il semplice repository).</summary>
        public static List<string> InstalledFullNames(string family)
        {
            var result = new List<string>();
            uint count = 0, len = 0;
            int rc = GetPackagesByPackageFamily(family, ref count, IntPtr.Zero, ref len, IntPtr.Zero);
            if (rc != 122 /*ERROR_INSUFFICIENT_BUFFER*/ || count == 0) return result;
            IntPtr names = IntPtr.Zero, buf = IntPtr.Zero;
            try
            {
                names = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)count * IntPtr.Size);
                buf = System.Runtime.InteropServices.Marshal.AllocHGlobal((int)len * 2);
                rc = GetPackagesByPackageFamily(family, ref count, names, ref len, buf);
                if (rc != 0) return result;
                for (int i = 0; i < count; i++)
                    result.Add(System.Runtime.InteropServices.Marshal.PtrToStringUni(System.Runtime.InteropServices.Marshal.ReadIntPtr(names, i * IntPtr.Size)));
            }
            finally
            {
                if (names != IntPtr.Zero) System.Runtime.InteropServices.Marshal.FreeHGlobal(names);
                if (buf != IntPtr.Zero) System.Runtime.InteropServices.Marshal.FreeHGlobal(buf);
            }
            return result;
        }

        public static string Nz(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                char l = char.ToLowerInvariant(c);
                if ((l >= 'a' && l <= 'z') || (l >= '0' && l <= '9')) sb.Append(l);
            }
            return sb.ToString();
        }

        public void AddStrong(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            string z = Nz(name);
            if (z.Length >= 3) _strong.Add(z);
            string[] words = name.Split(new[] { ' ', '.', '-', '_', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length > 0)
            {
                string w = Nz(words[0]);
                if (w.Length >= 3 && !Stop.Contains(w)) _strongWord.Add(w);
                if (words[0].Length == 2 && IsUpperWord(words[0])) _strongShort.Add(words[0]);
            }
        }

        readonly HashSet<string> _strongShort = new HashSet<string>(StringComparer.Ordinal);

        static bool IsUpperWord(string w) { return w == w.ToUpperInvariant() && w != w.ToLowerInvariant(); }

        /// <summary>
        /// Prova prudente per le chiavi di produttore: la prima parola in maiuscolo è un programma rilevato ("AB Sports" -> cartella "AB"),
        /// oppure il nome inizia con un programma rilevato ("ContosoShared" -> "Contoso"). Può tenere una chiave in più, mai eliminarne di più.
        /// </summary>
        public bool MatchVendorEvidence(string name)
        {
            string[] words = (name ?? "").Split(new[] { ' ', '.', '-', '_', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0) return false;
            if (IsUpperWord(words[0]))
            {
                if (words[0].Length == 2) { if (_strongShort.Contains(words[0])) return true; }
                else
                {
                    string first = Nz(words[0]);
                    if (first.Length >= 3 && !Stop.Contains(first) && (_strong.Contains(first) || _strongWord.Contains(first))) return true;
                }
            }
            string z = Nz(name);
            foreach (HashSet<string> set in new[] { _strong, _strongWord })
                foreach (string t in set)
                    if (t.Length >= 4 && !Stop.Contains(t) && z.StartsWith(t, StringComparison.Ordinal)) return true;
            return false;
        }

        public void AddWeak(string name)
        {
            string z = Nz(name);
            if (z.Length >= 3) _weak.Add(z);
        }

        public void Seal()
        {
            _strongBlob = "|" + string.Join("|", _strong) + "|";
            _weakBlob = "|" + string.Join("|", _weak) + "|";
        }

        public bool MatchStrong(string name) { string h; return Match(name, _strong, _strongBlob, _strongWord, out h); }
        public bool MatchStrong(string name, out string hit) { return Match(name, _strong, _strongBlob, _strongWord, out hit); }
        /// <summary>Nome di prodotto in una chiave: intero, oppure la prima parola esatta ("Contoso Racing" -> cartella "Contoso").</summary>
        public bool MatchProduct(string name)
        {
            if (MatchStrong(name)) return true;
            string[] words = (name ?? "").Split(new[] { ' ', '.', '-', '_', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0) return false;
            string w = Nz(words[0]);
            return w.Length >= 4 && !Stop.Contains(w) && (_strong.Contains(w) || _strongWord.Contains(w));
        }

        /// <summary>Corrispondenza esatta: per le sottochiavi, i cui nomi sono spesso generici.</summary>
        public bool MatchStrongExact(string name)
        {
            string z = Nz(name);
            return z.Length >= 5 && !Stop.Contains(z) && _strong.Contains(z);
        }

        public bool MatchWeak(string name) { string h; return Match(name, _weak, _weakBlob, null, out h); }

        static bool Match(string name, HashSet<string> set, string blob, HashSet<string> words, out string hit)
        {
            hit = null;
            string z = Nz(name);
            if (z.Length < 3 || Stop.Contains(z)) return false;
            if (set.Contains(z) || (words != null && words.Contains(z))) { hit = z; return true; }
            if (z.Length < 5) return false;
            if (blob != null)
            {
                // Inizio di token ("litho" -> "lithohub"); dentro al token solo per nomi lunghi, per evitare "litho" in "monolithography".
                int i = blob.IndexOf("|" + z, StringComparison.Ordinal);
                if (i >= 0) i++;
                else if (z.Length >= 8) i = blob.IndexOf(z, StringComparison.Ordinal);
                if (i >= 0)
                {
                    int a = blob.LastIndexOf('|', i) + 1, b = blob.IndexOf('|', i);
                    hit = blob.Substring(a, b - a);
                    return true;
                }
            }
            // Il nome del produttore inizia con un token del corpus ("contosotechnologies" -> "contoso").
            foreach (string t in set)
                if (t.Length >= 5 && !Stop.Contains(t) && z.StartsWith(t, StringComparison.Ordinal)) { hit = t; return true; }
            return false;
        }

        /// <summary>Vero se la cartella contiene un eseguibile entro la profondità data (con budget di voci).</summary>
        public bool HasExecutable(string dir, int depth = 3, int budget = 2000)
        {
            bool r;
            if (_exeCache.TryGetValue(dir, out r)) return r;
            r = ExeWalk(dir, depth, ref budget);
            _exeCache[dir] = r;
            return r;
        }

        static bool ExeWalk(string dir, int depth, ref int budget)
        {
            if (budget <= 0) return false;
            try
            {
                foreach (string f in Directory.EnumerateFiles(dir))
                {
                    if (--budget <= 0) return false;
                    string e = Path.GetExtension(f);
                    if (e.Equals(".exe", StringComparison.OrdinalIgnoreCase) || e.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return true;
                }
                if (depth <= 0) return false;
                foreach (string d in Directory.EnumerateDirectories(dir))
                {
                    if (--budget <= 0) return false;
                    if (ExeWalk(d, depth - 1, ref budget)) return true;
                }
            }
            catch (Exception) { }
            return false;
        }

        static readonly Regex AcfAppId = new Regex("\"appid\"\\s+\"(\\d+)\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex AcfName = new Regex("\"name\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex AcfDir = new Regex("\"installdir\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex VdfPath = new Regex("\"path\"\\s+\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>Legge libraryfolders.vdf e i manifest appmanifest_*.acf di tutte le librerie.</summary>
        public void LoadSteam(IEnumerable<string> steamRoots)
        {
            var libs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string r in steamRoots)
            {
                if (string.IsNullOrWhiteSpace(r)) continue;
                string root = r.Replace('/', '\\').TrimEnd('\\');
                libs.Add(root);
                string vdf = Path.Combine(root, @"steamapps\libraryfolders.vdf");
                try
                {
                    if (File.Exists(vdf))
                        foreach (Match m in VdfPath.Matches(File.ReadAllText(vdf)))
                            libs.Add(m.Groups[1].Value.Replace(@"\\", @"\").TrimEnd('\\'));
                }
                catch (Exception) { SteamReadErrors++; }
            }
            foreach (string lib in libs)
            {
                string apps = Path.Combine(lib, "steamapps");
                try
                {
                    if (lib.Length >= 2 && lib[1] == ':' && !Directory.Exists(lib.Substring(0, 2) + "\\")) { SteamLibraryOffline = true; continue; }
                    if (!Directory.Exists(apps)) continue;
                    foreach (string f in Directory.EnumerateFiles(apps, "appmanifest_*.acf"))
                    {
                        try
                        {
                            string t = File.ReadAllText(f);
                            Match id = AcfAppId.Match(t), nm = AcfName.Match(t), dr = AcfDir.Match(t);
                            if (id.Success) SteamAppIds.Add(id.Groups[1].Value);
                            if (nm.Success) AddStrong(nm.Groups[1].Value);
                            if (dr.Success) { AddStrong(dr.Groups[1].Value); SteamInstallDirs.Add(dr.Groups[1].Value); }
                            if (!id.Success || !dr.Success) SteamReadErrors++;
                        }
                        catch (Exception) { SteamReadErrors++; }
                    }
                }
                catch (Exception) { SteamReadErrors++; }
            }
        }

        static readonly Regex EpicName = new Regex("\"DisplayName\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.Compiled);

        /// <summary>Giochi Epic installati (manifest .item), se presenti.</summary>
        public void LoadEpic(string programData)
        {
            try
            {
                string dir = Path.Combine(programData, @"Epic\EpicGamesLauncher\Data\Manifests");
                if (!Directory.Exists(dir)) return;
                foreach (string f in Directory.EnumerateFiles(dir, "*.item"))
                {
                    try { Match m = EpicName.Match(File.ReadAllText(f)); if (m.Success) AddStrong(m.Groups[1].Value); }
                    catch (Exception) { }
                }
            }
            catch (Exception) { }
        }

        static readonly HashSet<string> RootSkip = new HashSet<string>(new[] { "Windows", "Program Files", "Program Files (x86)", "ProgramData", "Users", "$Recycle.Bin", "$WinREAgent", "System Volume Information", "PerfLogs", "Recovery", "Config.Msi", "MSOCache", "Documents and Settings", "OneDriveTemp", "inetpub" }, StringComparer.OrdinalIgnoreCase);

        /// <summary>Cartelle in radice di ogni unità fissa, un livello in profondità (D:\Giochi\..., E:\Programmi\...).</summary>
        public void LoadVolumeRoots()
        {
            DriveInfo[] drives;
            try { drives = DriveInfo.GetDrives(); } catch (Exception) { return; }
            foreach (DriveInfo d in drives)
            {
                try { if (d.DriveType != DriveType.Fixed || !d.IsReady) continue; }
                catch (Exception) { continue; }
                string[] dirs;
                try { dirs = Directory.GetDirectories(d.Name); } catch (Exception) { continue; }
                foreach (string dir in dirs)
                {
                    string name = Path.GetFileName(dir);
                    if (RootSkip.Contains(name)) continue;
                    if (HasExecutable(dir)) AddStrong(name); else AddWeak(name);
                    string[] subs;
                    try { subs = Directory.GetDirectories(dir); } catch (Exception) { continue; }
                    foreach (string s in subs.Take(60))
                    {
                        string sn = Path.GetFileName(s);
                        if (HasExecutable(s, 2, 300)) AddStrong(sn); else AddWeak(sn);
                    }
                }
            }
        }

        /// <summary>Censisce le cartelle: forti se contengono eseguibili, altrimenti deboli.</summary>
        public void LoadDirs(string parent, bool secondLevel)
        {
            if (string.IsNullOrEmpty(parent)) return;
            string[] dirs;
            try { dirs = Directory.GetDirectories(parent); } catch (Exception) { return; }
            foreach (string d in dirs)
            {
                string name = Path.GetFileName(d);
                if (HasExecutable(d)) AddStrong(name); else AddWeak(name);
                if (!secondLevel) continue;
                string[] subs;
                try { subs = Directory.GetDirectories(d); } catch (Exception) { continue; }
                foreach (string s in subs.Take(60))
                {
                    string sn = Path.GetFileName(s);
                    if (HasExecutable(s, 2, 300)) AddStrong(sn); else AddWeak(sn);
                }
            }
        }
    }
}
