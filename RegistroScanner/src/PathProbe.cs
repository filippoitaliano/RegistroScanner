using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text.RegularExpressions;

namespace RegistroScanner
{
    public enum PathStatus { Exists, Missing, BareMissing, Denied, DriveAbsent, Network, AppxUnverified, NotAPath, Empty, MsiMissing }

    public struct ProbeResult
    {
        public PathStatus Status;
        public string Target;
        public string FpNote; // valorizzata se un controllo ingenuo l'avrebbe segnalata come orfana
        public ProbeResult(PathStatus s, string t, string note = null) { Status = s; Target = t; FpNote = note; }

        public bool IsOrphan
        {
            get
            {
                switch (Status)
                {
                    case PathStatus.Missing:
                    case PathStatus.BareMissing:
                    case PathStatus.DriveAbsent:
                    case PathStatus.Network:
                    case PathStatus.AppxUnverified:
                    case PathStatus.MsiMissing:
                        return true;
                }
                return false;
            }
        }
    }

    /// <summary>Verifica dei percorsi: solo lettura del file system.</summary>
    public sealed class PathProbe
    {
        public const string NoteSlash = "Percorso con \"/\": il file esiste";
        public const string NoteNoExt = "Comando senza estensione: il file esiste";
        public const string NotePlaceholder = "Segnaposto o comando di sistema";
        public const string NoteNotPath = "Argomento, non un percorso";
        public const string NoteProtected = "Cartella protetta: non verificabile";
        public const string NoteTypeLib = "TypeLib con suffisso \\N: il file esiste";

        static readonly Regex ExtRx = new Regex("^(.+?\\.(?:exe|dll|ocx|cpl|sys|com|scr|bat|cmd|ps1|vbs|vbe|js|msc|ax|drv|tlb|olb|msi|acm|ime|wsf|lnk|jar|py|inproc))(?=$|[\\s,\"])(.*)$", RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.Singleline);
        static readonly Regex WrapArgRx = new Regex("\"?([A-Za-z]:[\\\\/][^\",]+?\\.(?:exe|dll|ocx|cpl|sys|com|scr|bat|cmd|ps1|vbs|vbe|js|msc|ax|drv|tlb|olb|msi|acm|ime|wsf|lnk|jar|py))(?=$|[\\s,\"])", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex GuidRx = new Regex("\\{[0-9A-Fa-f-]{36}\\}", RegexOptions.Compiled);
        static readonly Regex RundllRx = new Regex("^\\s*\"?([^\",\\s]+\\.dll)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex IconRx = new Regex(",\\s*-?\\d+\\s*$", RegexOptions.Compiled);
        static readonly Regex WinAppsRx = new Regex("\\\\WindowsApps\\\\([^\\\\]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex KnownExtRx = new Regex("\\.[A-Za-z0-9]{1,8}$", RegexOptions.Compiled);

        static readonly HashSet<string> Wrappers = new HashSet<string>(new[] { "rundll32", "regsvr32", "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "conhost", "javaw", "java", "python", "pythonw", "node", "dllhost", "start" }, StringComparer.OrdinalIgnoreCase);

        readonly string _windir, _sys32, _wow64;
        readonly List<string> _searchDirs;
        readonly Dictionary<string, ProbeResult> _cache = new Dictionary<string, ProbeResult>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, bool> _unreadable = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        readonly string _pf, _pf86;

        public HashSet<string> AppxInstalled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public Func<string, bool> MsiProductExists = g => true;

        public PathProbe()
        {
            _windir = Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows";
            _sys32 = Path.Combine(_windir, "System32");
            _wow64 = Path.Combine(_windir, "SysWOW64");
            _pf = Environment.GetEnvironmentVariable("ProgramW6432") ?? Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files";
            _pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)";
            _searchDirs = new List<string> { _windir, _sys32, _wow64, Path.Combine(_sys32, "wbem"), Path.Combine(_sys32, @"WindowsPowerShell\v1.0"), Path.Combine(_sys32, "drivers"), Path.Combine(_windir, "Fonts") };
            foreach (string d in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
            {
                string t = d.Trim().Trim('"');
                if (t.Length > 0 && t.IndexOfAny(Path.GetInvalidPathChars()) < 0) _searchDirs.Add(t);
            }
        }

        public string Windir { get { return _windir; } }

        /// <summary>Normalizza una stringa che si suppone sia un percorso (non una riga di comando).</summary>
        public string Normalize(string raw)
        {
            if (raw == null) return "";
            string p = raw.Trim().Trim('"').Trim();
            p = Environment.ExpandEnvironmentVariables(p);
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
            if (p.StartsWith(@"\\?\", StringComparison.Ordinal)) p = p.Substring(4);
            if (p.StartsWith("@", StringComparison.Ordinal)) p = p.Substring(1);
            if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) p = _windir + "\\" + p.Substring(12);
            if (p.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || p.StartsWith(@"syswow64\", StringComparison.OrdinalIgnoreCase)) p = _windir + "\\" + p;
            return p;
        }

        static string StripIcon(string p) { return IconRx.Replace(p, ""); }

        static bool HasSlash(string p) { return p.IndexOf('/') >= 0; }

        static string FixSlash(string p) { return p.Replace('/', '\\'); }

        /// <summary>Verifica un percorso già normalizzato (file o cartella).</summary>
        public ProbeResult ProbeFile(string rawPath)
        {
            string p = StripIcon(rawPath ?? "").Trim();
            if (p.Length == 0) return new ProbeResult(PathStatus.Empty, "");
            ProbeResult r;
            if (_cache.TryGetValue(p, out r)) return r;
            r = ProbeUncached(p);
            _cache[p] = r;
            return r;
        }

        ProbeResult ProbeUncached(string p)
        {
            string note = null;
            if (HasSlash(p) && (p.Length > 2 && p[1] == ':')) { p = FixSlash(p); note = NoteSlash; }

            if (p.IndexOf('%') >= 0) return new ProbeResult(PathStatus.NotAPath, p, NoteNotPath);
            if (p.StartsWith(@"\\", StringComparison.Ordinal)) return new ProbeResult(PathStatus.Network, p);

            if (p.Length >= 3 && char.IsLetter(p[0]) && p[1] == ':' && p[2] == '\\')
            {
                bool rootOk;
                try { rootOk = Directory.Exists(p.Substring(0, 3)); } catch { rootOk = false; }
                if (!rootOk) return new ProbeResult(PathStatus.DriveAbsent, p);

                PathStatus st = Attr(p);
                if (st == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, p, note);
                if (st == PathStatus.NotAPath) return new ProbeResult(PathStatus.NotAPath, p, NoteNotPath);

                Match mw = WinAppsRx.Match(p);
                if (mw.Success)
                {
                    if (AppxInstalled.Contains(mw.Groups[1].Value)) return new ProbeResult(PathStatus.Exists, p);
                    return new ProbeResult(PathStatus.AppxUnverified, p);
                }

                if (st == PathStatus.Denied) return new ProbeResult(PathStatus.Denied, p, NoteProtected);

                // Missing: varianti note.
                if (Under(p, _sys32) && Attr(_wow64 + p.Substring(_sys32.Length)) == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, p, note);
                if (Under(p, _wow64) && Attr(_sys32 + p.Substring(_wow64.Length)) == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, p, note);
                string sysnative = Path.Combine(_windir, "sysnative");
                if (Under(p, sysnative) && Attr(_sys32 + p.Substring(sysnative.Length)) == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, p, note);

                if (Under(p, Path.Combine(_sys32, "config"))) return new ProbeResult(PathStatus.Denied, p, NoteProtected);

                if (!KnownExtRx.IsMatch(p.Substring(p.LastIndexOf('\\') + 1)) && Attr(p + ".exe") == PathStatus.Exists)
                    return new ProbeResult(PathStatus.Exists, p + ".exe", NoteNoExt);

                if (ParentUnreadable(p)) return new ProbeResult(PathStatus.Denied, p, NoteProtected);
                return new ProbeResult(PathStatus.Missing, p);
            }

            if (p.IndexOf('\\') < 0)
            {
                bool hasExt = KnownExtRx.IsMatch(p);
                foreach (string d in _searchDirs)
                {
                    if (SafeFileExists(d, p)) return new ProbeResult(PathStatus.Exists, Path.Combine(d, p));
                    if (!hasExt && SafeFileExists(d, p + ".exe")) return new ProbeResult(PathStatus.Exists, Path.Combine(d, p + ".exe"), NoteNoExt);
                }
                return new ProbeResult(PathStatus.BareMissing, p);
            }
            return new ProbeResult(PathStatus.NotAPath, p, NoteNotPath);
        }

        static bool SafeFileExists(string dir, string name)
        {
            try { return File.Exists(Path.Combine(dir, name)); } catch { return false; }
        }

        static bool Under(string p, string dir)
        {
            return p.Length > dir.Length && p.StartsWith(dir, StringComparison.OrdinalIgnoreCase) && p[dir.Length] == '\\';
        }

        static PathStatus Attr(string p)
        {
            try { File.GetAttributes(p); return PathStatus.Exists; }
            catch (FileNotFoundException) { return PathStatus.Missing; }
            catch (DirectoryNotFoundException) { return PathStatus.Missing; }
            catch (UnauthorizedAccessException) { return PathStatus.Denied; }
            catch (ArgumentException) { return PathStatus.NotAPath; }
            catch (NotSupportedException) { return PathStatus.NotAPath; }
            catch (PathTooLongException) { return PathStatus.Denied; }
            catch (SecurityException) { return PathStatus.Denied; }
            catch (IOException) { return PathStatus.Denied; }
        }

        /// <summary>Vero se il più vicino antenato esistente non è elencabile: l'assenza non è dimostrabile.</summary>
        bool ParentUnreadable(string p)
        {
            string cur = p;
            while (true)
            {
                string par;
                try { par = Path.GetDirectoryName(cur); } catch { return false; }
                if (string.IsNullOrEmpty(par)) return false;
                bool res;
                if (_unreadable.TryGetValue(par, out res)) return res;
                PathStatus st = Attr(par);
                if (st == PathStatus.Missing) { cur = par; continue; }
                if (st == PathStatus.Denied) { _unreadable[par] = true; return true; }
                res = false;
                try { using (var e = Directory.EnumerateFileSystemEntries(par).GetEnumerator()) e.MoveNext(); }
                catch (UnauthorizedAccessException) { res = true; }
                catch (SecurityException) { res = true; }
                catch (IOException) { res = false; }
                _unreadable[par] = res;
                return res;
            }
        }

        /// <summary>Verifica una riga di comando: separa eseguibile e argomenti, gestisce i wrapper.</summary>
        public ProbeResult ProbeCommand(string cmd)
        {
            string trimmed = (cmd ?? "").Trim();
            if (trimmed.Length == 0) return new ProbeResult(PathStatus.Empty, "");
            ProbeResult early;
            if (IsNonPath(trimmed, out early)) return early;

            string s = Normalize(trimmed);
            if (s.Length == 0) return new ProbeResult(PathStatus.Empty, "");
            if (IsNonPath(s, out early)) return early;

            string exe = "", rest = "";
            bool quoted = false;
            if (trimmed[0] == '"')
            {
                int end = trimmed.IndexOf('"', 1);
                if (end > 1)
                {
                    exe = Normalize(trimmed.Substring(1, end - 1));
                    rest = Environment.ExpandEnvironmentVariables(trimmed.Substring(end + 1));
                    quoted = true;
                }
            }
            if (!quoted)
            {
                // Percorso con spazi non quotato: vince la corrispondenza esistente più lunga.
                string longest = LooksAbsolute(s) ? LongestExisting(s) : null;
                if (longest != null) { exe = longest; rest = s.Substring(longest.Length); }
                else
                {
                    Match m = ExtRx.Match(s);
                    if (m.Success) { exe = m.Groups[1].Value; rest = m.Groups[2].Value; }
                    else
                    {
                        int sp = s.IndexOfAny(new[] { ' ', '\t' });
                        exe = sp > 0 ? s.Substring(0, sp) : s;
                        rest = sp > 0 ? s.Substring(sp + 1) : "";
                    }
                }
            }
            exe = StripIcon(exe).Trim().Trim('"');

            string baseName;
            try
            {
                string safe = exe.Replace('/', '\\');
                foreach (char ch in new[] { '<', '>', '|', '*', '?', '"' }) safe = safe.Replace(ch.ToString(), "");
                baseName = Path.GetFileNameWithoutExtension(safe);
            }
            catch { baseName = ""; }

            if (string.Equals(baseName, "msiexec", StringComparison.OrdinalIgnoreCase))
            {
                Match g = GuidRx.Match(s);
                if (g.Success) return new ProbeResult(MsiProductExists(g.Value) ? PathStatus.Exists : PathStatus.MsiMissing, g.Value);
                return new ProbeResult(PathStatus.Exists, "msiexec");
            }
            if (Wrappers.Contains(baseName))
            {
                Match a = WrapArgRx.Match(rest);
                if (a.Success) return ProbeFile(Normalize(a.Groups[1].Value));
                if (string.Equals(baseName, "rundll32", StringComparison.OrdinalIgnoreCase))
                {
                    Match d = RundllRx.Match(rest);
                    if (d.Success) return ProbeFile(Normalize(d.Groups[1].Value));
                }
            }

            ProbeResult r = ProbeFile(exe);
            if (r.Status == PathStatus.Missing && (trimmed.IndexOf("%ProgramFiles%", StringComparison.OrdinalIgnoreCase) >= 0 || trimmed.IndexOf("%CommonProgramFiles%", StringComparison.OrdinalIgnoreCase) >= 0) && Under(exe, _pf))
            {
                if (Attr(_pf86 + exe.Substring(_pf.Length)) == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, exe);
            }
            // Parola senza nulla di riconducibile a un file.
            if (r.Status == PathStatus.BareMissing && (exe.Length <= 2 || !Regex.IsMatch(exe, "^[A-Za-z0-9_.\\-]+$")))
                return new ProbeResult(PathStatus.NotAPath, trimmed, NoteNotPath);
            return r;
        }

        static string LongestExisting(string s)
        {
            string whole = FixSlash(StripIcon(s));
            if (Attr(whole) == PathStatus.Exists) return s;
            for (int sp = s.LastIndexOf(' '); sp > 0; sp = s.LastIndexOf(' ', sp - 1))
            {
                string c = s.Substring(0, sp);
                string f = FixSlash(c);
                if (Attr(f) == PathStatus.Exists && !Directory.Exists(f)) return c;
                if (Attr(f + ".exe") == PathStatus.Exists) return c;
            }
            return null;
        }

        static bool LooksAbsolute(string s) { return s.Length >= 3 && char.IsLetter(s[0]) && s[1] == ':' && (s[2] == '\\' || s[2] == '/'); }

        static bool IsNonPath(string s, out ProbeResult r)
        {
            r = default(ProbeResult);
            string t = s.Trim().Trim('"').Trim();
            if (t.Length == 0) { r = new ProbeResult(PathStatus.Empty, ""); return true; }
            if (Regex.IsMatch(t, "^%(\\d|\\*|L|l)")) { r = new ProbeResult(PathStatus.NotAPath, s, NotePlaceholder); return true; }
            if (t[0] == '/' || t[0] == '-') { r = new ProbeResult(PathStatus.NotAPath, s, NoteNotPath); return true; }
            if (t.Length <= 2 && !LooksAbsolute(t) && t.IndexOf('\\') < 0) { r = new ProbeResult(PathStatus.NotAPath, s, NoteNotPath); return true; }
            if (Regex.IsMatch(t, "^[A-Za-z][A-Za-z0-9+.\\-]{2,}:(//|[^\\\\/])")) { r = new ProbeResult(PathStatus.NotAPath, s, NoteNotPath); return true; } // URL, shell:, ms-settings:
            if (t.StartsWith("::", StringComparison.Ordinal) || (t[0] == '{' && GuidRx.IsMatch(t))) { r = new ProbeResult(PathStatus.NotAPath, s, NoteNotPath); return true; }
            return false;
        }

        /// <summary>Percorso di una TypeLib: toglie l'eventuale suffisso \N (indice di risorsa).</summary>
        public ProbeResult ProbeTypeLib(string raw)
        {
            string p = Normalize(raw);
            ProbeResult r = ProbeFile(p);
            if (r.IsOrphan)
            {
                Match m = Regex.Match(p, "^(.*)\\\\\\d+$");
                if (m.Success)
                {
                    ProbeResult r2 = ProbeFile(m.Groups[1].Value);
                    if (r2.Status == PathStatus.Exists) return new ProbeResult(PathStatus.Exists, m.Groups[1].Value, NoteTypeLib);
                    if (r2.Status == PathStatus.Denied) return r2;
                    return new ProbeResult(r2.Status, m.Groups[1].Value);
                }
            }
            return r;
        }

        public string ExplainStatus(PathStatus s)
        {
            switch (s)
            {
                case PathStatus.DriveAbsent:
                case PathStatus.Network:
                    return "Unità non collegata: il programma può essere reale, ma non è verificabile ora.";
                case PathStatus.AppxUnverified:
                    return "Percorso in WindowsApps con pacchetto non riconosciuto: non verificato.";
            }
            return null;
        }
    }
}
