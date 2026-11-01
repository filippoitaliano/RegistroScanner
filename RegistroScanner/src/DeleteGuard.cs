using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace RegistroScanner
{
    /// <summary>
    /// Guardia di eliminazione: ALLOWLIST di forme ammesse, indipendente dalla classificazione.
    /// Tutto ciò che non corrisponde a una forma elencata è rifiutato. Non tocca mai il registro.
    /// </summary>
    public static class DeleteGuard
    {
        public const string SandboxName = "__RegistroScannerSelfTest";

        const string FirewallRules = @"system\currentcontrolset\services\sharedaccess\parameters\firewallpolicy\firewallrules";
        const string CurrentVersion = @"software\microsoft\windows\currentversion";

        static readonly Regex GuidSeg = new Regex(@"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$", RegexOptions.Compiled);
        static readonly Regex TypeLibVer = new Regex(@"^[0-9a-f]+\.[0-9a-f]+$", RegexOptions.Compiled);
        static readonly Regex VsVer = new Regex(@"^\d+\.\d+", RegexOptions.Compiled);

        static readonly HashSet<string> RunKeys = new HashSet<string>(new[]
        {
            CurrentVersion + @"\run", CurrentVersion + @"\runonce", CurrentVersion + @"\runonceex",
            CurrentVersion + @"\runservices", CurrentVersion + @"\runservicesonce", CurrentVersion + @"\policies\explorer\run",
        }, StringComparer.Ordinal);

        static readonly HashSet<string> ExactValueParents = new HashSet<string>(new[]
        {
            CurrentVersion + @"\installer\folders",
            CurrentVersion + @"\shareddlls",
            @"software\registeredapplications",
            @"software\classes\local settings\software\microsoft\windows\shell\muicache",
        }, StringComparer.Ordinal);

        public static bool HasControlChars(string s)
        {
            if (s == null) return false;
            foreach (char c in s)
                if (c < 0x20 || c == 0x7F) return true;
            return false;
        }

        /// <summary>Vero se la destinazione ha una forma ammessa. reason spiega il rifiuto.</summary>
        public static bool Check(string hive, string path, ActionKind action, string valueName, out string reason)
        {
            reason = null;
            if (hive != "HKLM" && hive != "HKCU") { reason = "hive non ammesso"; return false; }
            if (string.IsNullOrEmpty(path)) { reason = "percorso vuoto"; return false; }
            if (HasControlChars(path) || HasControlChars(valueName)) { reason = "caratteri di controllo nel nome"; return false; }
            if (path[0] == '\\' || path[path.Length - 1] == '\\' || path.Contains(@"\\")) { reason = "percorso non canonico"; return false; }

            string[] segs = path.Split('\\');
            foreach (string s in segs)
                if (s == "." || s == ".." || s.Length == 0) { reason = "percorso non canonico"; return false; }
            if (segs.Length < 2) { reason = "profondità insufficiente"; return false; }

            string first = segs[0].ToLowerInvariant();

            if (first == "system")
            {
                if (hive != "HKLM") { reason = "SYSTEM in HKCU non ammesso"; return false; }
                if (action == ActionKind.DeleteKey) { reason = "eliminazione di chiavi sotto SYSTEM vietata"; return false; }
                if (!path.Equals(FirewallRules, StringComparison.OrdinalIgnoreCase)) { reason = "sotto SYSTEM sono ammessi solo valori di FirewallRules"; return false; }
                if (string.IsNullOrEmpty(valueName)) { reason = "valore predefinito non ammesso"; return false; }
                return true;
            }
            if (first != "software") { reason = "ammessi solo SOFTWARE e FirewallRules"; return false; }

            List<string> n = Normalize(segs);
            if (n.Count < 2) { reason = "chiave protetta"; return false; }

            return action == ActionKind.DeleteKey ? CheckKey(n, out reason) : CheckValue(n, valueName, out reason);
        }

        /// <summary>Minuscolo, senza WOW6432Node dopo Software e dopo Classes.</summary>
        static List<string> Normalize(string[] segs)
        {
            var n = new List<string>(segs.Length);
            foreach (string s in segs) n.Add(s.ToLowerInvariant());
            if (n.Count > 1 && n[1] == "wow6432node") n.RemoveAt(1);
            if (n.Count > 2 && n[1] == "classes" && n[2] == "wow6432node") n.RemoveAt(2);
            return n;
        }

        static bool CheckKey(List<string> n, out string reason)
        {
            reason = null;
            string second = n[1];
            string joined = string.Join("\\", n);

            if (second == SandboxName.ToLowerInvariant()) return true;

            if (second == "microsoft")
            {
                if (n.Count == 6 && joined.StartsWith(CurrentVersion + @"\uninstall\", StringComparison.Ordinal)) return true;
                if (n.Count == 6 && joined.StartsWith(CurrentVersion + @"\app paths\", StringComparison.Ordinal)) return true;
                if (n.Count == 7 && joined.StartsWith(CurrentVersion + @"\explorer\shelliconoverlayidentifiers\", StringComparison.Ordinal)) return true;
                if (n.Count == 4 && n[2] == "visualstudio" && VsVer.IsMatch(n[3])) return true;
                reason = "sotto Microsoft non è una forma ammessa";
                return false;
            }

            if (second == "classes")
            {
                if (n.Count == 3)
                {
                    if (Hints.IsSystemClass(n[2])) { reason = "classe di sistema"; return false; }
                    return true;
                }
                if (n.Count == 4 && n[2] == "applications") return true;
                if (n.Count == 4 && n[2] == "clsid" && GuidSeg.IsMatch(n[3])) return true;
                if (n.Count == 5 && n[2] == "typelib" && GuidSeg.IsMatch(n[3]) && TypeLibVer.IsMatch(n[4])) return true;
                reason = "sotto Classes non è una forma ammessa";
                return false;
            }

            if (Hints.SystemKeys.Contains(second)) { reason = "chiave di sistema"; return false; }
            if (n.Count > 3) { reason = "chiave di produttore troppo profonda"; return false; }
            return true; // Software\<produttore>[\sottochiave]
        }

        static bool CheckValue(List<string> n, string valueName, out string reason)
        {
            reason = null;
            if (string.IsNullOrEmpty(valueName)) { reason = "valore predefinito non ammesso"; return false; }
            string j = string.Join("\\", n);

            if (n[1] == SandboxName.ToLowerInvariant()) return true;
            if (ExactValueParents.Contains(j) || RunKeys.Contains(j)) return true;
            if (j.StartsWith(@"software\microsoft\windows nt\currentversion\appcompatflags\", StringComparison.Ordinal)) return true;
            if (n.Count == 7 && j.StartsWith(CurrentVersion + @"\explorer\startupapproved\", StringComparison.Ordinal)) return true;
            if (n.Count == 4 && n[1] == "classes" && n[2].StartsWith(".", StringComparison.Ordinal) && n[3] == "openwithprogids") return true;

            reason = "chiave padre non ammessa per i valori";
            return false;
        }
    }
}
