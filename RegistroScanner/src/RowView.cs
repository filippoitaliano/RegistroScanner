using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace RegistroScanner
{
    /// <summary>Filtro, ordinamento e comandi di selezione. Nessuna dipendenza dalla UI: testabile.</summary>
    public sealed class RowView
    {
        public List<Row> All = new List<Row>();
        public List<Row> Visible = new List<Row>();

        public string Text = "", Tier = null, Area = null, Group = null;
        public int SortColumn = -1;
        public bool SortAscending = true;

        public const int ColCheck = 0, ColConf = 1, ColTier = 2, ColArea = 3, ColGroup = 4, ColKey = 5, ColItem = 6, ColDetail = 7, ColAction = 8, ColStatus = 9;

        public void Apply()
        {
            string t = (Text ?? "").Trim();
            IEnumerable<Row> q = All;
            if (Tier != null) q = q.Where(r => r.Tier == Tier);
            if (Area != null) q = q.Where(r => r.Area == Area);
            if (Group != null) q = q.Where(r => r.Group == Group);
            if (t.Length > 0)
                q = q.Where(r => Has(r.KeyPath, t) || Has(r.KeyLabel, t) || Has(r.Item, t) || Has(r.Detail, t) || Has(r.Group, t) || Has(r.ValueName, t));
            Visible = q.ToList();
            Sort();
        }

        static bool Has(string s, string t) { return s != null && s.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0; }

        public void Sort()
        {
            if (SortColumn < 0) { Visible.Sort((a, b) => a.Seq.CompareTo(b.Seq)); return; }
            int col = SortColumn, dir = SortAscending ? 1 : -1;
            Visible.Sort((a, b) =>
            {
                int c = Compare(a, b, col) * dir;
                return c != 0 ? c : a.Seq.CompareTo(b.Seq); // stabile
            });
        }

        static int Compare(Row a, Row b, int col)
        {
            switch (col)
            {
                case ColCheck: return a.Checked.CompareTo(b.Checked);
                case ColConf: return (a.Confidence ?? -1).CompareTo(b.Confidence ?? -1);
                case ColTier: return Tiers.Rank(a.Tier).CompareTo(Tiers.Rank(b.Tier));
                case ColArea: return Cmp(a.Area, b.Area);
                case ColGroup: return Cmp(a.Group, b.Group);
                case ColKey: return Cmp(a.KeyLabel, b.KeyLabel);
                case ColItem: return Cmp(a.Item, b.Item);
                case ColDetail: return Cmp(a.Detail, b.Detail);
                case ColAction: return Cmp(a.ActionText, b.ActionText);
                case ColStatus: return Cmp(a.Status, b.Status);
            }
            return 0;
        }

        static int Cmp(string a, string b) { return string.Compare(a, b, StringComparison.CurrentCultureIgnoreCase); }

        // ---- comandi di selezione: agiscono solo sulle righe visibili e solo su quelle eliminabili.

        /// <summary>Ultimo comando di massa: righe "Meglio lasciare" lasciate com'erano.</summary>
        public int LastSkippedRisky;

        /// <summary>Restituisce il numero di righe saltate perché non eliminabili.</summary>
        public int SelectVisible() { return SetChecked(Visible, r => true, true); }

        public int DeselectVisible() { return SetChecked(Visible, r => false, false); }

        public int InvertVisible() { return SetChecked(Visible, r => !r.Checked, true); }

        public int SelectGroupVisible(string group) { return SetChecked(Visible.Where(r => r.Group == group), r => true, true); }

        int SetChecked(IEnumerable<Row> rows, Func<Row, bool> value, bool bulk)
        {
            int skipped = 0;
            LastSkippedRisky = 0;
            foreach (Row r in rows)
            {
                if (!r.Deletable) { skipped++; r.Checked = false; continue; }
                // Le righe "Meglio lasciare" entrano in massa solo con il filtro Livello esattamente su quel livello.
                if (bulk && r.Tier == Tiers.Lasciare && Tier != Tiers.Lasciare) { LastSkippedRisky++; continue; }
                r.Checked = value(r);
            }
            return skipped;
        }

        /// <summary>Toglie la spunta alle righe prima nascoste che ora sono visibili (filtro azzerato da solo). Restituisce quante.</summary>
        public int UncheckRevealed(HashSet<Row> hiddenBefore)
        {
            int n = 0;
            foreach (Row r in Visible)
                if (r.Checked && hiddenBefore.Contains(r)) { r.Checked = false; n++; }
            return n;
        }

        /// <summary>Righe spuntate attualmente nascoste dai filtri.</summary>
        public HashSet<Row> HiddenChecked()
        {
            var vis = new HashSet<Row>(Visible);
            return new HashSet<Row>(All.Where(r => r.Checked && !vis.Contains(r)));
        }

        /// <summary>Esclude ciò che non si può eliminare con questo account: HKLM senza elevazione, HKCU se il profilo è di un altro utente.</summary>
        public static List<Row> ForAccount(IEnumerable<Row> rows, bool elevated, bool otherUser, out int excludedHklm, out int excludedHkcu)
        {
            var list = new List<Row>();
            excludedHklm = 0;
            excludedHkcu = 0;
            foreach (Row r in rows)
            {
                if (!elevated && r.Hive == "HKLM") { excludedHklm++; continue; }
                if (otherUser && r.Hive == "HKCU") { excludedHkcu++; continue; }
                list.Add(r);
            }
            return list;
        }

        public int CheckedVisible { get { return Visible.Count(r => r.Checked); } }
        public int CheckedHidden { get { return All.Count(r => r.Checked) - CheckedVisible; } }

        /// <summary>Insieme eleggibile all'eliminazione: spuntate, visibili ed eliminabili.</summary>
        public List<Row> Eligible() { return Visible.Where(r => r.Checked && r.Deletable).ToList(); }
    }

    public static class CsvExport
    {
        public static readonly string[] GridHeaders = { "Spuntata", "Sicurezza %", "Livello", "Area", "Gruppo", "Chiave/Regola", "Voce", "Dettaglio", "Azione", "Stato" };

        public static string Neutralize(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? "";
            char c = s[0];
            if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r') return "'" + s;
            return s;
        }

        public static string Cell(string s, string sep)
        {
            s = Neutralize(s);
            if (s.IndexOf(sep, StringComparison.Ordinal) >= 0 || s.IndexOf('"') >= 0 || s.IndexOf('\r') >= 0 || s.IndexOf('\n') >= 0)
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        public static string Separator { get { return CultureInfo.CurrentCulture.TextInfo.ListSeparator; } }

        /// <summary>extended aggiunge Eliminabile e Destinazione (solo CLI).</summary>
        public static void Write(string path, IEnumerable<Row> rows, bool extended)
        {
            string sep = Separator;
            using (var w = new StreamWriter(path, false, new UTF8Encoding(true)))
            {
                var hdr = new List<string>(GridHeaders) { "Motivo", "Come procedere" };
                if (extended) { hdr.Add("Eliminabile"); hdr.Add("Destinazione"); }
                w.WriteLine(string.Join(sep, hdr.Select(h => Cell(h, sep))));
                foreach (Row r in rows)
                {
                    var c = new List<string>
                    {
                        r.Checked ? "Sì" : "No",
                        r.Confidence.HasValue ? r.Confidence.Value.ToString(CultureInfo.InvariantCulture) : "",
                        r.Tier, r.Area, r.Group, r.KeyLabel, r.Item, r.Detail, r.ActionText, r.Status, r.Reason, r.How
                    };
                    if (extended) { c.Add(r.Deletable ? "Sì" : "No"); c.Add(r.TargetText); }
                    w.WriteLine(string.Join(sep, c.Select(x => Cell(x, sep))));
                }
            }
        }
    }

    public static class Env
    {
        public static bool IsElevated()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception) { return false; }
        }

        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr p);

        /// <summary>Vero se il processo gira con un account diverso dall'utente della sessione.</summary>
        public static bool RunningAsOtherUser()
        {
            string i = InteractiveUser();
            return !string.IsNullOrEmpty(i) && !i.Equals(Environment.UserName, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Utente della sessione interattiva corrente, o null se non determinabile.</summary>
        public static string InteractiveUser()
        {
            const int WTSUserName = 5;
            IntPtr buf; int n;
            try
            {
                if (!WTSQuerySessionInformationW(IntPtr.Zero, -1, WTSUserName, out buf, out n)) return null;
                try { return Marshal.PtrToStringUni(buf); }
                finally { WTSFreeMemory(buf); }
            }
            catch (Exception) { return null; }
        }
    }
}
