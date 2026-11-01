using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace RegistroScanner
{
    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            string smokeDir = args.Length == 2 && args[0] == "--ui-smoke" ? args[1] : null;
            if (args.Length > 0 && smokeDir == null)
            {
                try
                {
                    if (args[0] == "--scan-csv") return ScanCsv(args);
                    if (args[0] == "--selftest" && args.Length >= 2) return SelfTest.Run(args[1]);
                }
                catch (Exception ex)
                {
                    try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "RegistroScanner-errore.txt"), ex.ToString()); } catch (Exception) { }
                    return 2;
                }
                return 3;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            var form = new MainForm();
            if (smokeDir != null) form.EnableUiSmoke(smokeDir);
            Application.Run(form);
            return 0;
        }

        static int ScanCsv(string[] args)
        {
            if (args.Length < 2) return 3;
            string csv = args[1], summary = null;
            for (int i = 2; i + 1 < args.Length; i++)
                if (args[i] == "--summary") summary = args[i + 1];

            ScanResult res = Task.Run(() => new Scanner(CancellationToken.None, null).Run()).Result;
            CsvExport.Write(csv, res.Rows, true);

            if (summary != null)
            {
                var sb = new StringBuilder();
                sb.AppendLine("Righe totali: " + res.Rows.Count);
                sb.AppendLine("Eliminabili: " + res.Rows.Count(r => r.Deletable));
                sb.AppendLine("Tempo: " + res.Elapsed.TotalSeconds.ToString("0.0") + " s");
                sb.AppendLine("Chiavi non leggibili: " + res.DeniedKeys);
                var lost = res.Rows.Where(r => r.GuardRejection != null).ToList();
                sb.AppendLine("Candidate escluse da protezione o controlli: " + lost.Count);
                foreach (var g in lost.GroupBy(r => r.Group + " :: " + r.GuardRejection).OrderByDescending(g => g.Count()))
                    sb.AppendLine("  " + g.Count() + "\t" + g.Key + "\t(es. " + g.First().TargetText + ")");
                sb.AppendLine();
                sb.AppendLine("== Per livello");
                foreach (string t in Tiers.All)
                    sb.AppendLine(res.Rows.Count(r => r.Tier == t) + "\t" + t);
                sb.AppendLine();
                sb.AppendLine("== Per gruppo");
                foreach (var g in res.Rows.GroupBy(r => r.Group).OrderBy(g => Tiers.Rank(g.First().Tier)).ThenByDescending(g => g.Count()))
                    sb.AppendLine(g.Count() + "\t" + g.Min(r => r.Confidence ?? -1) + "\t" + g.Key);
                File.WriteAllText(summary, sb.ToString(), new UTF8Encoding(true));
            }
            return 0;
        }
    }
}
