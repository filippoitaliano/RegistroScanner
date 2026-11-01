using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace RegistroScanner
{
    public sealed class DeleteOptions
    {
        public string BackupPath;
        public string LogPath;
        public Action<int, int, string> Progress; // fatto, totale, voce
        /// <summary>Se valorizzato: rifiuta tutto ciò che non è sotto questo prefisso (usato dall'autotest).</summary>
        public string SandboxOnly;
        /// <summary>Tutte le righe note: una chiave che coprirebbe righe non selezionate viene saltata.</summary>
        public IList<Row> AllRows;
        public CancellationToken Cancel = CancellationToken.None;
        /// <summary>Solo autotest: simula un errore di scrittura del backup.</summary>
        public Func<bool> InjectBackupWriteFailure;
    }

    public sealed class DeleteOutcome
    {
        public int Deleted, Skipped, Errors, Partial, FirewallPending;
        public string BackupPath, LogPath, Warning;
        public List<Row> Removed = new List<Row>();
    }

    /// <summary>Motore di eliminazione. Riceve solo righe già filtrate; la guardia è sempre applicata.</summary>
    public static class DeleteEngine
    {
        public const string StatusFirewall = "Rimossa dal registro: attiva fino al riavvio del firewall";
        public const string StatusChanged = "Saltata: voce cambiata dopo la scansione";
        public const string StatusCovers = "Saltata: coprirebbe voci non selezionate";
        public const string StatusLink = "Saltata: è un collegamento del registro";
        public const string StatusCancelled = "Saltata: annullata dall'utente";
        public const string StatusBackupStopped = "Saltata: backup interrotto, nessuna eliminazione senza copia";

        sealed class Ctx
        {
            public DeleteOptions Opt;
            public DeleteOutcome Out;
            public RegBackupWriter Backup;
            public string BackupError;
            public bool BackupBroken;
            public PathProbe Probe = new PathProbe();
            public List<string> RemovedRoots = new List<string>();
            public HashSet<string> CoveredByOthers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        public static DeleteOutcome Run(IList<Row> rows, DeleteOptions opt)
        {
            var o = new DeleteOutcome { BackupPath = opt.BackupPath, LogPath = opt.LogPath };
            var ctx = new Ctx { Opt = opt, Out = o };
            Directory.CreateDirectory(Path.GetDirectoryName(opt.BackupPath));

            StreamWriter log = null;
            try
            {
                log = new StreamWriter(new FileStream(opt.LogPath, FileMode.Create, FileAccess.Write, FileShare.Read), new UTF8Encoding(true)) { AutoFlush = true };
                log.WriteLine("Registro Scanner - registro delle eliminazioni");
                log.WriteLine("Data: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "   Utente: " + Environment.UserName);
                log.WriteLine("Backup: " + opt.BackupPath);
                log.WriteLine();
            }
            catch (Exception ex)
            {
                o.LogPath = null;
                o.Warning = AddWarning(o.Warning, "Registro delle eliminazioni non scritto: " + ex.Message);
                if (log != null) { try { log.Dispose(); } catch (Exception) { } log = null; }
            }

            // Prima le radici più corte: una voce sotto una chiave già rimossa risulta coperta.
            var ordered = rows.OrderBy(r => r.DeleteRoot.Count(c => c == '\\')).ToList();

            if (opt.AllRows != null)
            {
                var selected = new HashSet<Row>(rows);
                foreach (Row r in opt.AllRows)
                {
                    if (selected.Contains(r) || string.IsNullOrEmpty(r.Hive)) continue;
                    AddSelfAndAncestors(ctx.CoveredByOthers, r.Hive + "\\" + r.DeleteRoot);
                    AddSelfAndAncestors(ctx.CoveredByOthers, r.Hive + "\\" + r.KeyPath);
                }
            }

            try { ctx.Backup = new RegBackupWriter(opt.BackupPath); }
            catch (Exception ex) { ctx.BackupError = ex.Message; }

            try
            {
                using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (RegistryKey hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                {
                    int done = 0;
                    foreach (Row r in ordered)
                    {
                        done++;
                        if (opt.Progress != null) opt.Progress(done, ordered.Count, r.TargetText);
                        string outcome;
                        if (opt.Cancel.IsCancellationRequested) outcome = Skip(r, o, StatusCancelled);
                        else if (ctx.BackupBroken) outcome = Skip(r, o, StatusBackupStopped);
                        else if (ctx.Backup == null) outcome = Skip(r, o, "Saltata: backup non disponibile (" + ctx.BackupError + ")");
                        else
                        {
                            try { outcome = ProcessRow(r, r.Hive == "HKLM" ? hklm : hkcu, ctx); }
                            catch (Exception ex) { outcome = Fail(r, o, ex.Message); }
                        }
                        WriteLog(log, outcome + "\t" + r.TargetText, o);
                    }
                }
            }
            finally
            {
                if (ctx.Backup != null)
                {
                    try { ctx.Backup.Dispose(); }
                    catch (Exception ex) { o.Warning = AddWarning(o.Warning, "ATTENZIONE: chiusura del file di backup non riuscita, verificalo: " + ex.Message); }
                }
                WriteLog(log, "", o);
                WriteLog(log, "Eliminate: " + o.Deleted + "  In parte: " + o.Partial + "  Saltate: " + o.Skipped + "  Errori: " + o.Errors + "  Regole firewall in attesa: " + o.FirewallPending, o);
                if (o.Warning != null) WriteLog(log, o.Warning, o);
                if (log != null) { try { log.Dispose(); } catch (Exception) { } }
            }
            return o;
        }

        static string AddWarning(string a, string b) { return string.IsNullOrEmpty(a) ? b : a + "\r\n" + b; }

        static void WriteLog(StreamWriter log, string line, DeleteOutcome o)
        {
            if (log == null) return;
            try { log.WriteLine(line); }
            catch (Exception ex) { o.Warning = AddWarning(o.Warning, "Scrittura del registro interrotta: " + ex.Message); }
        }

        static void AddSelfAndAncestors(HashSet<string> set, string full)
        {
            string cur = full;
            while (true)
            {
                set.Add(cur);
                int i = cur.LastIndexOf('\\');
                if (i <= 0) return;
                cur = cur.Substring(0, i);
            }
        }

        /// <summary>Testo serializzato della destinazione, o null se non esiste. Solleva un'eccezione se non è leggibile o non rappresentabile.</summary>
        public static string Serialize(RegistryKey baseKey, string hive, string root, ActionKind action, string valueName)
        {
            using (RegistryKey k = baseKey.OpenSubKey(root, false))
            {
                if (k == null) return null;
                if (action == ActionKind.DeleteKey) return RegBackupWriter.SerializeKey(hive, k, root);
                RawValue v = RegNative.ReadValue(k, valueName);
                return v == null ? null : RegBackupWriter.SerializeValue(hive, root, v);
            }
        }

        public static string Hash(string text)
        {
            using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(Encoding.Unicode.GetBytes(text))).Replace("-", "");
        }

        static string ProcessRow(Row r, RegistryKey baseKey, Ctx c)
        {
            DeleteOutcome o = c.Out;
            DeleteOptions opt = c.Opt;
            string why;
            if (!r.Deletable)
                return Skip(r, o, "Saltata: voce non eliminabile");
            if (!DeleteGuard.Check(r.Hive, r.DeleteRoot, r.Action, r.ValueName, out why))
                return Skip(r, o, "Saltata: rifiutata dalla protezione (" + why + ")");
            string fullRoot = r.Hive + "\\" + r.DeleteRoot;
            if (opt.SandboxOnly != null && !fullRoot.Equals(opt.SandboxOnly, StringComparison.OrdinalIgnoreCase) && !fullRoot.StartsWith(opt.SandboxOnly + "\\", StringComparison.OrdinalIgnoreCase))
                return Skip(r, o, "Saltata: fuori dalla sandbox");

            foreach (string gone in c.RemovedRoots)
                if (fullRoot.StartsWith(gone + "\\", StringComparison.OrdinalIgnoreCase) || fullRoot.Equals(gone, StringComparison.OrdinalIgnoreCase))
                {
                    r.Status = "Eliminata";
                    o.Deleted++;
                    o.Removed.Add(r);
                    return "Eliminata (inclusa in " + gone + ")";
                }

            if (r.Action == ActionKind.DeleteKey && c.CoveredByOthers.Contains(fullRoot))
                return Skip(r, o, StatusCovers);

            if (RegNative.IsLinkPath(baseKey, r.DeleteRoot))
                return Skip(r, o, StatusLink);

            // Il file che giustificava la voce deve essere ancora assente, e l'assenza deve essere dimostrata.
            if (!string.IsNullOrEmpty(r.ProbePath))
            {
                PathStatus now = c.Probe.ProbeFile(r.ProbePath).Status;
                PathStatus expected = r.ProbeStatus ?? PathStatus.Missing;
                if (now == PathStatus.Exists) return Skip(r, o, "Saltata: il file ora esiste");
                if (now != PathStatus.Missing && now != expected) return Skip(r, o, "Saltata: percorso non verificabile");
            }

            string text;
            try { text = Serialize(baseKey, r.Hive, r.DeleteRoot, r.Action, r.ValueName); }
            catch (Exception ex) { return Fail(r, o, "backup non riuscito: " + ex.Message); }
            if (text == null) return Skip(r, o, "Saltata: voce non più presente");

            if (r.ContentHash != null && !string.Equals(r.ContentHash, Hash(text), StringComparison.Ordinal))
                return Skip(r, o, StatusChanged);

            try
            {
                if (opt.InjectBackupWriteFailure != null && opt.InjectBackupWriteFailure()) throw new IOException("errore simulato");
                c.Backup.WriteEntry(text);
            }
            catch (Exception ex)
            {
                c.BackupBroken = true;
                o.Warning = AddWarning(o.Warning, "Scrittura del backup interrotta: le voci rimanenti sono state saltate. " + ex.Message);
                return Fail(r, o, "scrittura del backup non riuscita: " + ex.Message);
            }

            return r.Action == ActionKind.DeleteKey ? DeleteKey(r, baseKey, text, fullRoot, c) : DeleteValue(r, baseKey, c);
        }

        static string DeleteKey(Row r, RegistryKey baseKey, string before, string fullRoot, Ctx c)
        {
            DeleteOutcome o = c.Out;
            Exception err = null;
            try { baseKey.DeleteSubKeyTree(r.DeleteRoot, false); }
            catch (Exception ex) { err = ex; }

            bool present = true, unknown = false;
            string after = null;
            try
            {
                using (RegistryKey k = baseKey.OpenSubKey(r.DeleteRoot, false))
                {
                    present = k != null;
                    if (present) after = RegBackupWriter.SerializeKey(r.Hive, k, r.DeleteRoot);
                }
            }
            catch (Exception) { unknown = true; }

            if (!present)
            {
                c.RemovedRoots.Add(fullRoot);
                return Succeed(r, o);
            }
            string detail = err != null ? ": " + err.Message : "";
            if (!unknown && after == before) return Fail(r, o, "non eliminata" + detail);

            r.Status = "ELIMINATA IN PARTE: ripristina da " + c.Opt.BackupPath;
            o.Partial++;
            return r.Status + detail;
        }

        static string DeleteValue(Row r, RegistryKey baseKey, Ctx c)
        {
            DeleteOutcome o = c.Out;
            Exception err = null;
            try
            {
                using (RegistryKey w = baseKey.OpenSubKey(r.DeleteRoot, true))
                {
                    if (w == null) throw new IOException("chiave non scrivibile");
                    w.DeleteValue(r.ValueName, false);
                }
            }
            catch (Exception ex) { err = ex; }

            bool present;
            using (RegistryKey k = baseKey.OpenSubKey(r.DeleteRoot, false))
                present = k != null && RegNative.ReadValue(k, r.ValueName) != null;
            if (present) return Fail(r, o, "non eliminata" + (err != null ? ": " + err.Message : ""));
            return Succeed(r, o);
        }

        static string Succeed(Row r, DeleteOutcome o)
        {
            if (r.GroupId.StartsWith("fw-", StringComparison.Ordinal))
            {
                r.Status = StatusFirewall;
                o.FirewallPending++;
            }
            else r.Status = "Eliminata";
            o.Deleted++;
            o.Removed.Add(r);
            return r.Status;
        }

        static string Skip(Row r, DeleteOutcome o, string msg)
        {
            r.Status = msg;
            o.Skipped++;
            return msg;
        }

        static string Fail(Row r, DeleteOutcome o, string msg)
        {
            r.Status = "Errore: " + msg;
            o.Errors++;
            return r.Status;
        }
    }
}
