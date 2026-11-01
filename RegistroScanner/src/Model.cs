using System;
using System.Collections.Generic;

namespace RegistroScanner
{
    public enum ActionKind { DeleteKey, DeleteValue }

    public static class Tiers
    {
        public const string Pulibile = "Pulibile";
        public const string Probabile = "Probabilmente pulibile";
        public const string Lasciare = "Meglio lasciare";
        public const string NonToccare = "Non toccare";
        public const string Falso = "Falso positivo";

        public static readonly string[] All = { Pulibile, Probabile, Lasciare, NonToccare, Falso };

        public static string Of(int? conf)
        {
            if (conf == null) return Falso;
            int c = conf.Value;
            if (c >= 90) return Pulibile;
            if (c >= 70) return Probabile;
            if (c >= 40) return Lasciare;
            return NonToccare;
        }

        public static bool IsDeletable(string tier)
        {
            return tier != NonToccare && tier != Falso;
        }

        public static int Rank(string tier)
        {
            int i = Array.IndexOf(All, tier);
            return i < 0 ? All.Length : i;
        }
    }

    /// <summary>Riga del risultato. Lo stato Checked vive qui e sopravvive a filtri e ordinamenti.</summary>
    public sealed class Row
    {
        public bool Checked;
        public int? Confidence;
        public string Tier = Tiers.Falso;
        public string Area = "";
        public string Group = "";
        public string GroupId = "";
        public string Hive = "";          // HKLM | HKCU | "" (non registro: operazioni pianificate)
        public string KeyPath = "";       // percorso sotto l'hive
        public string ValueName;          // null se la voce è una chiave
        public ActionKind Action = ActionKind.DeleteKey;
        public string DeleteRoot = "";    // destinazione esatta sotto l'hive
        public string Item = "";
        public string Detail = "";
        public string Reason = "";
        public string How = "";
        public string ProbePath;          // percorso la cui assenza ha giustificato la voce
        public PathStatus? ProbeStatus;   // esito della verifica al momento della scansione
        public string ContentHash;        // hash del contenuto serializzato al momento della scansione
        public string GuardRejection;     // motivo per cui una voce candidata non è eliminabile
        public string Status = "Da valutare";
        public bool Deletable;
        public int Seq;                   // ordine di scansione: rende stabile l'ordinamento

        public string ActionText { get { return Action == ActionKind.DeleteKey ? "Elimina chiave" : "Elimina valore"; } }

        public string FullKey
        {
            get
            {
                string k = string.IsNullOrEmpty(Hive) ? KeyPath : Hive + "\\" + KeyPath;
                return k;
            }
        }

        /// <summary>Testo della colonna Chiave/Regola: per il firewall l'id della regola.</summary>
        public string KeyLabel
        {
            get { return GroupId.StartsWith("fw-", StringComparison.Ordinal) && ValueName != null ? ValueName : FullKey; }
        }

        public string TargetText
        {
            get
            {
                string h = string.IsNullOrEmpty(Hive) ? "" : Hive + "\\";
                return Action == ActionKind.DeleteValue ? h + DeleteRoot + " -> [" + ValueName + "]" : h + DeleteRoot;
            }
        }
    }

    public sealed class ScanProgress
    {
        public string Section;
        public int Percent;
        public int Rows;
    }

    public sealed class ScanResult
    {
        public List<Row> Rows = new List<Row>();
        public int DeniedKeys;
        public TimeSpan Elapsed;
        public bool Cancelled;
    }
}
