using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace RegistroScanner
{
    /// <summary>Riepilogo di conferma prima dell'eliminazione.</summary>
    public sealed class ConfirmForm : Form
    {
        public ConfirmForm(IList<Row> rows, int excludedHklm, int excludedHkcu, bool otherUser, string backupPath)
        {
            Text = "Conferma eliminazione";
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = SystemFonts.MessageBoxFont;
            StartPosition = FormStartPosition.CenterParent;
            Size = new Size(900, 700);
            MinimumSize = new Size(640, 480);
            ShowInTaskbar = false;
            MinimizeBox = false;
            KeyPreview = true;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(8) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 45));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 55));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            int keys = rows.Count(r => r.Action == ActionKind.DeleteKey), vals = rows.Count - keys;
            var tierText = string.Join("   ", Tiers.All.Select(t => new { t, n = rows.Count(r => r.Tier == t) }).Where(x => x.n > 0).Select(x => x.t + ": " + x.n));
            var hiveText = string.Join("   ", rows.GroupBy(r => r.Hive).OrderBy(g => g.Key).Select(g => g.Key + ": " + g.Count()));

            var lines = new List<string>
            {
                "Voci da eliminare: " + rows.Count + "   (chiavi: " + keys + ", valori: " + vals + ")",
                "Per livello:  " + tierText,
                "Per hive:  " + hiveText,
                "Backup:  " + backupPath,
            };
            var summary = new Label { AutoSize = true, Text = string.Join("\r\n", lines), Margin = new Padding(0, 0, 0, 6) };
            layout.Controls.Add(summary, 0, 0);

            var warn = new List<string>();
            if (excludedHklm > 0) warn.Add("Non amministratore: " + excludedHklm + " voci HKLM verranno saltate e sono già escluse da questo elenco.");
            if (excludedHkcu > 0) warn.Add("Account diverso dall'utente della sessione: " + excludedHkcu + " voci HKCU sono di un altro profilo e sono state escluse da questo elenco.");
            if (otherUser && rows.Any(r => r.Hive == "HKLM")) warn.Add("Account diverso dall'utente della sessione: anche la classificazione delle voci HKLM è meno affidabile, perché i programmi rilevati vengono dal profilo sbagliato.");
            if (rows.Any(r => r.Tier == Tiers.Lasciare)) warn.Add("Sono incluse voci \"Meglio lasciare\" (" + rows.Count(r => r.Tier == Tiers.Lasciare) + "): la loro eliminazione è sconsigliata.");
            if (rows.Any(r => r.GroupId.StartsWith("un-", StringComparison.Ordinal))) warn.Add("Sono incluse voci di disinstallazione: i programmi non compariranno più in Installazione app.");
            if (rows.Any(r => r.GroupId.StartsWith("ve-", StringComparison.Ordinal))) warn.Add("Sono incluse chiavi di produttori: si perdono le impostazioni salvate (nel backup restano recuperabili).");
            if (rows.Any(r => r.GroupId.StartsWith("fw-", StringComparison.Ordinal))) warn.Add("Le regole firewall hanno effetto dopo il ricaricamento del servizio o il riavvio.");
            warn.Add("Il file .reg non conserva ACL, nome di classe e volatilità delle chiavi.");
            var warnLabel = new Label { AutoSize = true, ForeColor = Color.Firebrick, Text = string.Join("\r\n", warn), Margin = new Padding(0, 0, 0, 6) };
            layout.Controls.Add(warnLabel, 0, 1);

            var groups = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, GridLines = true, HeaderStyle = ColumnHeaderStyle.Nonclickable };
            groups.Columns.Add("Gruppo", 540 * DeviceDpi / 96);
            groups.Columns.Add("Voci", 70 * DeviceDpi / 96, HorizontalAlignment.Right);
            groups.Columns.Add("Sicurezza minima", 150 * DeviceDpi / 96, HorizontalAlignment.Right);
            foreach (var g in rows.GroupBy(r => r.Group).OrderBy(g => g.Min(r => r.Confidence ?? 0)))
            {
                var it = new ListViewItem(g.Key);
                it.SubItems.Add(g.Count().ToString());
                it.SubItems.Add(g.Min(r => r.Confidence ?? 0) + "%");
                groups.Items.Add(it);
            }
            layout.Controls.Add(groups, 0, 2);

            layout.Controls.Add(new Label { AutoSize = true, Text = "Destinazioni esatte:", Margin = new Padding(0, 6, 0, 2) }, 0, 3);
            var list = new ListBox { Dock = DockStyle.Fill, HorizontalScrollbar = true, IntegralHeight = false };
            list.BeginUpdate();
            list.Items.AddRange(rows.Select(r => (object)r.TargetText).ToArray());
            list.EndUpdate();
            layout.Controls.Add(list, 0, 4);

            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            var cancel = new Button { Text = "Annulla", AutoSize = true, DialogResult = DialogResult.Cancel };
            var ok = new Button { Text = "Elimina " + rows.Count + " voci", AutoSize = true, DialogResult = DialogResult.OK };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons, 0, 5);

            Controls.Add(layout);
            AcceptButton = cancel;
            CancelButton = cancel;
            ActiveControl = cancel;
        }
    }

    public sealed class ResultForm : Form
    {
        public ResultForm(DeleteOutcome o, IList<Row> rows)
        {
            Text = "Esito eliminazione";
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = SystemFonts.MessageBoxFont;
            StartPosition = FormStartPosition.CenterParent;
            Size = new Size(760, 480);
            ShowInTaskbar = false;
            MinimizeBox = false;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(8) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            layout.Controls.Add(new Label
            {
                AutoSize = true,
                Text = "Eliminate: " + o.Deleted + "    Eliminate in parte: " + o.Partial + "    Saltate: " + o.Skipped + "    Errori: " + o.Errors + "\r\nBackup: " + o.BackupPath + "\r\nRegistro: " + (o.LogPath ?? "(non scritto)")
                    + (o.FirewallPending > 0 ? "\r\nRegole firewall rimosse dal registro: " + o.FirewallPending + ". Restano attive fino al riavvio del servizio firewall o del PC." : "")
                    + (o.Partial > 0 ? "\r\nATTENZIONE: voci eliminate in parte. Ripristinale importando il file di backup." : "")
                    + (o.Warning != null ? "\r\n" + o.Warning : ""),
                Margin = new Padding(0, 0, 0, 6)
            }, 0, 0);

            var det = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill };
            det.Text = string.Join("\r\n", rows.Where(r => r.Status != "Eliminata").Select(r => r.Status + "  ::  " + r.TargetText));
            if (det.TextLength == 0) det.Text = "Tutte le voci sono state eliminate.";
            layout.Controls.Add(det, 0, 1);

            var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, Margin = new Padding(0, 6, 0, 0) };
            var close = new Button { Text = "Chiudi", AutoSize = true, DialogResult = DialogResult.OK };
            var open = new Button { Text = "Apri cartella backup", AutoSize = true };
            open.Click += (s, e) =>
            {
                try { Process.Start("explorer.exe", "\"" + Path.GetDirectoryName(o.BackupPath) + "\""); }
                catch (Exception ex) { MessageBox.Show(this, ex.Message, "Registro Scanner", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };
            buttons.Controls.Add(close);
            buttons.Controls.Add(open);
            layout.Controls.Add(buttons, 0, 2);

            Controls.Add(layout);
            AcceptButton = close;
            CancelButton = close;
        }
    }
}
