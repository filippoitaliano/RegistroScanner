using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;

namespace RegistroScanner
{
    public sealed class MainForm : Form
    {
        readonly RowView _view = new RowView();
        readonly bool _elevated = Env.IsElevated();

        // comandi
        ToolStripButton _btnScan, _btnCancel, _btnCsv, _btnDelete, _btnSelect, _btnDeselect, _btnInvert, _btnGroup, _btnAdmin;
        // filtri
        TextBox _txtSearch;
        ComboBox _cmbTier, _cmbArea, _cmbGroup;
        Button _btnClear;
        System.Windows.Forms.Timer _debounce;
        // griglia
        DataGridView _grid;
        TextBox _details;
        Label _hint, _info;
        // stato
        ToolStripStatusLabel _stCounts, _stSel, _stMsg, _stDenied;
        ToolStripProgressBar _progress;

        CancellationTokenSource _cts, _deleteCts;
        bool _busy, _suppressFilter;
        int _denied;

        public MainForm()
        {
            Text = "Registro Scanner" + (_elevated ? " (Amministratore)" : "");
            AutoScaleMode = AutoScaleMode.Dpi;
            AutoScaleDimensions = new SizeF(96F, 96F);
            Font = SystemFonts.MessageBoxFont;
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(1360, 820);
            MinimumSize = new Size(900, 520);

            BuildUi();
            UpdateInfoLabel();
            RefreshAll();
        }

        // ---------------------------------------------------------------- costruzione UI

        void BuildUi()
        {
            var tool = new ToolStrip { GripStyle = ToolStripGripStyle.Hidden, Dock = DockStyle.Fill };
            _btnScan = Btn(tool, "Scansiona", (s, e) => StartScan());
            _btnCancel = Btn(tool, "Annulla scansione", (s, e) => { if (_cts != null) _cts.Cancel(); if (_deleteCts != null) _deleteCts.Cancel(); });
            _btnCsv = Btn(tool, "Esporta CSV", (s, e) => ExportCsv());
            _btnDelete = Btn(tool, "Elimina…", (s, e) => StartDelete());
            tool.Items.Add(new ToolStripSeparator());
            _btnSelect = Btn(tool, "Seleziona visibili", (s, e) => Bulk(_view.SelectVisible));
            _btnDeselect = Btn(tool, "Deseleziona visibili", (s, e) => Bulk(_view.DeselectVisible));
            _btnInvert = Btn(tool, "Inverti visibili", (s, e) => Bulk(_view.InvertVisible));
            _btnGroup = Btn(tool, "Seleziona gruppo", (s, e) => SelectCurrentGroup());
            tool.Items.Add(new ToolStripSeparator());
            _btnAdmin = Btn(tool, "Riavvia come amministratore", (s, e) => RelaunchAdmin());
            _btnAdmin.Visible = !_elevated;

            _info = new Label { AutoSize = true, Margin = new Padding(6, 4, 6, 2), MaximumSize = new Size(1800, 0) };

            var filter = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, WrapContents = true, Margin = new Padding(3, 0, 3, 3) };
            filter.Controls.Add(Cap("Cerca:"));
            _txtSearch = new TextBox { Width = 220, Margin = new Padding(3, 3, 12, 3) };
            filter.Controls.Add(_txtSearch);
            filter.Controls.Add(Cap("Livello:"));
            _cmbTier = Combo(filter, 150);
            filter.Controls.Add(Cap("Area:"));
            _cmbArea = Combo(filter, 160);
            filter.Controls.Add(Cap("Gruppo:"));
            _cmbGroup = Combo(filter, 260);
            _btnClear = new Button { Text = "Azzera filtri", AutoSize = true, Margin = new Padding(3, 2, 3, 2) };
            _btnClear.Click += (s, e) => ClearFilters();
            filter.Controls.Add(_btnClear);

            _debounce = new System.Windows.Forms.Timer { Interval = 250 };
            _debounce.Tick += (s, e) => { _debounce.Stop(); ApplyFilters(); };
            _txtSearch.TextChanged += (s, e) => { if (_suppressFilter) return; _debounce.Stop(); _debounce.Start(); };
            _cmbTier.SelectedIndexChanged += (s, e) => { if (!_suppressFilter) ApplyFilters(); };
            _cmbArea.SelectedIndexChanged += (s, e) => { if (!_suppressFilter) ApplyFilters(); };
            _cmbGroup.SelectedIndexChanged += (s, e) => { if (!_suppressFilter) ApplyFilters(); };

            BuildGrid();

            _hint = new Label
            {
                Text = "Premi «Scansiona» per cercare le voci orfane. La scansione è in sola lettura.",
                AutoSize = true, BackColor = SystemColors.Window, ForeColor = SystemColors.GrayText, Location = new Point(16, 48),
            };
            _grid.Controls.Add(_hint);

            _details = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill, BackColor = SystemColors.Window };

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, FixedPanel = FixedPanel.Panel2 };
            split.Panel1.Controls.Add(_grid);
            split.Panel2.Controls.Add(_details);

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = new Padding(0), Padding = new Padding(0) };
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.Controls.Add(tool, 0, 0);
            layout.Controls.Add(_info, 0, 1);
            layout.Controls.Add(filter, 0, 2);
            layout.Controls.Add(split, 0, 3);

            var status = new StatusStrip();
            _stCounts = new ToolStripStatusLabel();
            _stSel = new ToolStripStatusLabel { BorderSides = ToolStripStatusLabelBorderSides.Left };
            _stDenied = new ToolStripStatusLabel { BorderSides = ToolStripStatusLabelBorderSides.Left };
            _stMsg = new ToolStripStatusLabel { Spring = true, TextAlign = System.Drawing.ContentAlignment.MiddleLeft, BorderSides = ToolStripStatusLabelBorderSides.Left };
            _progress = new ToolStripProgressBar { Size = new Size(Dpi(160), Dpi(16)), Visible = false };
            status.Items.AddRange(new ToolStripItem[] { _stCounts, _stSel, _stDenied, _stMsg, _progress });

            Controls.Add(layout);
            Controls.Add(status);

            Shown += (s, e) =>
            {
                try { split.SplitterDistance = Math.Max(120, split.Height - (int)(150 * DeviceDpi / 96f)); } catch (Exception) { }
            };
            FormClosing += (s, e) =>
            {
                if (_deleteCts != null) { e.Cancel = true; SetMsg("Eliminazione in corso: usa Annulla o attendi la fine."); return; }
                if (_cts != null) _cts.Cancel();
            };
        }

        static ToolStripButton Btn(ToolStrip t, string text, EventHandler h)
        {
            var b = new ToolStripButton(text) { DisplayStyle = ToolStripItemDisplayStyle.Text };
            b.Click += h;
            t.Items.Add(b);
            return b;
        }

        static Label Cap(string text)
        {
            return new Label { Text = text, AutoSize = true, Margin = new Padding(3, 6, 2, 3) };
        }

        static ComboBox Combo(Control parent, int w)
        {
            var c = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = w, Margin = new Padding(3, 3, 12, 3) };
            c.Items.Add("Tutti");
            c.SelectedIndex = 0;
            parent.Controls.Add(c);
            return c;
        }

        void BuildGrid()
        {
            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                VirtualMode = true,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                AllowUserToOrderColumns = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = true,
                AutoGenerateColumns = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
                AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None,
                BackgroundColor = SystemColors.Window,
                BorderStyle = BorderStyle.None,
                ShowCellToolTips = true,
                ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
            };
            typeof(DataGridView).InvokeMember("DoubleBuffered", BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.SetProperty, null, _grid, new object[] { true });

            var chk = new DataGridViewCheckBoxColumn { HeaderText = "☑", Width = 34, SortMode = DataGridViewColumnSortMode.Programmatic, Resizable = DataGridViewTriState.False };
            chk.Width = Dpi(34);
            _grid.Columns.Add(chk);
            AddCol("Sicurezza %", 92, DataGridViewContentAlignment.MiddleRight);
            AddCol("Livello", 150);
            AddCol("Area", 150);
            AddCol("Gruppo", 260);
            AddCol("Chiave/Regola", 340);
            AddCol("Voce", 180);
            AddCol("Dettaglio", 320);
            AddCol("Azione", 105);
            AddCol("Stato", 140);

            _grid.CellValueNeeded += Grid_CellValueNeeded;
            _grid.CellFormatting += Grid_CellFormatting;
            _grid.CellPainting += Grid_CellPainting;
            _grid.CellMouseClick += Grid_CellMouseClick;
            _grid.CellMouseDown += Grid_CellMouseDown;
            _grid.ColumnHeaderMouseClick += Grid_ColumnHeaderMouseClick;
            _grid.CurrentCellChanged += (s, e) => ShowDetails();
            _grid.KeyDown += Grid_KeyDown;

            var menu = new ContextMenuStrip();
            menu.Items.Add("Spunta righe evidenziate", null, (s, e) => CheckHighlighted(true));
            menu.Items.Add("Togli spunta alle evidenziate", null, (s, e) => CheckHighlighted(false));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Seleziona visibili", null, (s, e) => Bulk(_view.SelectVisible));
            menu.Items.Add("Deseleziona visibili", null, (s, e) => Bulk(_view.DeselectVisible));
            menu.Items.Add("Inverti visibili", null, (s, e) => Bulk(_view.InvertVisible));
            menu.Items.Add("Seleziona gruppo", null, (s, e) => SelectCurrentGroup());
            _grid.ContextMenuStrip = menu;
        }

        int Dpi(int v) { return v * DeviceDpi / 96; }

        void AddCol(string header, int width, DataGridViewContentAlignment? align = null)
        {
            var c = new DataGridViewTextBoxColumn { HeaderText = header, Width = Dpi(width), SortMode = DataGridViewColumnSortMode.Programmatic };
            if (align != null) c.DefaultCellStyle.Alignment = align.Value;
            _grid.Columns.Add(c);
        }

        // ---------------------------------------------------------------- griglia

        void Grid_CellValueNeeded(object sender, DataGridViewCellValueEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _view.Visible.Count) return;
            Row r = _view.Visible[e.RowIndex];
            switch (e.ColumnIndex)
            {
                case RowView.ColCheck: e.Value = r.Checked; break;
                case RowView.ColConf: e.Value = r.Confidence.HasValue ? r.Confidence.Value.ToString() : "—"; break;
                case RowView.ColTier: e.Value = r.Tier; break;
                case RowView.ColArea: e.Value = r.Area; break;
                case RowView.ColGroup: e.Value = r.Group; break;
                case RowView.ColKey: e.Value = r.KeyLabel; break;
                case RowView.ColItem: e.Value = r.Item; break;
                case RowView.ColDetail: e.Value = r.Detail; break;
                case RowView.ColAction: e.Value = r.ActionText; break;
                case RowView.ColStatus: e.Value = r.Status; break;
            }
        }

        void Grid_CellFormatting(object sender, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _view.Visible.Count) return;
            if (e.ColumnIndex != RowView.ColConf) return;
            e.CellStyle.ForeColor = TierColor(_view.Visible[e.RowIndex].Tier);
            e.CellStyle.SelectionForeColor = SystemColors.HighlightText;
        }

        static Color TierColor(string tier)
        {
            switch (tier)
            {
                case Tiers.Pulibile: return Color.DarkGreen;
                case Tiers.Probabile: return Color.Teal;
                case Tiers.Lasciare: return Color.Chocolate;
                case Tiers.NonToccare: return Color.Firebrick;
                default: return Color.DimGray;
            }
        }

        // Le righe non eliminabili mostrano la casella disabilitata.
        void Grid_CellPainting(object sender, DataGridViewCellPaintingEventArgs e)
        {
            if (e.ColumnIndex != RowView.ColCheck || e.RowIndex < 0 || e.RowIndex >= _view.Visible.Count) return;
            if (_view.Visible[e.RowIndex].Deletable) return;
            e.PaintBackground(e.CellBounds, (e.State & DataGridViewElementStates.Selected) != 0);
            Size sz = CheckBoxRenderer.GetGlyphSize(e.Graphics, CheckBoxState.UncheckedDisabled);
            var pt = new Point(e.CellBounds.Left + (e.CellBounds.Width - sz.Width) / 2, e.CellBounds.Top + (e.CellBounds.Height - sz.Height) / 2);
            CheckBoxRenderer.DrawCheckBox(e.Graphics, pt, CheckBoxState.UncheckedDisabled);
            e.Handled = true;
        }

        void Grid_CellMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left || e.RowIndex < 0 || e.ColumnIndex != RowView.ColCheck || e.RowIndex >= _view.Visible.Count) return;
            Row r = _view.Visible[e.RowIndex];
            if (!r.Deletable) { SetMsg("Questa voce non è eliminabile (" + r.Tier + ")."); return; }
            r.Checked = !r.Checked;
            _grid.InvalidateRow(e.RowIndex);
            UpdateCounts();
        }

        void Grid_CellMouseDown(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Right || e.RowIndex < 0 || e.RowIndex >= _grid.RowCount) return;
            if (!_grid.Rows[e.RowIndex].Selected)
            {
                _grid.ClearSelection();
                _grid.Rows[e.RowIndex].Selected = true;
            }
            int col = e.ColumnIndex >= 0 ? e.ColumnIndex : 0;
            try { _grid.CurrentCell = _grid[col, e.RowIndex]; _grid.Rows[e.RowIndex].Selected = true; } catch (Exception) { }
        }

        void Grid_ColumnHeaderMouseClick(object sender, DataGridViewCellMouseEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            if (_view.SortColumn == e.ColumnIndex) _view.SortAscending = !_view.SortAscending;
            else { _view.SortColumn = e.ColumnIndex; _view.SortAscending = e.ColumnIndex != RowView.ColConf; }
            foreach (DataGridViewColumn c in _grid.Columns)
                c.HeaderCell.SortGlyphDirection = SortOrder.None;
            _grid.Columns[e.ColumnIndex].HeaderCell.SortGlyphDirection = _view.SortAscending ? SortOrder.Ascending : SortOrder.Descending;
            _view.Sort();
            _grid.ClearSelection();
            _grid.Invalidate();
            ShowDetails();
        }

        void Grid_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Space)
            {
                e.SuppressKeyPress = true;
                e.Handled = true;
                var rows = HighlightedRows();
                if (rows.Count == 0) return;
                bool allChecked = rows.Where(r => r.Deletable).All(r => r.Checked);
                CheckHighlighted(!allChecked);
            }
        }

        List<Row> HighlightedRows()
        {
            var list = new List<Row>();
            foreach (DataGridViewRow gr in _grid.SelectedRows)
                if (gr.Index >= 0 && gr.Index < _view.Visible.Count) list.Add(_view.Visible[gr.Index]);
            return list;
        }

        void CheckHighlighted(bool value)
        {
            if (FlushPendingFilter()) { SetMsg("Filtro aggiornato: evidenzia di nuovo le righe."); return; }
            var rows = HighlightedRows();
            _view.LastSkippedRisky = 0;
            Report(SetRows(rows, value));
        }

        /// <summary>Applica un filtro digitato ma non ancora attivo. Vero se c'era.</summary>
        bool FlushPendingFilter()
        {
            if (!_debounce.Enabled) return false;
            _debounce.Stop();
            ApplyFilters();
            return true;
        }

        void Bulk(Func<int> command)
        {
            FlushPendingFilter();
            Report(command());
        }

        static int SetRows(List<Row> rows, bool value)
        {
            int skipped = 0;
            foreach (Row r in rows)
            {
                if (!r.Deletable) { skipped++; continue; }
                r.Checked = value;
            }
            return skipped;
        }

        void SelectCurrentGroup()
        {
            FlushPendingFilter();
            Row r = CurrentRow();
            if (r == null) { SetMsg("Nessuna riga corrente."); return; }
            Report(_view.SelectGroupVisible(r.Group));
        }

        Row CurrentRow()
        {
            if (_grid.CurrentCell == null) return null;
            int i = _grid.CurrentCell.RowIndex;
            return i >= 0 && i < _view.Visible.Count ? _view.Visible[i] : null;
        }

        void Report(int skipped)
        {
            _grid.Invalidate();
            UpdateCounts();
            string m = skipped > 0 ? skipped + " voci saltate perché non eliminabili." : "";
            if (_view.LastSkippedRisky > 0)
                m = (m + " " + _view.LastSkippedRisky + " voci \"Meglio lasciare\" non toccate: filtra su quel livello o spuntale una per una.").Trim();
            SetMsg(m);
        }

        void ShowDetails()
        {
            Row r = CurrentRow();
            if (r == null) { _details.Text = ""; return; }
            string text = "Motivo: " + r.Reason + "\r\nCome procedere: " + r.How + "\r\nChiave: " + r.FullKey;
            if (r.ValueName != null) text += "\r\nValore: " + r.ValueName;
            if (r.Deletable) text += "\r\nDestinazione dell'eliminazione: " + r.TargetText;
            else text += "\r\nNon eliminabile da qui.";
            if (!string.IsNullOrEmpty(r.ProbePath)) text += "\r\nPercorso assente: " + r.ProbePath;
            if (!string.IsNullOrEmpty(r.Detail)) text += "\r\nDettaglio: " + r.Detail;
            _details.Text = text;
        }

        // ---------------------------------------------------------------- filtri

        void ApplyFilters()
        {
            _view.Text = _txtSearch.Text;
            _view.Tier = Sel(_cmbTier);
            _view.Area = Sel(_cmbArea);
            _view.Group = Sel(_cmbGroup);
            _view.Apply();
            RefreshGrid();
        }

        static string Sel(ComboBox c)
        {
            return c.SelectedIndex <= 0 ? null : c.SelectedItem as string;
        }

        void ClearFilters()
        {
            _suppressFilter = true;
            _txtSearch.Text = "";
            _cmbTier.SelectedIndex = 0;
            _cmbArea.SelectedIndex = 0;
            _cmbGroup.SelectedIndex = 0;
            _suppressFilter = false;
            ApplyFilters();
        }

        void FillFilterLists()
        {
            _suppressFilter = true;
            FillCombo(_cmbTier, Tiers.All.Where(t => _view.All.Any(r => r.Tier == t)));
            FillCombo(_cmbArea, _view.All.Select(r => r.Area).Distinct().OrderBy(x => x, StringComparer.CurrentCultureIgnoreCase));
            FillCombo(_cmbGroup, _view.All.Select(r => r.Group).Distinct().OrderBy(x => x, StringComparer.CurrentCultureIgnoreCase));
            _suppressFilter = false;
        }

        static void FillCombo(ComboBox c, IEnumerable<string> items)
        {
            string prev = c.SelectedItem as string;
            c.BeginUpdate();
            c.Items.Clear();
            c.Items.Add("Tutti");
            foreach (string s in items) c.Items.Add(s);
            c.EndUpdate();
            int i = prev == null ? 0 : c.Items.IndexOf(prev);
            c.SelectedIndex = i < 0 ? 0 : i;
        }

        void RefreshGrid()
        {
            _grid.SuspendLayout();
            _grid.RowCount = 0;
            _grid.RowCount = _view.Visible.Count;
            _grid.ResumeLayout();
            _grid.ClearSelection();
            _grid.Invalidate();
            ShowDetails();
            UpdateCounts();
        }

        void RefreshAll()
        {
            _hint.Visible = _view.All.Count == 0 && !_busy;
            RefreshGrid();
            UpdateButtons();
        }

        void UpdateCounts()
        {
            _stCounts.Text = "Totale: " + _view.All.Count + "   Visibili: " + _view.Visible.Count;
            int vis = _view.CheckedVisible, hid = _view.CheckedHidden;
            _stSel.Text = "Selezionate: " + vis + " visibili" + (hid > 0 ? "   " + hid + " selezionate nascoste dai filtri: non verranno eliminate" : "");
            _stSel.ForeColor = hid > 0 ? Color.Firebrick : SystemColors.ControlText;
            _stDenied.Text = "Chiavi non leggibili: " + _denied;
        }

        void UpdateButtons()
        {
            bool has = _view.All.Count > 0;
            _btnScan.Enabled = !_busy;
            _btnCancel.Enabled = _busy;
            _btnCancel.Text = _deleteCts != null ? "Annulla eliminazione" : "Annulla scansione";
            _btnAdmin.Enabled = !_busy;
            _btnCsv.Enabled = !_busy && _view.Visible.Count > 0;
            _btnDelete.Enabled = !_busy && has;
            _btnSelect.Enabled = _btnDeselect.Enabled = _btnInvert.Enabled = _btnGroup.Enabled = !_busy && has;
            _grid.Enabled = !_busy;
            _txtSearch.Enabled = _cmbTier.Enabled = _cmbArea.Enabled = _cmbGroup.Enabled = _btnClear.Enabled = !_busy;
        }

        void SetMsg(string m) { _stMsg.Text = m ?? ""; }

        void UpdateInfoLabel()
        {
            if (!_elevated)
            {
                _info.Text = "Non amministratore: alcune chiavi non sono visibili e le voci HKLM non sono eliminabili.";
                _info.ForeColor = SystemColors.ControlText;
                if (Env.RunningAsOtherUser())
                {
                    _info.Text += " ATTENZIONE: account diverso dall'utente della sessione: le voci HKCU non verranno eliminate.";
                    _info.ForeColor = Color.Firebrick;
                }
                return;
            }
            string me = Environment.UserName, inter = Env.InteractiveUser();
            string t = "Account corrente: " + me + ". HKCU è il profilo di questo account elevato.";
            _info.ForeColor = SystemColors.ControlText;
            if (string.IsNullOrEmpty(inter)) t += " Non è stato possibile determinare l'utente della sessione: controlla che HKCU sia il profilo giusto.";
            else if (!inter.Equals(me, StringComparison.OrdinalIgnoreCase))
            {
                t = "ATTENZIONE: l'account elevato (" + me + ") è diverso dall'utente della sessione (" + inter + "). HKCU appartiene a " + me + ", non a " + inter + ": le voci HKCU che vedi sono di un altro utente e non verranno eliminate. Anche la classificazione delle voci HKLM è meno affidabile.";
                _info.ForeColor = Color.Firebrick;
            }
            _info.Text = t;
        }

        // ---------------------------------------------------------------- scansione

        async void StartScan() { await ScanAsync(); }

        async Task ScanAsync()
        {
            if (_busy) return;
            foreach (Row r in _view.All) r.Checked = false;
            _busy = true;
            _hint.Visible = false;
            _cts = new CancellationTokenSource();
            _view.All = new List<Row>();
            _view.Visible = new List<Row>();
            RefreshGrid();
            UpdateButtons();
            _progress.Visible = true;
            _progress.Value = 0;
            var ct = _cts.Token;
            var ui = SynchronizationContext.Current;

            ScanResult res = null;
            Exception err = null;
            try
            {
                res = await Task.Run(() => new Scanner(ct, p => ui.Post(_ =>
                {
                    if (IsDisposed) return;
                    _progress.Value = Math.Min(100, Math.Max(0, p.Percent));
                    SetMsg(p.Section + "…  (voci: " + p.Rows + ")");
                }, null)).Run());
            }
            catch (Exception ex) { err = ex; }
            if (IsDisposed) return;

            _busy = false;
            _cts = null;
            _progress.Visible = false;
            if (err != null) { SetMsg("Errore di scansione: " + err.Message); RefreshAll(); return; }

            _denied = res.DeniedKeys;
            _view.All = res.Rows;
            FillFilterLists();
            ApplyFilters();
            RefreshAll();
            SetMsg((res.Cancelled ? "Scansione annullata: risultati parziali. " : "Scansione completata. ") + res.Rows.Count + " voci in " + res.Elapsed.TotalSeconds.ToString("0") + " s.");
        }

        // ---------------------------------------------------------------- CSV

        void ExportCsv()
        {
            FlushPendingFilter();
            using (var d = new SaveFileDialog { Title = "Esporta CSV", Filter = "File CSV (*.csv)|*.csv|Tutti i file (*.*)|*.*", FileName = "registro-scanner-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".csv", OverwritePrompt = true })
            {
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    CsvExport.Write(d.FileName, _view.Visible, false);
                    SetMsg("Esportate " + _view.Visible.Count + " righe in " + d.FileName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Esportazione non riuscita: " + ex.Message, "Registro Scanner", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
        }

        // ---------------------------------------------------------------- eliminazione

        async void StartDelete()
        {
            if (_busy) return;
            FlushPendingFilter();
            List<Row> eligible = _view.Eligible();
            if (eligible.Count == 0)
            {
                MessageBox.Show(this, "Nessuna voce selezionata tra quelle visibili ed eliminabili.", "Registro Scanner", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            int excluded, excludedHkcu;
            bool otherUser = Env.RunningAsOtherUser();
            eligible = RowView.ForAccount(eligible, _elevated, otherUser, out excluded, out excludedHkcu);
            if (eligible.Count == 0)
            {
                MessageBox.Show(this, "Nessuna voce eliminabile con questo account: " + excluded + " voci HKLM richiedono l'amministratore, " + excludedHkcu + " voci HKCU sono di un altro profilo.", "Registro Scanner", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents", "RegistroScanner");
            string backup = Path.Combine(dir, "backup-" + stamp + ".reg");
            string logFile = Path.Combine(dir, "backup-" + stamp + ".txt");

            using (var c = new ConfirmForm(eligible, excluded, excludedHkcu, otherUser, backup))
            {
                if (c.ShowDialog(this) != DialogResult.OK) return;
            }

            _busy = true;
            _deleteCts = new CancellationTokenSource();
            var cancelToken = _deleteCts.Token;
            var allRows = _view.All.ToList();
            UpdateButtons();
            _progress.Visible = true;
            _progress.Value = 0;
            var ui = SynchronizationContext.Current;
            DeleteOutcome outcome = null;
            Exception err = null;
            List<Row> list = eligible;
            try
            {
                outcome = await Task.Run(() => DeleteEngine.Run(list, new DeleteOptions
                {
                    BackupPath = backup,
                    LogPath = logFile,
                    AllRows = allRows,
                    Cancel = cancelToken,
                    Progress = (done, tot, item) => ui.Post(_ =>
                    {
                        if (IsDisposed) return;
                        _progress.Value = Math.Min(100, done * 100 / Math.Max(1, tot));
                        SetMsg("Eliminazione " + done + "/" + tot + ": " + item);
                    }, null),
                }));
            }
            catch (Exception ex) { err = ex; }

            _busy = false;
            _deleteCts = null;
            _progress.Visible = false;
            if (err != null)
            {
                MessageBox.Show(this, "Eliminazione interrotta: " + err.Message, "Registro Scanner", MessageBoxButtons.OK, MessageBoxIcon.Error);
                RefreshAll();
                return;
            }

            var removed = new HashSet<Row>(outcome.Removed);
            _view.All = _view.All.Where(r => !removed.Contains(r)).ToList();
            foreach (Row r in eligible) if (!removed.Contains(r)) r.Checked = false;
            HashSet<Row> hiddenBefore = _view.HiddenChecked();
            FillFilterLists();
            ApplyFilters();
            int revealed = _view.UncheckRevealed(hiddenBefore);
            RefreshAll();
            SetMsg("Eliminate " + outcome.Deleted + ", in parte " + outcome.Partial + ", saltate " + outcome.Skipped + ", errori " + outcome.Errors + "."
                + (revealed > 0 ? " Un filtro si è azzerato: tolta la spunta a " + revealed + " voci prima nascoste." : ""));
            using (var rf = new ResultForm(outcome, eligible)) rf.ShowDialog(this);
        }

        // ---------------------------------------------------------------- prova della UI (solo lettura, mai eliminazioni)

        /// <summary>Esercita griglia, filtri, ordinamento, selezione, CSV e dialogo di riepilogo senza alcun clic e senza chiamare il motore di eliminazione.</summary>
        public void EnableUiSmoke(string outDir)
        {
            Shown += async (s, e) =>
            {
                var log = new List<string>();
                try
                {
                    Snap(outDir, "1-vuota.png", this);
                    await ScanAsync();
                    log.Add("righe=" + _view.All.Count + " visibili=" + _view.Visible.Count + " griglia=" + _grid.RowCount);
                    Application.DoEvents();
                    Snap(outDir, "2-scansione.png", this);

                    _cmbTier.SelectedItem = Tiers.Pulibile;
                    log.Add("filtro livello: visibili=" + _view.Visible.Count + " griglia=" + _grid.RowCount);
                    Report(_view.SelectVisible());
                    log.Add("seleziona visibili: spuntate=" + _view.CheckedVisible + " msg=" + _stMsg.Text);
                    Application.DoEvents();
                    Snap(outDir, "3-filtro-selezione.png", this);

                    _cmbTier.SelectedItem = Tiers.NonToccare;
                    log.Add("altro filtro: spuntate visibili=" + _view.CheckedVisible + " nascoste=" + _view.CheckedHidden + " stato=" + _stSel.Text + " eleggibili=" + _view.Eligible().Count);
                    Report(_view.SelectVisible());
                    log.Add("Non toccare: spuntate=" + _view.CheckedVisible + " msg=" + _stMsg.Text);

                    _cmbTier.SelectedIndex = 0;
                    foreach (int col in new[] { RowView.ColConf, RowView.ColConf, RowView.ColGroup, RowView.ColKey, RowView.ColStatus, RowView.ColCheck })
                        Grid_ColumnHeaderMouseClick(_grid, new DataGridViewCellMouseEventArgs(col, -1, 0, 0, new MouseEventArgs(MouseButtons.Left, 1, 0, 0, 0)));
                    log.Add("ordinamento ok, glifo=" + _grid.Columns[RowView.ColCheck].HeaderCell.SortGlyphDirection);

                    _grid.CurrentCell = _grid[RowView.ColKey, 0];
                    log.Add("dettagli: " + (_details.TextLength > 0));
                    var el = _view.Eligible();
                    using (var c = new ConfirmForm(el, 5, 3, true, @"C:\esempio\backup.reg"))
                    {
                        c.Show(this);
                        Application.DoEvents();
                        Snap(outDir, "4-riepilogo.png", c);
                        log.Add("riepilogo: accept=" + ((Button)c.AcceptButton).Text + " cancel=" + ((Button)c.CancelButton).Text);
                        c.Close();
                    }
                    _view.DeselectVisible();
                    log.Add("fine: spuntate=" + _view.All.Count(r => r.Checked));
                }
                catch (Exception ex) { log.Add("ERRORE " + ex); }
                File.WriteAllLines(Path.Combine(outDir, "ui-smoke.txt"), log);
                Close();
            };
        }

        static void Snap(string dir, string name, Control c)
        {
            using (var b = new Bitmap(c.Width, c.Height))
            {
                c.DrawToBitmap(b, new Rectangle(0, 0, c.Width, c.Height));
                b.Save(Path.Combine(dir, name), System.Drawing.Imaging.ImageFormat.Png);
            }
        }

        // ---------------------------------------------------------------- elevazione

        void RelaunchAdmin()
        {
            if (_busy) return;
            int chk = _view.All.Count(r => r.Checked);
            if (chk > 0 && MessageBox.Show(this, "Il riavvio perde le " + chk + " voci spuntate e i risultati della scansione. Continuare?", "Registro Scanner", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
            try
            {
                Process.Start(new ProcessStartInfo(Application.ExecutablePath) { UseShellExecute = true, Verb = "runas" });
                Close();
            }
            catch (Win32Exception) { SetMsg("Elevazione annullata."); }
            catch (Exception ex) { SetMsg("Riavvio non riuscito: " + ex.Message); }
        }
    }
}
