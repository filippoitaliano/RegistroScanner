using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace RegistroScanner
{
    /// <summary>
    /// Autotest: guardia, serializzatore e motore di eliminazione SOLO su HKCU\Software\__RegistroScannerSelfTest.
    /// I percorsi vietati sono verificati tramite la guardia, mai tentati.
    /// </summary>
    public static class SelfTest
    {
        const string Sandbox = @"Software\__RegistroScannerSelfTest";

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegSetValueExW(SafeRegistryHandle h, string name, int reserved, uint type, byte[] data, int len);

        sealed class T
        {
            public int Pass, Fail;
            public StringBuilder Out = new StringBuilder();
            public void Check(string name, bool ok, string detail = null)
            {
                if (ok) Pass++; else Fail++;
                Out.AppendLine((ok ? "PASS " : "FAIL ") + name + (detail != null && !ok ? " :: " + detail : ""));
            }
        }

        public static int Run(string resultFile)
        {
            var t = new T();
            string temp = Path.Combine(Path.GetTempPath(), "RegistroScanner-selftest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                TestTiers(t);
                TestGuard(t);
                TestCsv(t);
                TestSelection(t);
                TestProbe(t, temp);
                TestVendorRules(t);
                TestReviewUnits(t, temp);
                TestCoreAndUninstall(t);
                TestSandbox(t, temp);
                TestEngineReview(t, temp);
                TestInjection(t, temp);
                TestRealScan(t);
            }
            catch (Exception ex)
            {
                t.Check("eccezione imprevista", false, ex.ToString());
            }
            finally
            {
                bool gone = RemoveSandbox();
                t.Check("sandbox rimossa alla fine", gone);
                try { Directory.Delete(temp, true); } catch (Exception) { }
            }
            t.Out.AppendLine("TOTALE PASS=" + t.Pass + " FAIL=" + t.Fail);
            File.WriteAllText(resultFile, t.Out.ToString(), new UTF8Encoding(true));
            return t.Fail == 0 ? 0 : 1;
        }

        static RegistryKey Hkcu() { return RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64); }

        static bool RemoveSandbox()
        {
            using (RegistryKey h = Hkcu())
            {
                using (RegistryKey probe = h.OpenSubKey(Sandbox, false))
                    if (probe == null) return true;
                RemoveLinks(h);
                UnlockTree(h, Sandbox);
                h.DeleteSubKeyTree(Sandbox, false);
                using (RegistryKey k = h.OpenSubKey(Sandbox, false)) return k == null;
            }
        }

        // ---------------------------------------------------------------- unità

        static void TestTiers(T t)
        {
            t.Check("livello 90 Pulibile", Tiers.Of(90) == Tiers.Pulibile);
            t.Check("livello 89 Probabilmente", Tiers.Of(89) == Tiers.Probabile);
            t.Check("livello 70 Probabilmente", Tiers.Of(70) == Tiers.Probabile);
            t.Check("livello 69 Meglio lasciare", Tiers.Of(69) == Tiers.Lasciare);
            t.Check("livello 39 Non toccare", Tiers.Of(39) == Tiers.NonToccare);
            t.Check("livello null Falso positivo", Tiers.Of(null) == Tiers.Falso);
            t.Check("Non toccare non eliminabile", !Tiers.IsDeletable(Tiers.NonToccare));
            t.Check("Falso positivo non eliminabile", !Tiers.IsDeletable(Tiers.Falso));
        }

        static void TestGuard(T t)
        {
            string why;
            var forbiddenKeys = new[]
            {
                new[]{"HKLM","SOFTWARE"}, new[]{"HKCU","Software"}, new[]{"HKLM","SOFTWARE\\Microsoft"}, new[]{"HKCU","Software\\Microsoft"},
                new[]{"HKLM","SOFTWARE\\Microsoft\\Windows"}, new[]{"HKLM","SOFTWARE\\Microsoft\\Windows NT"}, new[]{"HKLM","SOFTWARE\\Microsoft\\Windows Defender"},
                new[]{"HKLM","SOFTWARE\\Microsoft\\Windows\\CurrentVersion"}, new[]{"HKLM","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"},
                new[]{"HKLM","SOFTWARE\\Classes"}, new[]{"HKCU","Software\\Classes"}, new[]{"HKLM","SOFTWARE\\Classes\\CLSID"}, new[]{"HKLM","SOFTWARE\\Classes\\TypeLib"},
                new[]{"HKLM","SOFTWARE\\Classes\\Interface"}, new[]{"HKCU","Software\\Classes\\CLSID"}, new[]{"HKLM","SOFTWARE\\WOW6432Node"}, new[]{"HKLM","SOFTWARE\\WOW6432Node\\Microsoft"},
                new[]{"HKLM","SOFTWARE\\WOW6432Node\\Classes\\CLSID"}, new[]{"HKLM","SOFTWARE\\Policies"}, new[]{"HKCU","Software\\Policies"},
                new[]{"HKLM","SYSTEM"}, new[]{"HKLM","SYSTEM\\CurrentControlSet"}, new[]{"HKLM","SYSTEM\\CurrentControlSet\\Services\\Foo"},
                new[]{"HKLM","SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"},
                new[]{"HKLM","SAM\\SAM"}, new[]{"HKLM","HARDWARE\\DESCRIPTION"}, new[]{"HKCR","foo\\bar"}, new[]{"HKU","S-1-5-18\\Software\\X"}, new[]{"","Software\\X"},
                new[]{"HKCU","Environment"}, new[]{"HKCU","Software\\"}, new[]{"HKCU","Software\\..\\Foo"}, new[]{"HKCU","\\Software\\Foo"}, new[]{"HKCU",""},
                new[]{"HKLM","SOFTWARE\\Classes\\*"}, new[]{"HKLM","SOFTWARE\\Classes\\Directory"}, new[]{"HKLM","SOFTWARE\\Classes\\Drive"}, new[]{"HKLM","SOFTWARE\\Classes\\Folder"},
                new[]{"HKLM","SOFTWARE\\Classes\\exefile"}, new[]{"HKLM","SOFTWARE\\Classes\\batfile"}, new[]{"HKCU","Software\\Classes\\.exe"},
            };
            foreach (var f in forbiddenKeys)
                t.Check("guardia rifiuta chiave " + f[0] + "\\" + f[1], !DeleteGuard.Check(f[0], f[1], ActionKind.DeleteKey, null, out why));

            t.Check("guardia rifiuta valore SYSTEM generico", !DeleteGuard.Check("HKLM", @"SYSTEM\CurrentControlSet\Services\Foo", ActionKind.DeleteValue, "ImagePath", out why));
            t.Check("guardia rifiuta valore predefinito", !DeleteGuard.Check("HKCU", @"Software\Foo", ActionKind.DeleteValue, "", out why));
            t.Check("guardia rifiuta valore null", !DeleteGuard.Check("HKCU", @"Software\Foo", ActionKind.DeleteValue, null, out why));
            t.Check("guardia rifiuta valore Winlogon", !DeleteGuard.Check("HKLM", @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", ActionKind.DeleteValue, "Shell", out why));
            t.Check("guardia rifiuta firewall senza nome", !DeleteGuard.Check("HKLM", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", ActionKind.DeleteValue, "", out why));

            var allowed = new[]
            {
                new[]{"HKCU","Software\\Foo"}, new[]{"HKLM","SOFTWARE\\Foo"}, new[]{"HKLM","SOFTWARE\\WOW6432Node\\Foo"}, new[]{"HKCU","Software\\Classes\\contoso"},
                new[]{"HKLM","SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}"}, new[]{"HKLM","SOFTWARE\\Classes\\TypeLib\\{00000000-0000-0000-0000-000000000000}\\1.0"},
                new[]{"HKLM","SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Foo"}, new[]{"HKCU",Sandbox},
            };
            foreach (var a in allowed)
                t.Check("guardia ammette chiave " + a[0] + "\\" + a[1], DeleteGuard.Check(a[0], a[1], ActionKind.DeleteKey, null, out why), why);
            t.Check("guardia ammette valore firewall", DeleteGuard.Check("HKLM", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules", ActionKind.DeleteValue, "id", out why), why);
        }

        static void TestCsv(T t)
        {
            t.Check("CSV neutralizza =", CsvExport.Neutralize("=1+1") == "'=1+1");
            t.Check("CSV neutralizza +", CsvExport.Neutralize("+x") == "'+x");
            t.Check("CSV neutralizza -", CsvExport.Neutralize("-x") == "'-x");
            t.Check("CSV neutralizza @", CsvExport.Neutralize("@x") == "'@x");
            t.Check("CSV lascia testo normale", CsvExport.Neutralize("abc") == "abc");
            t.Check("CSV quoting separatore", CsvExport.Cell("a;b", ";") == "\"a;b\"");
            t.Check("CSV quoting virgolette", CsvExport.Cell("a\"b", ";") == "\"a\"\"b\"");
        }

        static Row R(int seq, string group, string tier, bool deletable, bool chk = false)
        {
            return new Row { Seq = seq, Group = group, Tier = tier, Deletable = deletable, Checked = chk, Hive = "HKCU", DeleteRoot = @"Software\X" + seq, KeyPath = @"Software\X" + seq, Item = "voce" + seq, Confidence = 50 + seq };
        }

        static void TestSelection(T t)
        {
            var v = new RowView();
            Row a = R(1, "A", Tiers.Pulibile, true), b = R(2, "A", Tiers.Pulibile, true), c = R(3, "B", Tiers.Pulibile, true),
                d = R(4, "A", Tiers.NonToccare, false), e = R(5, "B", Tiers.Falso, false), hiddenChk = R(6, "B", Tiers.Lasciare, true, true);
            v.All = new List<Row> { a, b, c, d, e, hiddenChk };

            v.Group = "A"; v.Apply();
            int sk = v.SelectVisible();
            t.Check("seleziona visibili: spunta visibili", a.Checked && b.Checked);
            t.Check("seleziona visibili: non tocca nascoste", !c.Checked && !e.Checked && hiddenChk.Checked);
            t.Check("seleziona visibili: non eliminabile mai spuntata", !d.Checked);
            t.Check("seleziona visibili: conta saltate", sk == 1);
            t.Check("nascoste spuntate contate", v.CheckedHidden == 1);

            var el = v.Eligible();
            t.Check("eleggibili escludono nascoste spuntate", el.Count == 2 && !el.Contains(hiddenChk));
            t.Check("eleggibili escludono non eliminabili", !el.Contains(d));

            b.Checked = false;
            v.InvertVisible();
            t.Check("inverti visibili", !a.Checked && b.Checked);
            t.Check("inverti non tocca nascoste", hiddenChk.Checked && !c.Checked);
            t.Check("inverti non spunta non eliminabili", !d.Checked);

            v.DeselectVisible();
            t.Check("deseleziona visibili", !a.Checked && !b.Checked);
            t.Check("deseleziona non tocca nascoste", hiddenChk.Checked);

            d.Checked = true; // anche se forzata, i comandi la riportano a false e l'eleggibilità la esclude
            t.Check("eleggibili escludono non eliminabile forzata", !v.Eligible().Contains(d));
            v.SelectVisible();
            t.Check("comandi ripuliscono non eliminabile forzata", !d.Checked);

            v.Group = null; v.Tier = Tiers.Pulibile; v.Apply();
            v.DeselectVisible();
            v.SelectGroupVisible("B");
            t.Check("seleziona gruppo solo righe visibili", c.Checked && !e.Checked && hiddenChk.Checked);
            v.Tier = null; v.Group = "B"; v.Apply();
            t.Check("filtri non alterano le spunte", c.Checked && hiddenChk.Checked);

            v.Group = null; v.Tier = null; v.SortColumn = RowView.ColConf; v.SortAscending = false; v.Apply();
            t.Check("ordinamento numerico discendente", v.Visible[0] == hiddenChk && v.Visible[5] == a);
            v.SortColumn = RowView.ColGroup; v.SortAscending = true; v.Apply();
            t.Check("ordinamento stabile", v.Visible[0] == a && v.Visible[1] == b && v.Visible[2] == d);
            v.Text = "voce3"; v.Apply();
            t.Check("ricerca testo", v.Visible.Count == 1 && v.Visible[0] == c);
        }

        static void TestProbe(T t, string temp)
        {
            var p = new PathProbe();
            string win = p.Windir;
            t.Check("probe %1 non è un percorso", p.ProbeCommand("\"%1\" %*").Status == PathStatus.NotAPath);
            t.Check("probe %1 ha nota", p.ProbeCommand("%1").FpNote != null);
            t.Check("probe /UserInstall", p.ProbeCommand("/UserInstall").Status == PathStatus.NotAPath);
            t.Check("probe U", p.ProbeCommand("U").Status == PathStatus.NotAPath);
            t.Check("probe perfmon senza estensione", p.ProbeCommand(win + @"\system32\perfmon /sys").Status == PathStatus.Exists);
            t.Check("probe explorer nudo", p.ProbeCommand("explorer").Status == PathStatus.Exists);
            t.Check("probe slash", p.ProbeCommand(win.Replace('\\', '/') + "/notepad.exe --arg").Status == PathStatus.Exists);
            t.Check("probe slash ha nota", p.ProbeCommand(win.Replace('\\', '/') + "/notepad.exe --arg").FpNote == PathProbe.NoteSlash);
            t.Check("probe @ e icona", p.ProbeFile(p.Normalize("@%SystemRoot%\\system32\\shell32.dll,-1")).Status == PathStatus.Exists);
            t.Check("probe \\SystemRoot", p.ProbeFile(p.Normalize(@"\SystemRoot\system32\ntoskrnl.exe")).Status == PathStatus.Exists);
            t.Check("probe \\??\\", p.ProbeFile(p.Normalize(@"\??\" + win + @"\system32\ntoskrnl.exe")).Status == PathStatus.Exists);
            t.Check("probe system32 relativo", p.ProbeFile(p.Normalize(@"system32\ntoskrnl.exe")).Status == PathStatus.Exists);
            t.Check("probe TypeLib con \\N", p.ProbeTypeLib(win + @"\system32\stdole2.tlb\1").Status == PathStatus.Exists);
            t.Check("probe TypeLib nota", p.ProbeTypeLib(win + @"\system32\stdole2.tlb\1").FpNote == PathProbe.NoteTypeLib);
            t.Check("probe rundll32 inspeziona argomento", p.ProbeCommand(win + @"\system32\rundll32.exe C:\__nonesiste__\x.dll,Foo").Status == PathStatus.Missing);
            t.Check("probe rundll32 dll di sistema", p.ProbeCommand("rundll32.exe shell32.dll,Control_RunDLL").Status == PathStatus.Exists);
            t.Check("probe mancante", p.ProbeFile(win.Substring(0, 3) + @"__nonesiste__\x.exe").Status == PathStatus.Missing);
            t.Check("probe systemprofile protetta", p.ProbeFile(win + @"\system32\config\systemprofile\__x\y.dll").Status == PathStatus.Denied);
            t.Check("probe WindowsApps sconosciuto", p.ProbeFile(win.Substring(0, 3) + @"Program Files\WindowsApps\Foo_1.0_x64__abc\x.exe").Status == PathStatus.AppxUnverified);
            t.Check("probe UNC", p.ProbeFile(@"\\server\share\x.exe").Status == PathStatus.Network);
            string free = FreeDrive();
            if (free != null) t.Check("probe unità assente", p.ProbeFile(free + @":\foo\x.exe").Status == PathStatus.DriveAbsent);
            t.Check("probe syswow64 <-> system32", p.ProbeFile(win + @"\SysWOW64\ntoskrnl.exe").Status == PathStatus.Exists);
            t.Check("squish GUID MSI", Scanner.Squish("{1D8E6291-B0D5-35EC-8441-6616F567A0F7}") == "1926E8D15D0BCE53481466615F760A7F");
        }

        static void TestVendorRules(T t)
        {
            t.Check("produttore sconosciuto: gruppo generico", Scanner.VendorGroupFor("Contoso Inesistente SpA", false, 0) == "ve-unknown");
            t.Check("gruppo generico al 80%", Groups.Get("ve-unknown").Conf == 80 && Groups.Get("ve-unknown").Title == "Produttore senza programma riconosciuto");
            t.Check("produttore con sola cartella dati: incerto", Scanner.VendorGroupFor("Contoso", true, 0) == "ve-unsure");
            t.Check("produttore con dati esistenti: incerto", Scanner.VendorGroupFor("Contoso", false, 1) == "ve-unsure");
            t.Check("chiave con nome GUID: incerta", Scanner.VendorGroupFor("bd400747-f0c1-5638-a859-982036102edf", false, 0) == "ve-unsure");
            foreach (string n in new[] { "Microsoft", "Classes", "Policies", "Clients", "RegisteredApplications", "ODBC", "Windows", "WOW6432Node", "Khronos", "ASIO", "AGEIA Technologies", "OEM", "Partner", "OpenSSH", "Setup", "DefaultUserEnvironment", "Intel", "NVIDIA Corporation", "dotnet", "Realtek", "JavaSoft" })
                t.Check("elenco di sistema contiene " + n, Hints.SystemKeys.Contains(n));
            t.Check("classi di sistema: exefile", Hints.IsSystemClass("exefile"));
            t.Check("classi di sistema: *", Hints.IsSystemClass("*"));
            t.Check("classe normale non di sistema", !Hints.IsSystemClass("contoso"));
        }

        static string FreeDrive()
        {
            var used = DriveInfoNames();
            for (char c = 'Z'; c >= 'G'; c--)
                if (!used.Contains(c)) return c.ToString();
            return null;
        }

        static HashSet<char> DriveInfoNames()
        {
            var s = new HashSet<char>();
            foreach (DriveInfo d in DriveInfo.GetDrives()) s.Add(char.ToUpperInvariant(d.Name[0]));
            return s;
        }

        // ---------------------------------------------------------------- sandbox

        static void BuildSandbox()
        {
            using (RegistryKey h = Hkcu())
            using (RegistryKey root = h.CreateSubKey(Sandbox, true))
            {
                root.SetValue("", "valore predefinito");
                root.SetValue("sz", "testo con \"virgolette\" e \\barre\\ e àèìòù €");
                root.SetValue("nome \"strano\"\\x", "v");
                root.SetValue("expand", "%windir%\\x;%TEMP%", RegistryValueKind.ExpandString);
                root.SetValue("multi", new[] { "uno", "due due", "tre\\3" }, RegistryValueKind.MultiString);
                root.SetValue("binary", new byte[] { 0, 1, 2, 0xfe, 0xff, 10, 13, 0 }, RegistryValueKind.Binary);
                root.SetValue("dword", unchecked((int)0xDEADBEEF), RegistryValueKind.DWord);
                root.SetValue("qword", unchecked((long)0x0123456789ABCDEFL), RegistryValueKind.QWord);
                root.SetValue("none", new byte[] { 1, 2, 3 }, RegistryValueKind.None);
                root.SetValue("lunghissimo", Enumerable.Range(0, 300).Select(i => (byte)i).ToArray(), RegistryValueKind.Binary);
                root.SetValue("vuoto", "");
                RegSetValueExW(root.Handle, "tipo8", 0, 8, new byte[] { 9, 8, 7, 6 }, 4);
                RegSetValueExW(root.Handle, "sz_a_capo", 0, 1, Encoding.Unicode.GetBytes("riga1\r\nriga2\0"), Encoding.Unicode.GetByteCount("riga1\r\nriga2\0"));
                RegSetValueExW(root.Handle, "dword_corto", 0, 4, new byte[] { 1, 2 }, 2);
                root.SetValue("da_eliminare", "addio");
                using (RegistryKey a = root.CreateSubKey(@"Sub1\Sub2\Sub3"))
                {
                    a.SetValue("profondo", 7, RegistryValueKind.DWord);
                    a.SetValue("", "predefinito profondo");
                }
                using (RegistryKey a = root.CreateSubKey(@"Sub1\Altra chiave con spazi"))
                    a.SetValue("x", "y");
                using (RegistryKey a = root.CreateSubKey("Scollegata")) { a.SetValue("x", "y"); }
                using (RegistryKey a = root.CreateSubKey("Protetta")) { a.SetValue("x", "y"); }
            }
        }

        static Dictionary<string, string> Snapshot(string path)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.OpenSubKey(path, false))
                if (k != null) Snap(k, "", d);
            return d;
        }

        static void Snap(RegistryKey k, string rel, Dictionary<string, string> d)
        {
            d[rel + "\\<chiave>"] = "";
            foreach (RawValue v in RegNative.ReadValues(k))
                d[rel + "\\" + v.Name] = v.Type + ":" + BitConverter.ToString(v.Data);
            foreach (string s in k.GetSubKeyNames())
                using (RegistryKey c = k.OpenSubKey(s, false))
                    if (c != null) Snap(c, rel + "\\" + s, d);
        }

        static bool SameSnap(Dictionary<string, string> a, Dictionary<string, string> b, out string diff)
        {
            diff = null;
            foreach (var kv in a)
            {
                string o;
                if (!b.TryGetValue(kv.Key, out o)) { diff = "manca " + kv.Key; return false; }
                if (o != kv.Value) { diff = "diverso " + kv.Key + ": " + kv.Value + " / " + o; return false; }
            }
            foreach (var kv in b)
                if (!a.ContainsKey(kv.Key)) { diff = "in più " + kv.Key; return false; }
            return true;
        }

        static Row SandboxRow(string sub, string value, string probe = null)
        {
            string path = sub.Length == 0 ? Sandbox : Sandbox + "\\" + sub;
            return new Row
            {
                Hive = "HKCU", KeyPath = path, DeleteRoot = path, ValueName = value,
                Action = value == null ? ActionKind.DeleteKey : ActionKind.DeleteValue,
                Deletable = true, ProbePath = probe, Item = sub,
            };
        }

        static DeleteOutcome RunEngine(string temp, string tag, params Row[] rows)
        {
            var opt = new DeleteOptions
            {
                BackupPath = Path.Combine(temp, tag + ".reg"),
                LogPath = Path.Combine(temp, tag + ".txt"),
                SandboxOnly = @"HKCU\" + Sandbox,
            };
            return DeleteEngine.Run(rows, opt);
        }

        // ---------------------------------------------------------------- revisione: unità

        static void TestCoreAndUninstall(T t)
        {
            t.Check("nucleo MSContosoTool Store", Corpus.Core("MSContosoTool Store") == "contosotool", Corpus.Core("MSContosoTool Store"));
            t.Check("nucleo Microsoft.MicrosoftContosoTool", Corpus.Core("Microsoft.MicrosoftContosoTool") == "contosotool", Corpus.Core("Microsoft.MicrosoftContosoTool"));
            t.Check("nucleo ContosoTool Service Store", Corpus.Core("ContosoTool Service Store") == "contosotool");
            t.Check("corrispondenza MSContosoTool Store / pacchetto", Corpus.CoreMatch("MSContosoTool Store", "Microsoft.MicrosoftContosoTool"));
            t.Check("corrispondenza MSContosoTool Store / servizio", Corpus.CoreMatch("MSContosoTool Store", "ContosoTool Service Store"));
            t.Check("corrispondenza con contenimento", Corpus.CoreMatch("Fabrikam", "FabrikamAB.FabrikamMusic"));
            t.Check("nessuna: Litho / monolithography (troppo corto)", !Corpus.CoreMatch("Litho", "monolithography"));
            t.Check("nessuna: Litho / LithoHub (troppo corto)", !Corpus.CoreMatch("Litho", "LithoHub"));
            t.Check("nessuna: XY Games / Microsoft.GamingApp", !Corpus.CoreMatch("XY Games", "Microsoft.GamingApp"));
            t.Check("nessuna: XY Games / Microsoft.Xbox.TCUI", !Corpus.CoreMatch("XY Games", "Microsoft.Xbox.TCUI"));
            t.Check("nessuna: Valley / Highvale", !Corpus.CoreMatch("Valley", "Highvale"));
            t.Check("nessuna: Valley / Microsoft.WindowsCalculator", !Corpus.CoreMatch("Valley", "Microsoft.WindowsCalculator"));
            t.Check("nessuna: nome solo generico", !Corpus.CoreMatch("Store Service", "Microsoft.WindowsStore") || Corpus.Core("Store Service").Length >= 6);
            var ve = new Corpus();
            ve.AddStrong("AB");
            ve.AddStrong("Contoso");
            t.Check("prova produttore: chiave con sigla rilevata", ve.MatchVendorEvidence("AB"));
            t.Check("prova produttore: prima parola in maiuscolo", ve.MatchVendorEvidence("AB Sports"));
            t.Check("prova produttore: prefisso di un programma", ve.MatchVendorEvidence("ContosoShared"));
            t.Check("prova produttore: sigla diversa", !ve.MatchVendorEvidence("XY Games"));
            t.Check("prova produttore: minuscole non sono una sigla", !ve.MatchVendorEvidence("Ab Sports"));
            t.Check("prova produttore: nome estraneo", !ve.MatchVendorEvidence("Fabrikam"));
            t.Check("famiglia del pacchetto", Corpus.PackageFamily("Microsoft.MicrosoftContosoTool_3.23.0.0_x64__8wekyb3d8bbwe") == "Microsoft.MicrosoftContosoTool_8wekyb3d8bbwe");
            t.Check("nome del pacchetto", Corpus.PackageName("Microsoft.MicrosoftContosoTool_3.23.0.0_x64__8wekyb3d8bbwe") == "Microsoft.MicrosoftContosoTool");
            t.Check("famiglia inesistente: nessun pacchetto", Corpus.InstalledFullNames("Inesistente.Pacchetto_abc123").Count == 0);

            // Tabella di decisione delle voci visibili.
            Func<PathStatus, PathStatus, bool, bool, string> G = Scanner.UninstallGroupFor;
            t.Check("disinstallazione: mancante, cartella mancante -> orfana", G(PathStatus.Missing, PathStatus.Missing, false, false) == "un-orphan");
            t.Check("disinstallazione: mancante, cartella assente -> orfana", G(PathStatus.Missing, PathStatus.Empty, false, false) == "un-orphan");
            t.Check("disinstallazione: MSI non registrato, senza cartella -> orfana", G(PathStatus.MsiMissing, PathStatus.Empty, false, false) == "un-orphan");
            t.Check("disinstallazione: mancante, file del programma -> presente", G(PathStatus.Missing, PathStatus.Exists, true, false) == "un-present");
            t.Check("disinstallazione: mancante, cartella senza eseguibili -> parziale", G(PathStatus.Missing, PathStatus.Exists, false, false) == "un-partial");
            t.Check("disinstallazione: esiste -> nessuna riga", G(PathStatus.Exists, PathStatus.Missing, false, false) == null);
            t.Check("disinstallazione: negato -> nessuna riga", G(PathStatus.Denied, PathStatus.Missing, false, false) == null);
            t.Check("disinstallazione: UNC -> nessuna riga", G(PathStatus.Network, PathStatus.Missing, false, false) == null);
            t.Check("disinstallazione: WindowsApps non verificato -> nessuna riga", G(PathStatus.AppxUnverified, PathStatus.Missing, false, false) == null);
            t.Check("disinstallazione: comando nudo non trovato -> nessuna riga", G(PathStatus.BareMissing, PathStatus.Missing, false, false) == null);
            t.Check("disinstallazione: unità assente -> non orfana", G(PathStatus.DriveAbsent, PathStatus.Missing, false, false) == "un-offline");
            t.Check("disinstallazione: cartella su unità assente -> non orfana", G(PathStatus.Missing, PathStatus.DriveAbsent, false, false) == "un-offline");
            t.Check("disinstallazione: cartella non verificabile -> nessuna riga", G(PathStatus.Missing, PathStatus.Denied, false, false) == null);
            t.Check("disinstallazione: MSI registrato -> mai orfana", G(PathStatus.Missing, PathStatus.Missing, false, true) == null);
            var orphan = Groups.Get("un-orphan"); var present = Groups.Get("un-present"); var off = Groups.Get("un-offline");
            t.Check("gruppo orfana: 92, eliminabile, titolo", orphan.Conf == 92 && orphan.RegistryDeletable && orphan.Title == "Voce di disinstallazione senza programma" && orphan.Area == Groups.AUn);
            t.Check("gruppo presente: 55, non eliminabile, titolo", present.Conf == 55 && !present.RegistryDeletable && Tiers.Of(present.Conf) == Tiers.Lasciare && present.Title == "Programma presente, disinstallatore mancante");
            t.Check("gruppo presente: come procedere", present.How == "Reinstalla o ripara il programma, poi disinstallalo da PC Manager o dalle Impostazioni di Windows.");
            t.Check("gruppo unità assente: al massimo 50, non eliminabile", off.Conf <= 50 && !off.RegistryDeletable);
            string why;
            t.Check("voce orfana ammessa dalla protezione", DeleteGuard.Check("HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Fantasma", ActionKind.DeleteKey, null, out why));
            // Prove di vita.
            t.Check("voce viva: disinstallatore", Scanner.UninstallAlive(PathStatus.Exists, false, false, false));
            t.Check("voce viva: cartella con eseguibili", Scanner.UninstallAlive(PathStatus.Missing, true, false, false));
            t.Check("voce viva: icona", Scanner.UninstallAlive(PathStatus.Missing, false, true, false));
            t.Check("voce viva: MSI registrato", Scanner.UninstallAlive(PathStatus.Empty, false, false, true));
            t.Check("voce fantasma: nessuna prova", !Scanner.UninstallAlive(PathStatus.Missing, false, false, false));
            t.Check("voce fantasma: senza stringa e senza prove", !Scanner.UninstallAlive(PathStatus.Empty, false, false, false));
            t.Check("voce non verificabile non è prova", !Scanner.UninstallAlive(PathStatus.Denied, false, false, false));
        }

        static void TestReviewUnits(T t, string temp)
        {
            string why;
            var refuse = new[]
            {
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-18"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\foo.exe"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Cryptography"},
                new[]{"HKLM",@"SOFTWARE\Policies\Microsoft"},
                new[]{"HKLM",@"SOFTWARE\Policies\Foo"},
                new[]{"HKLM",@"SOFTWARE\Clients"},
                new[]{"HKLM",@"SOFTWARE\Clients\StartMenuInternet"},
                new[]{"HKLM",@"SOFTWARE\Classes\Wow6432Node\CLSID"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Classes\Wow6432Node\CLSID"},
                new[]{"HKLM",@"SOFTWARE\Classes\Installer\Products"},
                new[]{"HKLM",@"SOFTWARE\Classes\Installer\Products\ABC"},
                new[]{"HKCU",@"Software\Classes\Local Settings\Software"},
                new[]{"HKCU",@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"},
                new[]{"HKLM",@"SOFTWARE\Classes\.docx"},
                new[]{"HKLM",@"SOFTWARE\Classes\.pdf"},
                new[]{"HKLM",@"SOFTWARE\Classes\Word.Document.12"},
                new[]{"HKLM",@"SOFTWARE\Classes\InternetShortcut"},
                new[]{"HKCU",@"Software\Classes\Word.Document.12"},
                new[]{"HKLM",@"SOFTWARE\Classes\Interface\{00000000-0000-0000-0000-000000000000}"},
                new[]{"HKLM",@"SOFTWARE\Classes\CLSID\nonguid"},
                new[]{"HKLM",@"SOFTWARE\Classes\contoso\shell"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Office"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Explorer"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foo\Bar"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\VisualStudio\Setup"},
                new[]{"HKLM",@"SOFTWARE\Foo\Bar\Baz"},
                new[]{"HKLM",@"SOFTWARE\Intel\Foo"},
                new[]{"HKLM","SOFTWARE\\Foo\nBar"},
                new[]{"HKLM","SOFTWARE\\Foo\0Bar"},
                new[]{"HKCU","Software\\Foo\rBar"},
            };
            foreach (var f in refuse)
                t.Check("allowlist rifiuta chiave " + f[0] + "\\" + f[1].Replace("\n", "<LF>").Replace("\r", "<CR>").Replace("\0", "<NUL>"), !DeleteGuard.Check(f[0], f[1], ActionKind.DeleteKey, null, out why));

            var refuseVal = new[]
            {
                new[]{"HKLM",@"SOFTWARE\Microsoft\Cryptography","MachineGuid"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon","Shell"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion","ProductName"},
                new[]{"HKLM",@"SOFTWARE\Policies\Foo","x"},
                new[]{"HKLM",@"SOFTWARE\Foo","x"},
                new[]{"HKCU",@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags","x"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved","x"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Run","x\ny"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Run","x\0y"},
            };
            foreach (var f in refuseVal)
                t.Check("allowlist rifiuta valore " + f[1] + " -> " + f[2].Replace("\n", "<LF>").Replace("\0", "<NUL>"), !DeleteGuard.Check(f[0], f[1], ActionKind.DeleteValue, f[2], out why));

            var acceptKey = new[]
            {
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\App Paths\foo.exe"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Foo"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ ContosoSync1"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\ ContosoSync1"},
                new[]{"HKCU",@"Software\Microsoft\VisualStudio\17.0_cb5d47d3"},
                new[]{"HKLM",@"SOFTWARE\Classes\Wow6432Node\CLSID\{00000000-0000-0000-0000-000000000000}"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Classes\CLSID\{00000000-0000-0000-0000-000000000000}"},
                new[]{"HKCU",@"Software\Classes\Applications\foo.exe"},
                new[]{"HKCU",@"Software\Classes\.ctso"},
                new[]{"HKCU",@"Software\Fabrikam\Prodotto"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Foo\Bar"},
            };
            foreach (var f in acceptKey)
                t.Check("allowlist ammette chiave " + f[0] + "\\" + f[1], DeleteGuard.Check(f[0], f[1], ActionKind.DeleteKey, null, out why), why);

            var acceptVal = new[]
            {
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",@"C:\x\"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs",@"C:\x.dll"},
                new[]{"HKCU",@"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",@"C:\x.exe"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",@"C:\x.exe"},
                new[]{"HKCU",@"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",@"C:\x.exe.FriendlyAppName"},
                new[]{"HKCU",@"Software\RegisteredApplications","x"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run","x"},
                new[]{"HKLM",@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32","x"},
                new[]{"HKCU",@"Software\Classes\.foo\OpenWithProgids","x"},
                new[]{"HKCU",@"Software\Microsoft\Windows\CurrentVersion\Run","x"},
                new[]{"HKLM",@"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce","x"},
            };
            foreach (var f in acceptVal)
                t.Check("allowlist ammette valore " + f[1], DeleteGuard.Check(f[0], f[1], ActionKind.DeleteValue, f[2], out why), why);

            // C6
            t.Check("C6: produttore con cartella dati va in incerto", Scanner.VendorGroupFor("Fabrikam", true, 0) == "ve-unsure");
            t.Check("C6: produttore con dati esistenti va in incerto", Scanner.VendorGroupFor("Fabrikam", false, 2) == "ve-unsure");
            t.Check("C6: produttore senza prove resta generico", Scanner.VendorGroupFor("Fabrikam", false, 0) == "ve-unknown");

            // P3
            t.Check("P3: manifest Steam illeggibili limitano a 60", Scanner.CapForReadErrors("un-steam", 1, 0) == 60 && Scanner.CapForReadErrors("ve-unknown", 1, 0) == 60);
            t.Check("P3: istanze VS illeggibili limitano a 60", Scanner.CapForReadErrors("ve-vs", 0, 1) == 60 && Scanner.CapForReadErrors("pr-ext-vs", 0, 1) == 60);
            t.Check("P3: senza errori nessun limite", Scanner.CapForReadErrors("un-steam", 0, 0) == null);

            // C15
            t.Check("C15: tr-regappx e ms-shared al 65", Groups.Get("tr-regappx").Conf == 65 && Groups.Get("ms-shared").Conf == 65);
            var v = new RowView();
            Row safe = R(1, "G", Tiers.Pulibile, true), risky = R(2, "G", Tiers.Lasciare, true);
            v.All = new List<Row> { safe, risky };
            v.Apply();
            v.SelectVisible();
            t.Check("C15: seleziona visibili salta Meglio lasciare", safe.Checked && !risky.Checked && v.LastSkippedRisky == 1);
            v.InvertVisible();
            t.Check("C15: inverti salta Meglio lasciare", !safe.Checked && !risky.Checked);
            v.SelectGroupVisible("G");
            t.Check("C15: seleziona gruppo salta Meglio lasciare", safe.Checked && !risky.Checked);
            v.DeselectVisible();
            v.Tier = Tiers.Lasciare; v.Apply();
            v.SelectVisible();
            t.Check("C15: col filtro su quel livello si seleziona", risky.Checked && v.LastSkippedRisky == 0);
            v.Tier = null; v.Apply();
            v.DeselectVisible();
            t.Check("C15: deseleziona toglie anche Meglio lasciare", !risky.Checked);

            // C8
            var w = new RowView();
            Row shown = R(1, "A", Tiers.Pulibile, true, true), hidden = R(2, "B", Tiers.Pulibile, true, true);
            w.All = new List<Row> { shown, hidden };
            w.Group = "A"; w.Apply();
            HashSet<Row> before = w.HiddenChecked();
            t.Check("C8: nascosta riconosciuta", before.Contains(hidden) && !before.Contains(shown));
            w.All = new List<Row> { hidden }; // il gruppo A è sparito dopo l'eliminazione
            w.Group = null; w.Apply();        // il filtro si azzera da solo
            int rev = w.UncheckRevealed(before);
            t.Check("C8: filtro azzerato toglie la spunta alle nascoste", rev == 1 && !hidden.Checked && w.Eligible().Count == 0);

            // C9
            int xl, xc;
            var mix = new List<Row> { new Row { Hive = "HKLM" }, new Row { Hive = "HKCU" }, new Row { Hive = "HKCU" } };
            var l1 = RowView.ForAccount(mix, true, true, out xl, out xc);
            t.Check("C9: altro utente elevato esclude HKCU", l1.Count == 1 && l1[0].Hive == "HKLM" && xc == 2 && xl == 0);
            var l2 = RowView.ForAccount(mix, false, false, out xl, out xc);
            t.Check("non elevato esclude HKLM", l2.Count == 2 && xl == 1 && xc == 0);
            var l3 = RowView.ForAccount(mix, true, false, out xl, out xc);
            t.Check("elevato stesso utente non esclude nulla", l3.Count == 3);

            // C10
            bool threw = false;
            try { RegBackupWriter.FormatValue(new RawValue { Name = "a\nb", Type = 1, Data = new byte[] { 0, 0 } }); } catch (InvalidDataException) { threw = true; }
            t.Check("C10: LF nel nome del valore è un errore", threw);
            threw = false;
            try { RegBackupWriter.FormatValue(new RawValue { Name = "a\0b", Type = 1, Data = new byte[] { 0, 0 } }); } catch (InvalidDataException) { threw = true; }
            t.Check("C10: NUL nel nome del valore è un errore", threw);
            byte[] lone = { 0x00, 0xD8, 0x41, 0x00, 0x00, 0x00 }; // surrogato alto isolato + 'A' + terminatore
            t.Check("C10: surrogato isolato in hex(1)", RegBackupWriter.FormatValue(new RawValue { Name = "s", Type = 1, Data = lone }) == "\"s\"=hex(1):00,d8,41,00,00,00");
            byte[] ok = Encoding.Unicode.GetBytes("ciao\0");
            t.Check("C10: testo normale resta testo", RegBackupWriter.FormatValue(new RawValue { Name = "s", Type = 1, Data = ok }) == "\"s\"=\"ciao\"");

            // C12 scansione
            var tree = new List<Row>
            {
                new Row { Hive = "HKCU", KeyPath = @"Software\P", DeleteRoot = @"Software\P", Deletable = true, Confidence = 95, Tier = Tiers.Pulibile },
                new Row { Hive = "HKCU", KeyPath = @"Software\P\Keep", DeleteRoot = @"Software\P\Keep", Deletable = false, Confidence = 10, Tier = Tiers.NonToccare },
                new Row { Hive = "HKCU", KeyPath = @"Software\Q", DeleteRoot = @"Software\Q", Deletable = true, Confidence = 95, Tier = Tiers.Pulibile },
            };
            int dem = Scanner.ApplySubtreeProtection(tree);
            t.Check("C12: chiave con figlio non eliminabile perde l'eliminabilità", dem == 1 && !tree[0].Deletable && tree[0].Tier == Tiers.NonToccare && tree[2].Deletable);

            // P4
            string dir = Path.Combine(temp, "Node.js Tools");
            Directory.CreateDirectory(dir);
            string exe = Path.Combine(dir, "x.exe");
            File.WriteAllText(exe, "x");
            var pp = new PathProbe();
            ProbeResult pr = pp.ProbeCommand(exe + " --arg uno");
            t.Check("P4: percorso con .js e spazi non quotato", pr.Status == PathStatus.Exists && pr.Target.Equals(exe, StringComparison.OrdinalIgnoreCase), pr.Status + " " + pr.Target);

            // C4: stato Denied non vale come assente (provato sotto col motore)
            t.Check("probe cartella protetta non è Missing", pp.ProbeFile(pp.Windir + @"\system32\config\__x\y.dll").Status == PathStatus.Denied);
        }

        // ---------------------------------------------------------------- revisione: motore

        static string SerializeSandbox(string sub, string value)
        {
            string path = sub.Length == 0 ? Sandbox : Sandbox + "\\" + sub;
            using (RegistryKey h = Hkcu())
                return DeleteEngine.Serialize(h, "HKCU", path, value == null ? ActionKind.DeleteKey : ActionKind.DeleteValue, value);
        }

        static void SetVal(string sub, string name, object val)
        {
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.CreateSubKey(sub.Length == 0 ? Sandbox : Sandbox + "\\" + sub, true))
                k.SetValue(name, val);
        }

        static bool KeyThere(string sub)
        {
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.OpenSubKey(Sandbox + "\\" + sub, false))
                return k != null;
        }

        static void TestEngineReview(T t, string temp)
        {
            RemoveSandbox();
            BuildSandbox();
            int tag = 0;
            Func<string> Tag = () => "rev" + (++tag);

            // C4: contenuto cambiato
            SetVal("Hash", "a", "1");
            SetVal("Hash", "b", "2");
            Row changedKey = SandboxRow("Hash", null);
            changedKey.ContentHash = DeleteEngine.Hash(SerializeSandbox("Hash", null));
            SetVal("Hash", "a", "CAMBIATO");
            RunEngine(temp, Tag(), changedKey);
            t.Check("C4: chiave cambiata saltata", changedKey.Status == DeleteEngine.StatusChanged && KeyThere("Hash"), changedKey.Status);

            Row changedVal = SandboxRow("Hash", "b");
            changedVal.ContentHash = DeleteEngine.Hash(SerializeSandbox("Hash", "b"));
            SetVal("Hash", "b", "CAMBIATO");
            RunEngine(temp, Tag(), changedVal);
            t.Check("C4: valore cambiato saltato", changedVal.Status == DeleteEngine.StatusChanged, changedVal.Status);

            Row sameKey = SandboxRow("Hash", null);
            sameKey.ContentHash = DeleteEngine.Hash(SerializeSandbox("Hash", null));
            DeleteOutcome oSame = RunEngine(temp, Tag(), sameKey);
            t.Check("C4: chiave invariata eliminata", oSame.Deleted == 1 && !KeyThere("Hash"), sameKey.Status);

            // C4: percorso non dimostrabile come assente
            SetVal("Probe", "a", "1");
            string denied = (Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows") + @"\system32\config\__x\y.dll";
            Row deniedRow = SandboxRow("Probe", null, denied);
            RunEngine(temp, Tag(), deniedRow);
            t.Check("C4: accesso negato non vale come assente", deniedRow.Status == "Saltata: percorso non verificabile" && KeyThere("Probe"), deniedRow.Status);
            Row absentRow = SandboxRow("Probe", null, Path.Combine(temp, "non-esiste.exe"));
            absentRow.ProbeStatus = PathStatus.Missing;
            DeleteOutcome oAbs = RunEngine(temp, Tag(), absentRow);
            t.Check("C4: file davvero assente procede", oAbs.Deleted == 1 && !KeyThere("Probe"), absentRow.Status);

            // C11
            SetVal("Fw", "regola", "x");
            Row fw = SandboxRow("Fw", "regola");
            fw.GroupId = "fw-apps";
            DeleteOutcome oFw = RunEngine(temp, Tag(), fw);
            t.Check("C11: firewall esito onesto e contato", fw.Status == DeleteEngine.StatusFirewall && oFw.FirewallPending == 1 && oFw.Deleted == 1, fw.Status);

            // C12: motore con tutte le righe
            SetVal(@"Padre\Figlio", "x", "1");
            Row padre = SandboxRow("Padre", null), figlio = SandboxRow(@"Padre\Figlio", null);
            DeleteOutcome oCov = DeleteEngine.Run(new[] { padre }, new DeleteOptions { BackupPath = Path.Combine(temp, Tag() + ".reg"), LogPath = Path.Combine(temp, Tag() + ".txt"), SandboxOnly = @"HKCU\" + Sandbox, AllRows = new List<Row> { padre, figlio } });
            t.Check("C12: padre non eliminato se copre righe non selezionate", padre.Status == DeleteEngine.StatusCovers && KeyThere("Padre") && oCov.Skipped == 1, padre.Status);
            padre.Status = "";
            DeleteOutcome oBoth = DeleteEngine.Run(new[] { padre, figlio }, new DeleteOptions { BackupPath = Path.Combine(temp, Tag() + ".reg"), LogPath = Path.Combine(temp, Tag() + ".txt"), SandboxOnly = @"HKCU\" + Sandbox, AllRows = new List<Row> { padre, figlio } });
            t.Check("C12: padre e figlio entrambi selezionati si eliminano", oBoth.Deleted == 2 && !KeyThere("Padre"));

            // C14: annullamento e registro riga per riga
            SetVal("Ann1", "x", "1");
            SetVal("Ann2", "x", "1");
            Row a1 = SandboxRow("Ann1", null), a2 = SandboxRow("Ann2", null);
            string logA = Path.Combine(temp, Tag() + ".txt");
            using (var cts = new CancellationTokenSource())
            {
                var optA = new DeleteOptions { BackupPath = Path.Combine(temp, Tag() + ".reg"), LogPath = logA, SandboxOnly = @"HKCU\" + Sandbox, Cancel = cts.Token };
                optA.Progress = (d, n, s) => { if (d == 2) cts.Cancel(); };
                DeleteOutcome oA = DeleteEngine.Run(new[] { a1, a2 }, optA);
                t.Check("C14: annullamento fra una riga e l'altra", oA.Deleted == 1 && a2.Status == DeleteEngine.StatusCancelled && KeyThere("Ann2") && !KeyThere("Ann1"), a2.Status);
            }
            string logText = File.ReadAllText(logA);
            t.Check("C14: registro con esito per riga", logText.Contains("Eliminata\t") && logText.Contains(DeleteEngine.StatusCancelled));

            // P7: errore di scrittura del backup
            SetVal("B1", "x", "1");
            SetVal("B2", "x", "1");
            SetVal("B3", "x", "1");
            Row b1 = SandboxRow("B1", null), b2 = SandboxRow("B2", null), b3 = SandboxRow("B3", null);
            DeleteOutcome oB = DeleteEngine.Run(new[] { b1, b2, b3 }, new DeleteOptions { BackupPath = Path.Combine(temp, Tag() + ".reg"), LogPath = Path.Combine(temp, Tag() + ".txt"), SandboxOnly = @"HKCU\" + Sandbox, InjectBackupWriteFailure = () => true });
            t.Check("P7: primo errore di backup ferma tutto", oB.Deleted == 0 && oB.Errors == 1 && oB.Skipped == 2 && KeyThere("B1") && KeyThere("B2") && KeyThere("B3") && oB.Warning != null);
            // backup che non si può creare
            string exists = Path.Combine(temp, Tag() + ".reg");
            File.WriteAllText(exists, "occupato");
            Row b4 = SandboxRow("B1", null);
            DeleteOutcome oC = DeleteEngine.Run(new[] { b4 }, new DeleteOptions { BackupPath = exists, LogPath = exists + ".txt", SandboxOnly = @"HKCU\" + Sandbox });
            t.Check("P7: senza backup nessuna eliminazione", oC.Deleted == 0 && oC.Skipped == 1 && KeyThere("B1"), b4.Status);

            // C9: intestazione
            string hdr = File.ReadAllText(Path.Combine(temp, "rev1.reg"), Encoding.Unicode);
            using (var id = WindowsIdentity.GetCurrent())
                t.Check("C9: commento SID e utente nel .reg", hdr.Contains("; SID=" + id.User.Value + " Utente=" + Environment.UserName));

            // C10: nome di valore con a capo dentro una chiave
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.CreateSubKey(Sandbox + @"\NomeStrano", true))
                k.SetValue("riga1\nriga2", "x");
            Row bad = SandboxRow("NomeStrano", null);
            DeleteOutcome oBad = RunEngine(temp, Tag(), bad);
            t.Check("C10: chiave con nome non rappresentabile non eliminata", oBad.Deleted == 0 && oBad.Errors == 1 && bad.Status.StartsWith("Errore: backup non riuscito") && KeyThere("NomeStrano"), bad.Status);

            // C10: surrogato isolato, andata e ritorno
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.CreateSubKey(Sandbox + @"\Surr", true))
            {
                byte[] lone = { 0x00, 0xD8, 0x41, 0x00, 0x00, 0x00 };
                RegSetValueExW(k.Handle, "s", 0, 1, lone, lone.Length);
            }
            var before = Snapshot(Sandbox + @"\Surr");
            Row surr = SandboxRow("Surr", null);
            DeleteOutcome oSurr = RunEngine(temp, "surr", surr);
            bool imported = oSurr.Deleted == 1 && OnlySandboxHeaders(File.ReadAllText(oSurr.BackupPath, Encoding.Unicode)) && RegImport(oSurr.BackupPath) == 0;
            string d1;
            t.Check("C10: surrogato isolato ripristinato identico", imported && SameSnap(before, Snapshot(Sandbox + @"\Surr"), out d1));

            RemoveSandbox();
        }

        // ---------------------------------------------------------------- iniezione guasti (solo sandbox)

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegCreateKeyExW")]
        static extern int RegCreateLink(SafeRegistryHandle parent, string sub, int reserved, string cls, uint options, int sam, IntPtr sa, out IntPtr result, out int disposition);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegSetValueExW")]
        static extern int RegSetRaw(IntPtr h, string name, int reserved, uint type, byte[] data, int len);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        static extern int RegOpenRaw(SafeRegistryHandle parent, string sub, uint options, int sam, out IntPtr result);

        [DllImport("advapi32.dll")]
        static extern int RegCloseKey(IntPtr h);

        [DllImport("ntdll.dll")]
        static extern int NtDeleteKey(IntPtr h);

        const string LinkDirect = Sandbox + @"\LinkDiretto", LinkNested = Sandbox + @"\ConLink\Link";
        const int KEY_ALL_ACCESS = 0xF003F, KEY_WOW64_64KEY = 0x100;

        static bool CreateLink(RegistryKey h, string path, string targetSub)
        {
            string sid;
            using (var id = WindowsIdentity.GetCurrent()) sid = id.User.Value;
            byte[] target = Encoding.Unicode.GetBytes(@"\REGISTRY\USER\" + sid + @"\" + Sandbox + @"\" + targetSub);
            IntPtr k; int disp;
            if (RegCreateLink(h.Handle, path, 0, null, 2 /*REG_OPTION_CREATE_LINK*/, KEY_ALL_ACCESS | KEY_WOW64_64KEY, IntPtr.Zero, out k, out disp) != 0) return false;
            int rc = RegSetRaw(k, "SymbolicLinkValue", 0, 6, target, target.Length);
            RegCloseKey(k);
            return rc == 0;
        }

        static void RemoveLinks(RegistryKey h)
        {
            foreach (string p in new[] { LinkDirect, LinkNested })
            {
                IntPtr k;
                if (RegOpenRaw(h.Handle, p, 8 /*REG_OPTION_OPEN_LINK*/, KEY_ALL_ACCESS | KEY_WOW64_64KEY, out k) != 0) continue;
                NtDeleteKey(k);
                RegCloseKey(k);
            }
        }

        static RegistryAccessRule DenyRule()
        {
            using (var id = WindowsIdentity.GetCurrent())
                return new RegistryAccessRule(id.User, RegistryRights.Delete | RegistryRights.SetValue | RegistryRights.CreateSubKey, AccessControlType.Deny);
        }

        static void LockKey(RegistryKey h, string path)
        {
            using (RegistryKey k = h.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadPermissions | RegistryRights.ChangePermissions))
            {
                RegistrySecurity sec = k.GetAccessControl();
                sec.AddAccessRule(DenyRule());
                k.SetAccessControl(sec);
            }
        }

        /// <summary>Toglie la regola di negazione da tutta la sandbox, ricorsivamente.</summary>
        static void UnlockTree(RegistryKey h, string path)
        {
            using (RegistryKey k = h.OpenSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadPermissions | RegistryRights.ChangePermissions | RegistryRights.ReadKey))
            {
                if (k == null) return;
                RegistrySecurity sec = k.GetAccessControl();
                sec.RemoveAccessRuleSpecific(DenyRule());
                k.SetAccessControl(sec);
                foreach (string s in k.GetSubKeyNames()) UnlockTree(h, path + "\\" + s);
            }
        }

        static void TestInjection(T t, string temp)
        {
            RemoveSandbox();
            BuildSandbox();
            using (RegistryKey h = Hkcu())
            {
                // C1: chiave protetta da scrittura e cancellazione
                SetVal("Bloccata", "x", "1");
                LockKey(h, Sandbox + @"\Bloccata");
                Row locked = SandboxRow("Bloccata", null);
                DeleteOutcome o1 = RunEngine(temp, "inj1", locked);
                t.Check("C1: chiave negata non risulta eliminata", o1.Deleted == 0 && o1.Errors == 1 && locked.Status.StartsWith("Errore: non eliminata") && KeyThere("Bloccata") && o1.Removed.Count == 0, locked.Status);

                // C1: valore in chiave negata
                Row lockedVal = SandboxRow("Bloccata", "x");
                DeleteOutcome o2 = RunEngine(temp, "inj2", lockedVal);
                t.Check("C1: valore negato non risulta eliminato", o2.Deleted == 0 && o2.Errors == 1 && lockedVal.Status.StartsWith("Errore: non eliminata"), lockedVal.Status);

                // C1: una riga figlia di una radice non rimossa non deve risultare inclusa
                Row parentLocked = SandboxRow("Bloccata", null), childVal = SandboxRow("Bloccata", "x");
                DeleteOutcome o3 = RunEngine(temp, "inj3", childVal, parentLocked);
                t.Check("C1: radice fallita non copre le altre righe", o3.Deleted == 0 && o3.Errors == 2);

                // C2: eliminazione parziale
                SetVal(@"Parziale\A", "x", "1");
                SetVal(@"Parziale\Z", "x", "1");
                LockKey(h, Sandbox + @"\Parziale\Z");
                Row part = SandboxRow("Parziale", null);
                DeleteOutcome o4 = RunEngine(temp, "inj4", part);
                t.Check("C2: parziale riconosciuta e contata", o4.Partial == 1 && o4.Deleted == 0 && part.Status.StartsWith("ELIMINATA IN PARTE: ripristina da ") && part.Status.Contains(o4.BackupPath) && !KeyThere(@"Parziale\A") && KeyThere(@"Parziale\Z"), part.Status);
                t.Check("C2: parziale nel registro", File.ReadAllText(o4.LogPath).Contains("ELIMINATA IN PARTE") && File.ReadAllText(o4.LogPath).Contains("In parte: 1"));
                t.Check("C2: backup completo per il ripristino", File.ReadAllText(o4.BackupPath, Encoding.Unicode).Contains(@"Parziale\A]") && File.ReadAllText(o4.BackupPath, Encoding.Unicode).Contains(@"Parziale\Z]"));

                UnlockTree(h, Sandbox);

                // P5: collegamenti
                SetVal("Bersaglio", "x", "intatto");
                bool made = CreateLink(h, LinkDirect, "Bersaglio");
                h.CreateSubKey(Sandbox + @"\ConLink").Dispose();
                made &= CreateLink(h, LinkNested, "Bersaglio");
                t.Check("P5: collegamenti di prova creati", made);
                t.Check("P5: collegamento rilevato", RegNative.IsLink(h, LinkDirect) && !RegNative.IsLink(h, Sandbox + @"\Bersaglio"));
                Row direct = SandboxRow("LinkDiretto", null), nested = SandboxRow("ConLink", null);
                DeleteOutcome o5 = RunEngine(temp, "inj5", direct);
                t.Check("P5: collegamento diretto saltato", direct.Status == DeleteEngine.StatusLink && o5.Deleted == 0, direct.Status);
                DeleteOutcome o6 = RunEngine(temp, "inj6", nested);
                t.Check("P5: collegamento nel sottoalbero blocca l'eliminazione", o6.Deleted == 0 && o6.Errors == 1 && KeyThere("ConLink"), nested.Status);
                using (RegistryKey k = h.OpenSubKey(Sandbox + @"\Bersaglio", false))
                    t.Check("P5: bersaglio intatto", k != null && (k.GetValue("x") as string) == "intatto");
                RemoveLinks(h);
                t.Check("P5: collegamenti rimossi", !RegNative.IsLink(h, LinkDirect) && !RegNative.IsLink(h, LinkNested));
            }
            t.Check("iniezione: sandbox rimovibile dopo i guasti", RemoveSandbox());
        }

        // ---------------------------------------------------------------- scansione reale (sola lettura)

        static void TestRealScan(T t)
        {
            var scanner = new Scanner(CancellationToken.None, null);
            ScanResult res = System.Threading.Tasks.Task.Run(() => scanner.Run()).Result;
            t.Check("scansione reale: pacchetti e servizi vivi rilevati", scanner.LiveNameCount > 0);
            var del = res.Rows.Where(r => r.Deletable).ToList();
            int bad = 0, noHash = 0;
            string why, firstBad = null;
            foreach (Row r in del)
            {
                if (!DeleteGuard.Check(r.Hive, r.DeleteRoot, r.Action, r.ValueName, out why)) { bad++; if (firstBad == null) firstBad = r.TargetText; }
                if (r.ContentHash == null) noHash++;
            }
            t.Check("scansione reale: " + del.Count + " eliminabili passano tutte la protezione", bad == 0, firstBad);
            t.Check("scansione reale: tutte le eliminabili hanno l'impronta", noHash == 0, noHash.ToString());
            t.Check("scansione reale: nessuna eliminabile nei livelli vietati", del.All(r => Tiers.IsDeletable(r.Tier)));
            t.Check("scansione reale: non tocca la sandbox", res.Rows.All(r => r.KeyPath.IndexOf(DeleteGuard.SandboxName, StringComparison.OrdinalIgnoreCase) < 0));
            t.Check("scansione reale: voci HKLM ancora eliminabili (lettura senza scrittura)", del.Any(r => r.Hive == "HKLM"));
            using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                t.Check("IsLinkPath su HKLM non richiede scrittura", !RegNative.IsLinkPath(hklm, @"SOFTWARE\Microsoft\Windows"));
            var lost = res.Rows.Where(r => r.GuardRejection != null).ToList();
            foreach (var g in lost.GroupBy(r => r.GroupId + " :: " + r.GuardRejection))
                t.Out.AppendLine("INFO candidata esclusa: " + g.Count() + " " + g.Key + " (es. " + g.First().TargetText + ")");
            t.Out.AppendLine("INFO scansione reale: righe=" + res.Rows.Count + " eliminabili=" + del.Count + " candidate escluse=" + lost.Count);
        }

        static void TestSandbox(T t, string temp)
        {
            RemoveSandbox();
            BuildSandbox();
            t.Check("sandbox creata", Snapshot(Sandbox).Count > 10);

            // --- riga non eliminabile e righe rifiutate: nulla deve cambiare
            var before = Snapshot(Sandbox);
            Row nd = SandboxRow("Protetta", null); nd.Deletable = false;
            Row outside = new Row { Hive = "HKCU", KeyPath = @"Software\__RegistroScannerSelfTestAltra", DeleteRoot = @"Software\__RegistroScannerSelfTestAltra", Action = ActionKind.DeleteKey, Deletable = true };
            Row guardBlocked = new Row { Hive = "HKCU", KeyPath = "Software", DeleteRoot = "Software", Action = ActionKind.DeleteKey, Deletable = true };
            string tempFile = Path.Combine(temp, "esiste.txt");
            File.WriteAllText(tempFile, "x");
            Row probeBack = SandboxRow("Protetta", null, tempFile);
            DeleteOutcome oSkip = RunEngine(temp, "skip", nd, outside, guardBlocked, probeBack);
            string d0 = null;
            t.Check("motore: voce non eliminabile saltata", nd.Status.StartsWith("Saltata"));
            t.Check("motore: fuori sandbox saltata", outside.Status.StartsWith("Saltata"));
            t.Check("motore: guardia blocca Software", guardBlocked.Status.Contains("protezione"));
            t.Check("motore: file ricomparso saltato", probeBack.Status == "Saltata: il file ora esiste", probeBack.Status);
            t.Check("motore: nessuna modifica dopo i rifiuti", oSkip.Deleted == 0 && SameSnap(before, Snapshot(Sandbox), out d0), d0);

            // --- voce già assente
            Row missing = SandboxRow("NonEsiste", null);
            DeleteOutcome oMiss = RunEngine(temp, "miss", missing);
            t.Check("motore: voce assente saltata", missing.Status.StartsWith("Saltata") && oMiss.Skipped == 1);

            // --- valore: backup e cancellazione
            Row val = SandboxRow("", "da_eliminare");
            DeleteOutcome oVal = RunEngine(temp, "valore", val);
            t.Check("motore: valore eliminato", oVal.Deleted == 1 && val.Status == "Eliminata");
            using (RegistryKey h = Hkcu())
            using (RegistryKey k = h.OpenSubKey(Sandbox, false))
                t.Check("valore assente nel registro", k.GetValue("da_eliminare") == null);
            string vReg = File.ReadAllText(oVal.BackupPath, Encoding.Unicode);
            t.Check("backup valore contiene la voce", vReg.Contains("\"da_eliminare\"=\"addio\""));
            byte[] head = File.ReadAllBytes(oVal.BackupPath).Take(2).ToArray();
            t.Check("backup con BOM UTF-16 LE", head[0] == 0xFF && head[1] == 0xFE);
            t.Check("backup con intestazione", vReg.StartsWith("Windows Registry Editor Version 5.00\r\n"));
            t.Check("log scritto", File.Exists(oVal.LogPath) && File.ReadAllText(oVal.LogPath).Contains("Eliminata"));

            // --- chiave annidata
            Row sub = SandboxRow(@"Sub1\Sub2", null);
            DeleteOutcome oSub = RunEngine(temp, "sub", sub);
            t.Check("motore: sottochiave eliminata", oSub.Deleted == 1);
            using (RegistryKey h = Hkcu())
            {
                using (RegistryKey k = h.OpenSubKey(Sandbox + @"\Sub1\Sub2", false)) t.Check("sottochiave assente", k == null);
                using (RegistryKey k = h.OpenSubKey(Sandbox + @"\Sub1", false)) t.Check("chiave padre intatta", k != null);
            }
            t.Check("backup include il sottoalbero", File.ReadAllText(oSub.BackupPath, Encoding.Unicode).Contains(@"Sub1\Sub2\Sub3]"));

            // --- voce coperta dalla radice rimossa
            Row parent = SandboxRow("Scollegata", null), child = SandboxRow("Scollegata", "x");
            DeleteOutcome oCov = RunEngine(temp, "cov", child, parent);
            t.Check("motore: voce inclusa in chiave rimossa", oCov.Deleted == 2 && oCov.Errors == 0);

            // --- andata e ritorno: tutta la sandbox
            RemoveSandbox();
            BuildSandbox();
            var full = Snapshot(Sandbox);
            string all = Path.Combine(temp, "tutto.reg");
            Row whole = new Row { Hive = "HKCU", KeyPath = Sandbox, DeleteRoot = Sandbox, Action = ActionKind.DeleteKey, Deletable = true };
            DeleteOutcome oAll = DeleteEngine.Run(new[] { whole }, new DeleteOptions { BackupPath = all, LogPath = all + ".txt", SandboxOnly = @"HKCU\" + Sandbox });
            t.Check("motore: sandbox eliminata con backup", oAll.Deleted == 1 && Snapshot(Sandbox).Count == 0);

            string reg = File.ReadAllText(all, Encoding.Unicode);
            t.Check("file .reg: REG_SZ con escape", reg.Contains("\"sz\"=\"testo con \\\"virgolette\\\" e \\\\barre\\\\ e àèìòù €\""));
            t.Check("file .reg: nome con escape", reg.Contains("\"nome \\\"strano\\\"\\\\x\"=\"v\""));
            t.Check("file .reg: predefinito @", reg.Contains("@=\"valore predefinito\""));
            t.Check("file .reg: dword", reg.Contains("\"dword\"=dword:deadbeef"));
            t.Check("file .reg: expand hex(2)", reg.Contains("\"expand\"=hex(2):25,00,77,00"));
            t.Check("file .reg: multi hex(7)", reg.Contains("\"multi\"=hex(7):75,00"));
            t.Check("file .reg: binary hex", reg.Contains("\"binary\"=hex:00,01,02,fe,ff,0a,0d,00"));
            t.Check("file .reg: qword hex(b)", reg.Contains("\"qword\"=hex(b):ef,cd,ab,89,67,45,23,01"));
            t.Check("file .reg: none hex(0)", reg.Contains("\"none\"=hex(0):01,02,03"));
            t.Check("file .reg: tipo arbitrario hex(8)", reg.Contains("\"tipo8\"=hex(8):09,08,07,06"));
            t.Check("file .reg: sz con a capo in hex(1)", reg.Contains("\"sz_a_capo\"=hex(1):"));
            t.Check("file .reg: dword corto in hex(4)", reg.Contains("\"dword_corto\"=hex(4):01,02"));
            t.Check("file .reg: radice HKEY_CURRENT_USER", reg.Contains("[HKEY_CURRENT_USER\\" + Sandbox + "]"));
            t.Check("file .reg: solo chiavi sandbox", OnlySandboxHeaders(reg));

            if (OnlySandboxHeaders(reg))
            {
                int rc = RegImport(all);
                t.Check("reg.exe import esito 0", rc == 0, "exit " + rc);
                string diff;
                bool same = SameSnap(full, Snapshot(Sandbox), out diff);
                t.Check("andata e ritorno: valori identici (" + full.Count + " voci)", same, diff);
            }
            else t.Check("reg.exe import non eseguito", false);
        }

        static bool OnlySandboxHeaders(string reg)
        {
            string prefix = "[HKEY_CURRENT_USER\\" + Sandbox;
            foreach (string line in reg.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                if (line.StartsWith("[", StringComparison.Ordinal) && !line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            }
            return true;
        }

        static int RegImport(string file)
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.GetEnvironmentVariable("windir") ?? @"C:\Windows", @"System32\reg.exe"), "import \"" + file + "\"")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using (Process p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit(30000);
                return p.ExitCode;
            }
        }
    }
}
