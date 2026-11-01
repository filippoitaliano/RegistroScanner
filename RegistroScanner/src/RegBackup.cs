using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace RegistroScanner
{
    /// <summary>Lettura grezza dei valori: tipo nativo e byte esatti, senza espansioni.</summary>
    public sealed class RawValue
    {
        public string Name;
        public uint Type;
        public byte[] Data;
    }

    public static class RegNative
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegEnumValueW(SafeRegistryHandle hKey, uint index, StringBuilder name, ref uint nameLen, IntPtr reserved, out uint type, byte[] data, ref uint dataLen);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegQueryInfoKeyW(SafeRegistryHandle hKey, IntPtr cls, IntPtr clsLen, IntPtr reserved, IntPtr subKeys, IntPtr maxSub, IntPtr maxCls, out uint values, out uint maxValueName, out uint maxValueData, IntPtr sd, IntPtr lastWrite);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern int RegQueryValueExW(SafeRegistryHandle hKey, string name, IntPtr reserved, out uint type, byte[] data, ref uint dataLen);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        static extern int RegOpenKeyExRaw(SafeRegistryHandle hKey, string sub, uint options, int sam, out IntPtr result);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW")]
        static extern int RegQueryValueExRaw(IntPtr hKey, string name, IntPtr reserved, out uint type, IntPtr data, ref uint dataLen);

        [DllImport("advapi32.dll")]
        static extern int RegCloseKey(IntPtr hKey);

        const uint REG_OPTION_OPEN_LINK = 8, REG_LINK = 6;
        const int KEY_QUERY_VALUE = 1, KEY_WOW64_64KEY = 0x100;

        /// <summary>Come IsLink, partendo da una chiave base: l'handle delle chiavi base di HKLM richiede scrittura, quindi passa dal padre.</summary>
        public static bool IsLinkPath(RegistryKey baseKey, string path)
        {
            int i = path.LastIndexOf('\\');
            if (i <= 0) return false;
            using (RegistryKey p = baseKey.OpenSubKey(path.Substring(0, i), false))
                return p != null && IsLink(p, path.Substring(i + 1));
        }

        /// <summary>Vero se la sottochiave è un collegamento simbolico del registro (senza seguirlo).</summary>
        public static bool IsLink(RegistryKey parent, string sub)
        {
            IntPtr h;
            int rc = RegOpenKeyExRaw(parent.Handle, sub, REG_OPTION_OPEN_LINK, KEY_QUERY_VALUE | KEY_WOW64_64KEY, out h);
            if (rc != 0) return false;
            try
            {
                uint type, len = 0;
                rc = RegQueryValueExRaw(h, "SymbolicLinkValue", IntPtr.Zero, out type, IntPtr.Zero, ref len);
                return (rc == 0 || rc == ERROR_MORE_DATA) && type == REG_LINK;
            }
            finally { RegCloseKey(h); }
        }

        const int ERROR_MORE_DATA = 234, ERROR_NO_MORE_ITEMS = 259, ERROR_FILE_NOT_FOUND = 2;

        public static List<RawValue> ReadValues(RegistryKey k)
        {
            var list = new List<RawValue>();
            uint count, maxName, maxData;
            int rc = RegQueryInfoKeyW(k.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out count, out maxName, out maxData, IntPtr.Zero, IntPtr.Zero);
            if (rc != 0) throw new Win32Exception(rc);
            var nameBuf = new StringBuilder((int)maxName + 2);
            byte[] dataBuf = new byte[Math.Max(maxData + 2, 64)];
            for (uint i = 0; ; i++)
            {
                uint nl = (uint)nameBuf.Capacity, dl = (uint)dataBuf.Length, type;
                nameBuf.Length = 0;
                rc = RegEnumValueW(k.Handle, i, nameBuf, ref nl, IntPtr.Zero, out type, dataBuf, ref dl);
                if (rc == ERROR_NO_MORE_ITEMS) break;
                if (rc == ERROR_MORE_DATA)
                {
                    dataBuf = new byte[Math.Max(dl, (uint)dataBuf.Length * 2)];
                    nameBuf.EnsureCapacity((int)Math.Max(nl + 2, (uint)nameBuf.Capacity * 2));
                    i--;
                    continue;
                }
                if (rc != 0) throw new Win32Exception(rc);
                var d = new byte[dl];
                Array.Copy(dataBuf, d, (int)dl);
                list.Add(new RawValue { Name = nameBuf.ToString(0, (int)nl), Type = type, Data = d });
            }
            return list;
        }

        public static RawValue ReadValue(RegistryKey k, string name)
        {
            uint type, dl = 0;
            int rc = RegQueryValueExW(k.Handle, name, IntPtr.Zero, out type, null, ref dl);
            if (rc == ERROR_FILE_NOT_FOUND) return null;
            if (rc != 0 && rc != ERROR_MORE_DATA) throw new Win32Exception(rc);
            byte[] d = new byte[dl];
            rc = RegQueryValueExW(k.Handle, name, IntPtr.Zero, out type, d, ref dl);
            if (rc != 0) throw new Win32Exception(rc);
            if (dl != d.Length) Array.Resize(ref d, (int)dl);
            return new RawValue { Name = name, Type = type, Data = d };
        }
    }

    /// <summary>Serializzatore .reg (UTF-16 LE con BOM). Ogni voce è scritta e scaricata su disco prima della sua eliminazione.</summary>
    public sealed class RegBackupWriter : IDisposable
    {
        readonly FileStream _fs;
        readonly StreamWriter _w;

        public string Path { get; private set; }

        public RegBackupWriter(string path)
        {
            Path = path;
            _fs = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            _w = new StreamWriter(_fs, new UnicodeEncoding(false, true));
            _w.Write("Windows Registry Editor Version 5.00\r\n\r\n");
            _w.Write("; SID=" + CurrentSid() + " Utente=" + Environment.UserName + "\r\n\r\n");
            Flush();
        }

        void Flush()
        {
            _w.Flush();
            _fs.Flush(true);
        }

        static string CurrentSid()
        {
            try { using (var id = System.Security.Principal.WindowsIdentity.GetCurrent()) return id.User.Value; }
            catch (Exception) { return "sconosciuto"; }
        }

        public void WriteEntry(string text)
        {
            _w.Write(text);
            Flush();
        }

        public void Dispose()
        {
            _w.Dispose();
        }

        // ---- serializzazione (pura, testabile)

        public static string RegRoot(string hive)
        {
            if (hive == "HKLM") return "HKEY_LOCAL_MACHINE";
            if (hive == "HKCU") return "HKEY_CURRENT_USER";
            throw new ArgumentException("hive non ammesso: " + hive);
        }

        /// <summary>Serializza una chiave con tutte le sottochiavi. Solleva un'eccezione se qualcosa non è leggibile.</summary>
        public static string SerializeKey(string hive, RegistryKey key, string path)
        {
            var sb = new StringBuilder();
            AppendKey(sb, RegRoot(hive) + "\\" + path, key);
            return sb.ToString();
        }

        static void CheckName(string name)
        {
            if (name == null) return;
            foreach (char c in name)
                if (c == '\r' || c == '\n' || c == '\0') throw new InvalidDataException("Nome non rappresentabile in un file .reg (a capo o NUL): " + name.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\0", "\\0"));
        }

        static void AppendKey(StringBuilder sb, string fullPath, RegistryKey key)
        {
            CheckName(fullPath);
            sb.Append('[').Append(fullPath).Append("]\r\n");
            foreach (RawValue v in RegNative.ReadValues(key))
                sb.Append(FormatValue(v)).Append("\r\n");
            sb.Append("\r\n");
            foreach (string sub in key.GetSubKeyNames())
            {
                if (RegNative.IsLink(key, sub)) throw new InvalidDataException("La chiave contiene un collegamento del registro: " + fullPath + "\\" + sub);
                using (RegistryKey c = key.OpenSubKey(sub, false))
                {
                    if (c == null) throw new IOException("Sottochiave non leggibile: " + fullPath + "\\" + sub);
                    AppendKey(sb, fullPath + "\\" + sub, c);
                }
            }
        }

        public static string SerializeValue(string hive, string path, RawValue v)
        {
            CheckName(path);
            return "[" + RegRoot(hive) + "\\" + path + "]\r\n" + FormatValue(v) + "\r\n\r\n";
        }

        public static string FormatValue(RawValue v)
        {
            CheckName(v.Name);
            string name = string.IsNullOrEmpty(v.Name) ? "@" : "\"" + Escape(v.Name) + "\"";
            return name + "=" + FormatData(v.Type, v.Data);
        }

        static string Escape(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        static string FormatData(uint type, byte[] d)
        {
            switch (type)
            {
                case 1: // REG_SZ: testo solo se rappresentabile senza perdite
                    string text;
                    if (TryPlainString(d, out text)) return "\"" + Escape(text) + "\"";
                    return Hex("hex(1):", d);
                case 4: // REG_DWORD
                    if (d.Length == 4) return "dword:" + BitConverter.ToUInt32(d, 0).ToString("x8");
                    return Hex("hex(4):", d);
                case 3: return Hex("hex:", d);
                default: return Hex("hex(" + type.ToString("x") + "):", d); // 0 NONE, 2 EXPAND, 7 MULTI, b QWORD, altri
            }
        }

        static bool TryPlainString(byte[] d, out string text)
        {
            text = null;
            if (d.Length < 2 || d.Length % 2 != 0) return false;
            if (d[d.Length - 1] != 0 || d[d.Length - 2] != 0) return false;
            string s = Encoding.Unicode.GetString(d, 0, d.Length - 2);
            foreach (char c in s)
                if (c == '\0' || c == '\r' || c == '\n') return false;
            // Surrogati isolati e simili: il testo deve ricodificarsi negli stessi byte.
            byte[] re = Encoding.Unicode.GetBytes(s);
            if (re.Length != d.Length - 2) return false;
            for (int i = 0; i < re.Length; i++)
                if (re[i] != d[i]) return false;
            text = s;
            return true;
        }

        static string Hex(string prefix, byte[] d)
        {
            var sb = new StringBuilder(prefix, prefix.Length + d.Length * 3 + d.Length / 20 * 4);
            int col = prefix.Length + 2;
            for (int i = 0; i < d.Length; i++)
            {
                sb.Append(d[i].ToString("x2"));
                col += 3;
                if (i < d.Length - 1)
                {
                    sb.Append(',');
                    if (col >= 76) { sb.Append("\\\r\n  "); col = 2; }
                }
            }
            return sb.ToString();
        }
    }
}
