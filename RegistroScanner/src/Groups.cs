using System;
using System.Collections.Generic;

namespace RegistroScanner
{
    public sealed class GroupDef
    {
        public string Id, Area, Title, Why, How;
        public int? Conf;
        public bool RegistryDeletable; // false: il tipo di voce non prevede l'eliminazione
    }

    /// <summary>Gruppi, titoli, motivi e "come procedere" (portati da build.js e resi generici).</summary>
    public static class Groups
    {
        public const string AUn = "Programmi installati", APr = "Protocolli e tipi di file", ACo = "Componenti COM",
            AFw = "Regole firewall", AVe = "Chiavi di produttori", ATr = "Tracce di utilizzo", ASt = "Avvio automatico",
            AMs = "Windows Installer", ASh = "Shell e sistema", ASe = "Servizi";

        static readonly Dictionary<string, GroupDef> Map = new Dictionary<string, GroupDef>(StringComparer.Ordinal);

        static void D(string id, string area, int? conf, string title, string why, string how, bool del = true)
        {
            Map[id] = new GroupDef { Id = id, Area = area, Conf = conf, Title = title, Why = why, How = how, RegistryDeletable = del };
        }

        public static GroupDef Get(string id) { return Map[id]; }

        static Groups()
        {
            // --- Disinstallazione
            D("un-steam", AUn, 98, "Voci \"Steam App\" senza gioco", "Nessun manifest Steam corrisponde a questa voce: il gioco non è installato. La chiave è invisibile o inutile in Installazione app; Steam la ricrea se reinstalli il gioco.", "Elimina le singole chiavi.");
            D("un-dead", AUn, 97, "Programmi rimossi: resta la voce di disinstallazione", "Il programma di disinstallazione non esiste più e nemmeno la cartella di installazione: resta solo la voce nell'elenco.", "Elimina la chiave.");
            D("un-orphan", AUn, 92, "Voce di disinstallazione senza programma", "Non restano né il disinstallatore né la cartella del programma: la voce è solo un residuo nell'elenco.", "Elimina la chiave.");
            D("un-present", AUn, 55, "Programma presente, disinstallatore mancante", "Il disinstallatore manca ma i file del programma ci sono ancora: eliminare la voce nasconderebbe un programma reale.", "Reinstalla o ripara il programma, poi disinstallalo da PC Manager o dalle Impostazioni di Windows.", false);
            D("un-offline", AUn, 50, "Voce di disinstallazione su unità non collegata", "Il programma è su un'unità non collegata: non è possibile dire che sia stato rimosso.", "Ricollega l'unità e ripeti la scansione.", false);
            D("un-partial", AUn, 60, "Disinstallatore mancante, cartella presente", "Il disinstallatore manca ma la cartella del programma esiste ancora: il programma potrebbe essere danneggiato, non rimosso.", "Lascia: prova prima a riparare o reinstallare il programma.");
            D("un-stub", AUn, 45, "Voci vuote o storiche di Windows (IE40, WIC, DirectDrawEx…)", "Vuote ma create da Windows stesso. Non danno fastidio e tornano con gli aggiornamenti.", "Lascia.");
            D("un-vc", AUn, 30, "Patch KB di Visual C++", "Vuote, ma appartengono a runtime Visual C++ che i programmi possono usare ancora.", "Lascia.");

            // --- Protocolli e tipi di file
            D("pr-removed", APr, 95, "Protocolli di programmi disinstallati", "L'eseguibile non esiste e il programma non risulta installato. Se lo reinstalli, la voce viene ricreata.", "Elimina la chiave del protocollo (es. HKCU\\Software\\Classes\\nome).");
            D("pr-sec", APr, 96, "Protocolli che puntano a cartelle scrivibili (consigliata)", "Da pulire anche per sicurezza: chi riuscisse a mettere un file con quel nome in Download, Desktop o Temp verrebbe avviato da un link.", "Elimina le chiavi. Il programma le ricrea solo se lo riavvii.");
            D("pr-stale", APr, 75, "Protocolli con eseguibile mancante di un programma presente", "Il programma risulta presente ma questo eseguibile no. Probabili residui di una versione precedente; un aggiornamento li può ricreare.", "Facoltativo.");
            D("pr-bare", APr, 70, "Protocolli con comando non trovato", "Il comando non si trova nelle cartelle di sistema né nel PATH, ma potrebbe servire ai link se reinstalli il programma.", "Facoltativo.");
            D("pr-partial", APr, 35, "Tipi di file con verbi in parte funzionanti", "Almeno un altro comando della stessa classe funziona: eliminare la classe intera romperebbe anche quello.", "Non toccare.");
            D("pr-ext-unknown", APr, 80, "Estensioni con tipo di file inesistente", "L'estensione rimanda a un tipo di file che non esiste e non è riconducibile a un programma installato.", "Elimina la chiave dell'estensione se non riconosci il programma.");
            D("pr-ext-shared", APr, 60, "Estensioni usate anche da altri programmi", "Il tipo predefinito è inesistente, ma la chiave elenca altri programmi validi in OpenWithProgids.", "Lascia: eliminarla toglierebbe anche quelle associazioni.");
            D("pr-ext-vs", APr, 88, "Estensioni di un'istanza di Visual Studio rimossa", "Rimandano a un'istanza di Visual Studio non più presente. Una versione installata può riassegnarle.", "Pulibile.");
            D("pr-ext-win", APr, 20, "Estensioni predefinite di Windows o di programmi presenti", "Lo sembrano, ma sono voci di sistema (.eml, .mydocs, .desklink…) o scritte da programmi installati.", "Lascia.", false);
            D("pr-vs", APr, 35, "Voci di Visual Studio", "Appartengono a un'istanza di Visual Studio installata o sono gestite dal suo programma di installazione.", "Lascia: le gestisce il Visual Studio Installer.", false);
            D("pr-win", APr, 10, "ProgID e interfacce di Windows", "Incoerenze presenti di fabbrica in Windows o legate a programmi installati.", "Non toccare.", false);

            // --- COM
            D("co-removed", ACo, 94, "COM di programmi rimossi", "DLL o EXE inesistenti e programma non più presente: nessun programma installato li usa.", "Elimina i singoli CLSID, dopo aver esportato la chiave (il backup è automatico).");
            D("co-stale", ACo, 65, "COM di versioni vecchie di un programma presente", "Puntano a versioni passate; il programma c'è ancora e il suo aggiornamento li gestisce. Sono rifiuti, ma toglierli non dà vantaggi.", "Lascia: non vale il rischio.");
            D("co-ms", ACo, 55, "COM in cartelle Microsoft", "Il file manca, ma il percorso è di un componente Microsoft che può essere riscritto o usato da altri prodotti.", "Lascia, a meno che tu non sappia che è stato rimosso.");
            D("co-vs", ACo, 55, "Automazione di Visual Studio (DTE)", "Puntano a una versione di Visual Studio rimossa, ma i CLSID sono condivisi fra le versioni.", "Lascia: una riparazione di Visual Studio li sistema.");
            D("co-pkg", ACo, 60, "COM in cartelle di pacchetti Store", "Punta alla cartella dati di un pacchetto Store, che può essere temporanea: il componente può essere ancora in uso.", "Lascia finché usi quel programma.");
            D("co-partial", ACo, 30, "COM con server in parte funzionanti", "Almeno un altro server dello stesso componente funziona: eliminare la chiave romperebbe anche quello.", "Non toccare.");
            D("co-win", ACo, 5, "COM di Windows", "Di fabbrica Windows registra classi a 32 bit senza file corrispondente. I pulitori le segnalano sempre: sono la causa classica dei danni.", "Non toccare.");

            // --- Firewall
            const string fwNote = " La modifica ha effetto dopo il ricaricamento del servizio firewall o il riavvio. Serve l'amministratore.";
            D("fw-apps", AFw, 96, "Regole di giochi e app rimossi", "L'eseguibile non esiste più. Una reinstallazione richiede di nuovo il permesso." + fwNote, "Windows Defender Firewall > Impostazioni avanzate, oppure elimina da qui.");
            D("fw-user", AFw, 96, "Regole su cartelle dell'utente (consigliata)", "Molte consentono il traffico in ingresso verso percorsi dentro AppData, scrivibili senza privilegi: un file messo lì ottiene quel permesso." + fwNote, "Da pulire per prime.");
            D("fw-webview", AFw, 90, "Regole mDNS di WebView2 vecchi", "Una regola per ogni versione passata. Edge ne crea di nuove a ogni aggiornamento, quindi l'accumulo continuerà." + fwNote, "Pulibili; utilità solo estetica.");
            D("fw-stale", AFw, 60, "Regole di programmi ancora presenti", "La cartella del programma esiste ma il file no: probabile residuo di una versione o di un componente vecchio. Non è certo." + fwNote, "Lascia finché usi quel programma.");
            D("fw-steam", AFw, 70, "Regola di Steam Web Helper", "Steam è installato; il percorso è di una versione precedente." + fwNote, "Facoltativo.");
            D("fw-win", AFw, 25, "Regole di sistema di Windows", "L'eseguibile non esiste più, ma le regole fanno parte del set predefinito di Windows.", "Lascia.");

            // --- Windows Installer
            D("ms-other", AMs, 88, "Cartelle di programmi non più presenti", "Windows Installer ricorda cartelle che non esistono più, di programmi non rilevati. Può restare un pacchetto MSI collegato.", "Pulibile; se il pacchetto è ancora elencato in Installazione app, disinstallalo prima.");
            D("ms-present", AMs, 35, "Cartelle sotto un programma o produttore presente", "La cartella manca, ma il percorso superiore contiene programmi: non si può dire che il riferimento non serva più.", "Lascia.");
            D("ms-win", AMs, 20, "Cartelle di sistema", "Il riferimento riguarda cartelle di sistema o condivise.", "Lascia.");
            D("ms-shared", AMs, 65, "SharedDLLs di file inesistenti", "Contatori di file che non esistono più. Innocui anche se restano.", "Lascia: nessun vantaggio.");
            D("ms-cached", AMs, 30, "Prodotti MSI con dati mancanti", "Il pacchetto MSI in cache o la cartella del prodotto mancano. Modificare queste voci a mano può impedire la disinstallazione.", "Non toccare: usa Installazione app.", false);

            // --- Tracce
            D("tr-appcompat", ATr, 98, "Cronologia di compatibilità (AppCompat)", "Registra solo che il programma è stato eseguito o una sua impostazione di compatibilità. Il file non esiste più.", "Pulibile: nessun effetto sui programmi.");
            D("tr-mui", ATr, 99, "Cache dei nomi dei programmi (MuiCache)", "Nomi visualizzati dei programmi eseguiti. Windows la ricostruisce da sola.", "Pulibile. È una traccia anche ai fini della privacy.");
            D("tr-regapp", ATr, 94, "App registrate di programmi rimossi", "Puntano a una chiave Capabilities che non esiste più.", "Elimina il singolo valore.");
            D("tr-regappx", ATr, 65, "App registrate di pacchetti Store vecchi", "Riferimenti a pacchetti di build precedenti. Sono innocui e li gestisce Windows.", "Lascia: nessun vantaggio.");

            // --- Avvio
            D("st-orphan", ASt, 96, "Stato di avvio senza voce di avvio", "Interruttore di Gestione attività di un programma assente.", "Elimina il valore.");
            D("st-installed", ASt, 90, "Stato di avvio di programmi installati", "Il programma c'è ma non è più nella lista di avvio. Il valore si ricrea se lo riattivi.", "Facoltativo.");
            D("st-run", ASt, 88, "Avvio automatico con file mancante", "Windows tenta di avviare a ogni accesso un file che non esiste più.", "Elimina il valore.");

            // --- Shell
            D("sh-overlay", ASh, 85, "Icone di stato con CLSID non registrato", "CLSID non registrati. Gli spazi iniziali nel nome occupano i primi posti del limite di 15 overlay.", "Pulibile se non usi quel programma; tornano con la sua reinstallazione.");
            D("sh-apppaths", ASh, 80, "App Paths con eseguibile mancante", "La chiave punta a un eseguibile non più presente.", "Pulibile; il programma può riscriverla.");
            D("sh-win", ASh, 10, "Voci di shell di Windows", "Registrate di fabbrica: estensioni approvate storiche, gestori di tipi di file, font di sistema.", "Non toccare.", false);
            D("sh-winlogon", ASh, 10, "Winlogon, AppInit e IFEO con file mancante", "Voci critiche per l'avvio di Windows o dei programmi. Vanno esaminate a mano, mai cancellate in automatico.", "Non toccare.", false);
            D("sh-activesetup", ASh, 35, "Active Setup con file mancante", "Comando eseguito al primo accesso degli utenti. Può riguardare componenti di sistema.", "Non toccare.", false);
            D("sh-odbc", ASh, 35, "Driver ODBC con file mancante", "Il driver non esiste più, ma la voce può servire a un programma che lo reinstalla.", "Usa l'amministrazione origini dati ODBC.", false);
            D("sh-cpl", ASh, 35, "Pannello di controllo con file mancante", "Applet registrata senza file corrispondente.", "Non toccare.", false);
            D("sh-env", ASh, 35, "Variabili d'ambiente con percorso mancante", "La voce punta a una cartella che non esiste. Va modificata dentro il valore, non cancellata per intero.", "Modifica la variabile da Impostazioni di sistema.", false);
            D("sh-native", ASh, 35, "Native messaging con manifest mancante", "Il browser non trova il manifest dell'estensione nativa.", "Rimuovi l'estensione del browser o reinstalla il programma.", false);
            D("sh-bho", ASh, 35, "Browser Helper Object non registrato", "Componente di Internet Explorer con CLSID non registrato.", "Non toccare.", false);
            D("sh-task", ASh, 35, "Operazioni pianificate con file mancante", "L'operazione punta a un file che non esiste. Non è una voce eliminabile da qui.", "Usa Utilità di pianificazione.", false);
            D("sh-profile", ASh, 30, "Profili utente con cartella mancante", "Il profilo è registrato ma la cartella non esiste.", "Usa Sistema > Impostazioni avanzate > Profili utente.", false);

            // --- Servizi
            D("se-svc", ASe, 15, "Servizi e driver con immagine mancante", "Il file manca ora, ma servizi e driver (come gli anti-cheat) possono essere reinstallati al bisogno. Eliminarli può impedire l'avvio di giochi e programmi.", "Non toccare.", false);

            // --- Produttori
            D("ve-subkey", AVe, 80, "Sottochiavi di produttori con native messaging", "La chiave del produttore contiene NativeMessagingHosts usati da altri programmi: viene proposta solo la sottochiave, mai l'intera chiave.", "Elimina solo questa sottochiave.");
            D("ve-vs", AVe, 82, "Impostazioni utente di Visual Studio rimosso", "Chiave di un'istanza di Visual Studio non più presente.", "Pulibile; contengono solo preferenze.");
            D("ve-unknown", AVe, 80, "Produttore senza programma riconosciuto", "Nessun programma installato, servizio, pacchetto o cartella corrisponde a questo nome, e nessun percorso nella chiave esiste. Può trattarsi di un programma rimosso, di un gioco o di un driver: si possono perdere impostazioni e, in alcuni giochi, i progressi.", "Pulibile se non riconosci il produttore o non ti serve più. Il backup permette di ripristinarla.");
            D("ve-unsure", AVe, 55, "Origine non verificata", "Nessun programma riconosciuto con certezza, ma potrebbero servire: al più resta una cartella di dati.", "Lascia, a meno che tu non riconosca il programma.");
            D("ve-keep", AVe, 15, "Verificate e da tenere", "Il programma è presente oppure sono chiavi di Windows, driver e runtime.", "Non toccare.");

            // --- Falsi positivi
            D("fp", ASh, null, "Falsi positivi esclusi", "Sembravano orfane ma non lo sono: segnaposto \"%1\", comandi senza estensione, percorsi con \"/\", cartelle protette, voci senza stringa di disinstallazione.", "Non toccare. Un pulitore automatico le segnalerebbe.", false);
        }
    }

    /// <summary>Chiavi e classi di Windows, runtime e driver. I programmi installati si riconoscono solo da prove a runtime.</summary>
    public static class Hints
    {
        static HashSet<string> S(params string[] a) { return new HashSet<string>(a, StringComparer.OrdinalIgnoreCase); }

        /// <summary>Chiavi di sistema: sempre "da tenere".</summary>
        public static readonly HashSet<string> SystemKeys = S(
            "Microsoft", "Classes", "Policies", "Clients", "RegisteredApplications", "ODBC", "Windows", "Windows NT",
            "WOW6432Node", "Khronos", "ASIO", "AGEIA Technologies", "AGEIA", "OEM", "Partner", "OpenSSH", "Setup",
            "DefaultUserEnvironment", "Intel", "NVIDIA Corporation", "NVIDIA", "AMD", "ATI", "dotnet", "Realtek", "JavaSoft", "JreMetrics",
            "Oracle", "Accessibility", "AppDataLow", "IM Providers", "Sysinternals", "EasyAntiCheat", "EasyAntiCheat_EOS", "QtProject", "Node.js");

        /// <summary>Classi di sistema mai eliminabili (usato anche dal guard di eliminazione).</summary>
        public static readonly HashSet<string> SystemClasses = S(
            "*", "AllFilesystemObjects", "Directory", "Drive", "Folder", "Unknown", "Applications", "SystemFileAssociations", "DesktopBackground", "Network",
            "exefile", "batfile", "cmdfile", "comfile", "piffile", "scrfile", "dllfile", "lnkfile", "htafile", "inifile", "inffile", "regfile", "txtfile",
            "vbsfile", "vbefile", "jsfile", "jsefile", "wsffile", "wshfile", "mscfile", "cplfile", "sysfile", "ocxfile", "fonfile", "otffile", "ttffile", "ttcfile", "icofile", "icmfile",
            "htmlfile", "shtmlfile", "mhtmlfile", "xmlfile", "Msi.Package", "Msi.Patch", "Microsoft.PowerShellScript.1", "http", "https", "ftp", "file", "mailto", "ms-settings", "ms-windows-store", "shell",
            "CLSID", "Interface", "TypeLib", "Installer", "AppID", "WOW6432Node", "Local Settings", "Record", "Licenses", "MIME", "Media Type", "PackagedCom", "ActivatableClasses", "Extensions",
            ".exe", ".dll", ".com", ".bat", ".cmd", ".lnk", ".msc", ".msi", ".reg", ".scr", ".sys", ".txt", ".ini", ".inf", ".pif", ".vbs", ".js", ".ps1", ".htm", ".html", ".xml", ".url", ".zip", ".cpl", ".ocx", ".ttf", ".ico", ".eml",
            ".doc", ".docx", ".docm", ".dot", ".dotx", ".xls", ".xlsx", ".xlsm", ".xlt", ".xltx", ".ppt", ".pptx", ".pptm", ".pot", ".potx", ".pdf", ".rtf", ".csv", ".odt", ".ods", ".odp", ".msg", ".one", ".pst", ".vsd", ".vsdx", ".mdb", ".accdb",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".svg", ".heic", ".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".wma", ".wmv", ".avi", ".mkv", ".mov", ".flac", ".ogg", ".aac", ".mpg", ".mpeg",
            ".7z", ".rar", ".tar", ".gz", ".cab", ".iso", ".json", ".md", ".log", ".css", ".wsf", ".wsh", ".hta", ".jse", ".vbe", ".msp", ".appx", ".msix", ".appinstaller", ".library-ms", ".search-ms", ".theme", ".themepack",
            "InternetShortcut", "CompressedFolder", "Word.Document", "Excel.Sheet", "PowerPoint.Show", "AcroExch.Document",
            "findapp.dvd", "msstoragesense");

        static readonly string[] SystemClassPrefixes = { "diagnostic.", "word.", "excel.", "powerpoint.", "outlook.", "onenote.", "access.", "visio.", "publisher.", "msproject.", "acroexch.", "acrobat.", "microsoft.", "windows.", "windowsmediaplayer", "wmp", "shell.", "wscript.", "scripting.", "appx" };

        public static bool IsSystemClass(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            if (SystemClasses.Contains(name)) return true;
            string l = name.ToLowerInvariant();
            foreach (string p in SystemClassPrefixes)
                if (l.StartsWith(p, StringComparison.Ordinal)) return true;
            return false;
        }
    }
}
