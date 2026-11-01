# Registro Scanner

Applicazione Windows (WinForms, .NET Framework 4.7.2) che cerca nel registro le voci orfane, le mostra in una griglia filtrabile, esporta CSV ed elimina le voci selezionate dopo un riepilogo, con backup `.reg`.

## Perimetro

L'applicazione fa una cosa sola: analizza e pulisce il registro. Disinstallare i programmi e pulire i file restano compiti di PC Manager e delle Impostazioni di Windows: qui non esistono un comando di disinstallazione né l'avvio dei disinstallatori.

## Compilazione

Eseguire `build.cmd` da qualsiasi cartella. L'output è `..\RegistroScanner.exe`, accanto alla cartella `RegistroScanner`. I percorsi del progetto sono relativi, quindi la cartella si può spostare.

Sono assoluti solo i percorsi degli strumenti, nelle prime righe di `build.cmd`. Su un'altra macchina vanno adattati:

- `CSC`: il `csc.exe` di Roslyn fornito con Visual Studio;
- `REF`: gli assembly di riferimento di .NET Framework 4.7.2.

Nessun pacchetto NuGet e nessun accesso alla rete.

## Riga di comando

| Comando | Effetto |
|---|---|
| `RegistroScanner.exe` | Apre l'interfaccia. Non avvia la scansione da sola. |
| `--scan-csv <file> [--summary <file>]` | Scansione in sola lettura: CSV di tutte le righe e riepilogo per livello e gruppo. Il CSV ha in più le colonne `Eliminabile` e `Destinazione`. |
| `--selftest <file>` | Autotest, scrive righe PASS/FAIL. Scrive nel registro solo in `HKCU\Software\__RegistroScannerSelfTest` e la rimuove alla fine. Esegue anche una scansione in sola lettura. |
| `--ui-smoke <cartella>` | Prova l'interfaccia senza clic: scansione, filtri, ordinamento, selezione, riepilogo e schermate PNG. Non chiama il motore di eliminazione. |

Non c'è console: gli esiti sono nei file e nel codice di uscita. `0` indica successo.

## Sorgenti (`src\`)

| File | Contenuto |
|---|---|
| `Program.cs` | Punto di ingresso e comandi da riga di comando |
| `AssemblyInfo.cs` | Attributo del framework di destinazione |
| `Model.cs` | Riga del risultato, livelli |
| `Groups.cs` | Gruppi con motivi in italiano, chiavi e classi di sistema |
| `PathProbe.cs` | Verifica di percorsi e righe di comando |
| `Corpus.cs` | Programmi installati, costruiti a runtime |
| `Scanner.cs` | Sezioni di scansione e classificazione |
| `DeleteGuard.cs` | Allowlist delle destinazioni eliminabili |
| `RegBackup.cs` | Lettura grezza dei valori, collegamenti, serializzatore `.reg` |
| `DeleteEngine.cs` | Riverifica, backup, eliminazione, registro degli esiti |
| `RowView.cs` | Filtri, selezione, CSV, rilevamento dell'account |
| `MainForm.cs`, `Dialogs.cs` | Interfaccia e dialoghi |
| `SelfTest.cs` | Autotest |

## Regole di sicurezza per le modifiche

1. **Prove:** mai eliminare voci reali. Le prove di scrittura vanno solo in `--selftest` e solo nella chiave sandbox, che deve risultare rimossa alla fine. Non serve l'elevazione.
2. **Scansione:** resta in sola lettura. Ogni chiave si apre con `writable = false` e vista `Registry64`.
3. **`DeleteGuard`:** è un'allowlist indipendente dalla classificazione. Ciò che non corrisponde a una forma ammessa viene rifiutato. Per ogni nuova forma aggiungere test di accettazione e di rifiuto. Non indebolirla per far passare una riga.
4. **Niente eliminazione senza copia:** il backup di ogni voce è scritto e scaricato su disco prima della cancellazione. Al primo errore di scrittura la corsa si ferma.
5. **Esito verificato:** dopo la cancellazione si rilegge il registro. Una voce ancora presente è "non eliminata" oppure "ELIMINATA IN PARTE". Non dichiarare mai un'eliminazione non verificata.
6. **Riverifica prima di cancellare:** impronta del contenuto, stato del file giustificante, collegamenti del registro, righe non selezionate coperte dalla chiave.
7. **Assenza dimostrata:** un accesso negato non vale come file assente.
8. **Solo voci generali in `Hints`:** contiene unicamente chiavi e classi di Windows, runtime e driver. Non aggiungere nomi di giochi, programmi o produttori presi da una macchina specifica. Regole pubbliche di piattaforma, come Steam, Epic, Visual Studio ed EdgeUpdate, sono ammesse.
9. **Nessun nome fisso al posto delle prove:** un nome scritto nel codice non può mai dimostrare che un programma è installato o rimosso. Il software installato si riconosce da prove raccolte a runtime: pacchetti installati per l'utente, servizi vivi, voci di disinstallazione vive, cartelle con eseguibili. Nel codice e negli autotest non vanno nomi utente, percorsi personali o dati di una macchina; negli esempi si usano nomi inventati come Contoso e Fabrikam.
10. **Selezione:** i comandi agiscono solo su righe visibili ed eliminabili. Le righe "Meglio lasciare" entrano in massa solo con il filtro Livello su quel livello.
11. **Livelli non eliminabili:** "Non toccare" e "Falso positivo" non sono mai eliminabili.
12. **Testi:** tutta l'interfaccia è in italiano. Etichetta del livello e testo "Come procedere" devono essere coerenti.

Il file `.reg` non conserva ACL, nome di classe e volatilità delle chiavi.
