# Modello delle minacce

Versione: 1.0  
Data: 7 ottobre 2026  
Stato: requisiti di sicurezza da verificare durante lo sviluppo. Nessuna protezione elencata è già implementata.  
Documento di riferimento: [architecture.md](architecture.md).

## 1. Scopo

Questo documento identifica cosa proteggere, chi può attaccare il sistema, quali controlli richiedere e quali rischi rimangono. Si applica ai client Android e Windows, al backend Go con SQLite su CasaOS, al tunnel HTTPS, alle email di registrazione, ai backup e alla distribuzione attraverso GitHub.

Ogni account possiede un vault indipendente. L'amministratore gestisce l'istanza e gli inviti, ma non riceve le chiavi degli utenti. Il codice email verifica l'indirizzo durante la registrazione; non è un secondo fattore dei login successivi. Nessuna assunzione di sicurezza dipende dal fatto che gli utenti iniziali siano amici.

La chiusura delle porte del router riduce l'esposizione diretta dell'host. Il servizio pubblico attraverso il tunnel continua a ricevere richieste potenzialmente ostili.

## 2. Beni da proteggere

| Bene | Proprietà richiesta |
| --- | --- |
| Master Password e chiavi derivate | Restano sul client; non compaiono in richieste, log o file in chiaro. |
| Chiave vault e recovery key | Confidenzialità, corretta separazione e accesso locale autorizzato. |
| Credenziali, note, URL, tag, segreti TOTP e chiavi passkey | Confidenzialità e integrità dei contenuti cifrati. |
| Verificatori, credenziali di autenticazione e sessioni | Accesso al solo account autorizzato; revoca e resistenza agli abusi. |
| Inviti e codici email | Uso autorizzato, scadenza, consumo singolo e riservatezza. |
| Database, cache, coda offline e backup | Coerenza, isolamento e recuperabilità. |
| Email degli account e metadati | Raccolta minima e accesso limitato. Non sono Zero-Knowledge. |
| Token tunnel, SMTP, chiavi di firma e account GitHub | Separazione dal repository e gestione operativa protetta. |
| CasaOS, Immich e Jellyfin | Nessuna esposizione o privilegio aggiuntivo necessario al password manager. |

## 3. Attaccanti e capacità considerate

1. **Attaccante Internet:** conosce l'URL, può inviare richieste, registrazioni e payload arbitrari, tentare credenziali e provocare errori.
2. **Utente autenticato ostile:** possiede un account valido e può manipolare identificatori, richieste e sincronizzazione per colpire altri account.
3. **Attaccante di rete:** controlla una rete Wi-Fi o DNS e tenta intercettazione, redirect o sostituzione del server.
4. **Ladro di dati:** ottiene database, backup o cache locali e può analizzarli offline senza limiti di tentativi imposti dalle API.
5. **Attaccante con server compromesso:** modifica risposte, configurazione, ciphertext e metadati, oppure cancella dati. Può usare tutti i privilegi del processo e, in caso di compromissione host, leggere i segreti operativi.
6. **Ladro di dispositivo:** possiede un telefono o PC bloccato, oppure una sua copia del disco.
7. **Malware sul client:** può avere accesso allo stesso utente, alla memoria, agli appunti o ai processi. Un controllo completo del sistema mentre il vault è aperto supera le garanzie del prodotto.
8. **Dipendenza o aggiornamento compromesso:** codice ostile viene introdotto nel client, backend, build o pacchetto distribuito.
9. **Errore operativo:** perdita delle chiavi, backup incompleto, pubblicazione di segreti, dominio sbagliato o aggiornamento incompatibile.

Cloudflare e il servizio SMTP costituiscono confini di fiducia esterni. Cloudflare può osservare il traffico API dopo la terminazione HTTPS; SMTP può osservare email e codici. Un operatore o servizio compromesso può interferire con tali flussi. La cifratura del vault non rende segreti questi metadati.

## 4. Flussi e superfici di attacco

| Flusso | Superficie da controllare |
| --- | --- |
| URL → `/api/v1/config` | Parsing URL, TLS, redirect, identità istanza, dimensioni e parametri KDF. |
| Invito → registrazione → email | Tentativi, abuso SMTP, stato pendente, concorrenza e attivazione. |
| Master Password → autenticazione | Derivazione client, separazione delle chiavi, verificatore server e protocollo. |
| Sessione → API vault | Autorizzazione per account, scadenza, replay e revoca. |
| Cache → decifratura → UI | Formato cifrato, autenticazione dei metadati, memoria, blocco e appunti. |
| Modifiche offline → sincronizzazione | Revisioni, conflitti, idempotenza, ordine e cancellazioni. |
| Sistema operativo → autofill/passkey | Identità del richiedente, origine, consenso e chiave selezionata. |
| Database → backup → ripristino | Snapshot coerente, chiavi cifrate, migrazioni e sessioni ripristinate. |
| GitHub → build → dispositivo | Dipendenze, permessi CI, firme e integrità della release. |

Il backend non deve contattare URL arbitrari salvati nel vault o ricevuti nella discovery: il client contatta il server selezionato. Non sono previsti fetch server di favicon o anteprime. Questo evita di aggiungere un percorso SSRF e di inviare URL dei servizi in chiaro.

## 5. Invarianti di sicurezza

- **I-01:** nessun messaggio verso backend, tunnel o SMTP contiene Master Password, recovery key, chiave vault in chiaro o credenziali decifrate del vault.
- **I-02:** il solo materiale di autenticazione non consente di ricavare la chiave vault senza attaccare la Master Password o compromettere il client.
- **I-03:** ogni lettura e scrittura server è autorizzata con l'account della sessione; un ID fornito dal client non stabilisce il proprietario.
- **I-04:** una registrazione pendente o un semplice codice email non concede accesso al vault né ruolo amministratore.
- **I-05:** un contenuto non autentico o un formato non supportato non viene mostrato né interpretato come credenziale valida.
- **I-06:** un fallimento TLS, biometrico o crittografico non provoca fallback silenzioso a una modalità meno protetta.
- **I-07:** una modifica concorrente non sovrascrive silenziosamente una versione differente.
- **I-08:** un backend compromesso non può ordinare al client di caricare segreti decifrati, cambiare libreria crittografica o eseguire codice scaricato dalla configurazione.
- **I-09:** nonce e chiavi devono rispettare il protocollo anche dopo reinstallazione, ripristino e scritture da più dispositivi.
- **I-10:** nessuna procedura amministrativa o di reset email costituisce una chiave universale per decifrare i vault.

## 6. Registro delle minacce

Le priorità sono qualitative: **P0** richiede soluzione e verifica prima del relativo componente utilizzabile; **P1** richiede controllo prima della distribuzione agli utenti. Non sono punteggi CVSS o stime della probabilità.

| ID | Minaccia e conseguenza | Controllo richiesto | Priorità |
| --- | --- | --- | --- |
| T-01 | Furto database e tentativi offline sulla Master Password. | Argon2id calibrato, salt casuale, chiavi separate, protezione del verificatore e scelta guidata di una Master Password robusta. I rate limit online non proteggono una copia rubata. | P0 |
| T-02 | Credenziale derivata intercettata o riutilizzata per impersonare l'utente. | Protocollo di autenticazione esplicito, HTTPS e trattamento della credenziale derivata come segreto; non dichiarare resistenza al replay se non prevista e verificata. | P0 |
| T-03 | Parametri KDF malevoli indeboliscono la derivazione o esauriscono memoria. | Limiti client minimi/massimi, versioni ammesse, nessun downgrade automatico e gestione degli errori. | P0 |
| T-04 | Riutilizzo nonce AES-GCM compromette confidenzialità e integrità. | Strategia nonce nel protocollo, budget d'uso per chiave e verifica multi-dispositivo, offline e dopo ripristino; nessun contatore locale ingenuo condiviso. | P0 |
| T-05 | Sostituzione di oggetti o involucri tra account. | AAD con contesto definito dal protocollo, identità account/vault/oggetto verificata e autorizzazione server indipendente. | P0 |
| T-06 | Utente A legge o modifica il vault B cambiando un ID. | Query e autorizzazione vincolate all'account della sessione su ogni operazione, incluse code, cancellazioni e endpoint amministrativi. | P0 |
| T-07 | Riutilizzo di invito o codice, oppure attivazione concorrente di più account. | Token casuali, scadenza, revoca, limiti ai tentativi e transazione con vincoli database per attivazione e consumo. | P0 |
| T-08 | Brute force, enumerazione email o invio massivo di email. | Risposte pubbliche uniformi dove possibile, rate limit per più dimensioni, quote SMTP e pulizia degli stati pendenti; evitare blocchi permanenti attivabili da terzi. | P1 |
| T-09 | Furto token di sessione, refresh riutilizzato o logout inefficace. | Token fuori da log e URL, archivio locale protetto, scadenze, rotazione e rilevamento riuso se si usano refresh token; revoca verificabile. | P0 |
| T-10 | Phishing mediante server diverso, redirect o identità cambiata. | URL HTTPS verificato, blocco redirect con credenziali, cache legata all'istanza e avviso esplicito al cambio di identità. Un ID dichiarato dal server non è da solo una prova crittografica della sua identità. | P0 |
| T-11 | Sblocco biometrico solo grafico, mentre la chiave è leggibile senza autenticazione. | Accesso crittografico vincolato alla protezione OS, controllo capacità, gestione chiavi invalidate e nessun fallback che riutilizzi la chiave senza autorizzazione. | P0 |
| T-12 | Secrets in appunti, log, screenshot, crash dump o cache. | Cache e indici cifrati, nessuna telemetria dei segreti, mascheramento UI, blocco al ciclo di vita, copia esplicita e gestione appunti descritta nella sezione 8. | P1 |
| T-13 | Autofill su dominio simile o firma passkey per un'origine diversa. | Validare identità del richiedente e relying party tramite API OS, controllare challenge e algoritmo, richiedere consenso e rifiutare richieste incoerenti. | P0 |
| T-14 | Vecchi ciphertext validi, revisioni contraffatte o cancellazione selettiva da server ostile. | Metadati autenticati e stato di sincronizzazione locale per rilevare incongruenze; nessuna promessa di freschezza assoluta. Backup separati per la perdita dati. | P0 |
| T-15 | Replay di scritture o conflitti provocano duplicazioni o perdita di aggiornamenti. | Operazioni idempotenti legate all'account, controllo revisione e conflitti espliciti, inclusa la cancellazione. | P0 |
| T-16 | Recupero email aggira la cifratura o furto recovery key apre il vault. | Recovery locale con involucro distinto, nessun reset email che decifri dati, revoca/rotazione documentate e recovery key mai inviata al server. | P0 |
| T-17 | Backup incompleto o ripristino resuscita sessioni e inviti revocati. | Backup SQLite coerente, verifica degli involucri, prova di ripristino e invalidazione delle sessioni e degli inviti precedenti prima di riaprire l'istanza. | P1 |
| T-18 | Richieste enormi o costose saturano CasaOS e gli altri servizi. | Limiti payload, timeout, paginazione, budget di verifica credenziali, concorrenza limitata e misure con Immich/Jellyfin attivi. | P1 |
| T-19 | Backend compromesso accede a Docker o espone gli altri servizi. | Rete interna, nessuna porta API pubblicata, nessun socket Docker, privilegi minimi e mount limitati. Una compromissione dell'host supera questi confini. | P0 |
| T-20 | Dipendenza o release compromessa sottrae chiavi dal client. | Dipendenze fissate e riesaminate, CI con permessi minimi, segreti separati, firme release e canale di aggiornamento verificabile. | P1 |

## 7. Minacce del server attivo e limiti della cifratura

Un server compromesso può controllare le risposte e mentire sulle revisioni. Il client deve trattare tutti i dati remoti come input non fidato e autenticare gli involucri prima di usare le chiavi contenute. La discovery non può modificare le regole crittografiche installate nel client.

Un amministratore ostile può negare l'accesso, cancellare il database o fornire materiale utile a tentativi offline sulla Master Password. Il prodotto non promette di proteggere una password debole da un server ostile.

Un ciphertext vecchio può essere ancora crittograficamente valido. Su un nuovo dispositivo senza stato precedente, o dopo un ripristino completo, la sola cifratura non distingue necessariamente l'ultimo stato da uno stato storico. Il protocollo dovrà precisare quali incongruenze può rilevare; per garantire freschezza globale contro un server malevolo servirebbero ulteriori meccanismi e un riferimento fidato distinto.

Il cambio della Master Password non rende inutilizzabili automaticamente le vecchie copie degli involucri rubati. Se un attaccante possiede una vecchia password e un involucro storico della stessa chiave vault, può recuperare quella chiave. Una compromissione confermata richiede valutare la rotazione della chiave vault, delle credenziali dei servizi e dei segreti TOTP; riproteggere soltanto la chiave vault non basta.

## 8. Dispositivo, TOTP e dati mostrati

La biometria protegge una chiave locale secondo le capacità del sistema. Non rende sicuro un vault già aperto contro malware con controllo completo del dispositivo. Chiavi non esportabili possono comunque essere usate abusivamente se il sistema compromesso soddisfa o aggira le condizioni di autorizzazione.

Appunti e campi decifrati sono esposizioni intenzionali e temporanee. La copia è esplicita; un timer tenta la cancellazione senza sovrascrivere un contenuto successivo dell'utente. Cronologia appunti, sincronizzazione OS e app terze possono conservare copie: il timer non revoca tali copie. Il client non copia automaticamente password o codici TOTP.

Le schermate sensibili sono mascherate nelle anteprime e protette dagli screenshot dove le API consentono una protezione verificata. Su Windows non si promette di impedire ogni cattura. I report di crash e i file temporanei non devono contenere payload decifrati.

Conservare password e TOTP dello stesso servizio nel medesimo vault significa che la compromissione del vault può esporli entrambi. L'authenticator integrato non equivale a una separazione fisica dei fattori. L'app usa l'orologio locale e segnala problemi noti senza inviare segreti TOTP per la correzione dell'ora.

## 9. Criteri di verifica

La tabella identifica prove richieste, non test già eseguiti. Parametri e risultati attesi esatti saranno fissati in `crypto-protocol.md` e `api-contract.md`.

| Verifica | Minacce | Risultato atteso |
| --- | --- | --- |
| Ispezione traffico, log, cache e file temporanei durante registrazione, login e modifica. | T-01, T-02, T-12 | Nessun segreto di decifratura o contenuto vault in chiaro; materiale di autenticazione confinato al flusso previsto. |
| Vettori comuni Android/Windows e alterazione di tag, nonce, AAD, account e versione. | T-03, T-04, T-05 | Interoperabilità e rifiuto degli input invalidi prima di esporre contenuti. |
| Scritture da due dispositivi offline e dopo ripristino. | T-04, T-15 | Strategia nonce rispettata, nessuna perdita silenziosa, operazioni ripetute senza duplicati. |
| Richieste utente A con tutti gli identificatori appartenenti a B. | T-06 | Nessuna lettura, scrittura o inferenza non autorizzata sui contenuti di B. |
| Registrazioni concorrenti, reinvii, scadenza e riutilizzo dei codici. | T-07, T-08 | Un invito attiva al massimo un account; limiti e scadenze effettivi. |
| Token scaduti, revocati e riutilizzati dopo rotazione. | T-09 | Rifiuto secondo il contratto; blocco locale e logout non sono confusi con la sola revoca server. |
| Certificato invalido, redirect verso host ostile, KDF fuori limite e cambio istanza. | T-03, T-10 | Nessun invio di credenziali al nuovo host e nessun downgrade automatico. |
| Biometria annullata, chiave invalidata e protezione hardware assente. | T-11 | Nessuno sblocco indebito; ritorno alla Master Password secondo la capacità dichiarata. |
| Richieste autofill/passkey con origine errata e app richiedente non autorizzata. | T-13 | Nessuna credenziale rilasciata o firma effettuata. |
| Server restituisce stato storico, tronca pagine o elimina dati. | T-14 | Rilevamento delle incongruenze coperte dal protocollo; limiti non rilevabili dichiarati. |
| Recupero con sola email, con recovery key valida e con chiave errata. | T-16 | L'email da sola non decifra; solo il percorso crittografico previsto recupera il vault. |
| Ripristino backup con vecchie sessioni e inviti. | T-17 | Dati decifrabili; credenziali operative obsolete invalidate prima dell'accesso pubblico. |
| Carico ostile con gli altri servizi CasaOS attivi. | T-18, T-19 | Richieste eccedenti limitate; risorse misurate e nessun accesso aggiuntivo ad altri container. |
| Ispezione release, permessi CI, dipendenze e segreti nel repository. | T-20 | Artefatti verificabili e nessun segreto personale o operativo pubblicato. |

Un fallimento di un'invariante o di un controllo P0 blocca il rilascio del componente interessato. Eventuali limiti P1 non risolti devono essere registrati esplicitamente e non possono essere presentati come protezioni completate.

## 10. Decisioni da fissare nei prossimi file

Prima del codice, la specifica crittografica deve definire il protocollo di autenticazione, compresa l'esposizione di una credenziale riutilizzabile al proxy TLS; parametri e formati; strategia nonce; protezione degli involucri; cambio password; recovery e rotazione. Non si introdurrà un protocollo crittografico artigianale per simulare una protezione dal replay.

Il contratto API deve fissare durata e revoca delle sessioni; quote e scadenze; transazioni di registrazione; idempotenza; conflitti; paginazione; controllo delle revisioni e procedure di ripristino. Le politiche biometriche e le versioni OS saranno fissate prima dell'integrazione nativa.

Questi sono passaggi pianificati della specifica, non segnaposto di codice o autorizzazione a procedere senza la verifica dell'utente. Si aggiornerà il modello se una decisione cambia un confine di fiducia o introduce una nuova superficie, per esempio estensioni browser, allegati o vault condivisi.

## 11. Riferimenti

Le scelte specifiche del progetto, le minacce e le prove richieste sono analisi progettuali. I riferimenti seguenti supportano i principi generali; non costituiscono una certificazione del prodotto.

- [OWASP — Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html): cifratura autenticata, casualità e gestione crittografica.
- [OWASP — Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html): protezione, scadenza e invalidazione delle sessioni.
- [OWASP — Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html): abusi dell'autenticazione e limitazione dei tentativi.
- [OWASP — Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html): scadenza e uso singolo dei token; il recupero Zero-Knowledge richiede la specifica distinta del progetto.
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106): derivazione memory-hard e vettori di test.
- [Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/): collegamento in uscita senza apertura delle porte in ingresso.
