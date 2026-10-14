# Architettura del password manager

Versione del documento: 1.0  
Data: 7 ottobre 2026  
Stato: proposta iniziale da verificare prima dell'implementazione.

## 1. Obiettivo e perimetro

Applicazione self-hosted per gestire credenziali personali, con client Android e Windows e backend containerizzato per CasaOS. Il progetto sarà pubblicabile su GitHub e installabile da altri amministratori su istanze indipendenti.

La prima istanza sarà utilizzata dall'amministratore e da un amico. Il server dispone di 8 GB di RAM ed esegue già Immich e Jellyfin. Non sono previsti vault condivisi: ogni account ha un vault privato. Il prodotto richiama le funzionalità di Bitwarden, senza richiedere compatibilità con il suo protocollo o con i suoi client.

La progettazione comprende credenziali con username, email, password, URL, note e tag; TOTP locale; generatore di password e passphrase; ricerca locale; sincronizzazione offline; recovery key opzionale; Dark Mode; autofill e provider passkey attraverso integrazioni native.

Le funzioni passkey e biometriche hanno requisiti di sistema propri. Le versioni minime e le capacità effettivamente supportate saranno definite e verificate prima di implementare tali integrazioni. Il supporto dell'app desktop non implica automaticamente il supporto provider passkey su ogni versione di Windows.

## 2. Stack e componenti

| Componente | Tecnologia e responsabilità |
| --- | --- |
| Client Android/Windows | Flutter e Dart; Riverpod per lo stato; UI adattiva e logica condivisa. |
| Integrazioni Android | Kotlin: Keystore, autenticazione biometrica, autofill e Credential Provider. |
| Integrazioni Windows | Componenti nativi per archivio protetto, Windows Hello e provider passkey, secondo le API supportate. |
| Backend | Go, API REST versionate sotto `/api/v1`, gestione account e sincronizzazione. |
| Database | SQLite su volume locale persistente; una sola istanza backend in scrittura. |
| Distribuzione | Docker Compose, integrazione CasaOS e immagini per le architetture supportate e testate. |
| Accesso remoto | Cloudflare Tunnel con hostname HTTPS stabile, senza port forwarding sul router. |
| Email | Servizio SMTP configurato dall'amministratore per la verifica iniziale dell'indirizzo. |

Il server non implementa la crittografia del contenuto del vault. Le librerie client saranno selezionate verificando manutenzione, piattaforme supportate e vettori di test: nessuna primitiva crittografica sarà implementata artigianalmente.

## 3. Confini di fiducia e rete

Percorso online: client → HTTPS pubblico → Cloudflare → tunnel → backend Go → SQLite.

Il connettore `cloudflared` stabilisce connessioni in uscita. Backend e tunnel comunicano attraverso una rete Docker privata, senza pubblicare la porta API sull'host nella configurazione prevista. CasaOS, Immich, Jellyfin e le interfacce amministrative non sono esposti dal tunnel di questo progetto.

L'hostname dell'app resta pubblico: mantenere chiuse le porte del router non elimina attacchi alle API. Sono necessari autorizzazione per risorsa, limiti ai tentativi, controllo degli input e aggiornamenti.

Cloudflare termina HTTPS all'edge e può osservare richieste API, indirizzi email, materiale di autenticazione in transito e metadati. La cifratura del vault è un livello distinto dal trasporto TLS e protegge i suoi contenuti anche lungo questo percorso. L'operatore del servizio email può osservare destinatari e codici di verifica. Nessuno dei due servizi deve ricevere chiavi del vault o Master Password.

Il client verifica normalmente i certificati HTTPS. Non sono previsti bypass TLS, fallback HTTP automatici o invio di credenziali attraverso redirect verso host diversi. Le credenziali sono associate all'identità del server selezionato.

## 4. Significato di Zero-Knowledge

Il server non riceve la Master Password, le chiavi di decifratura o il contenuto del vault in chiaro. Il termine riguarda i contenuti del vault, non l'assenza totale di informazioni sull'account.

| Dati | Visibilità server |
| --- | --- |
| Password, username ed email dei servizi salvati, URL, note, tag | Solo contenuto cifrato. |
| Segreti TOTP e chiavi private delle passkey sincronizzabili | Solo contenuto cifrato. |
| Chiave vault | Solo involucro cifrato prodotto dal client. |
| Master Password e recovery key | Mai ricevute. |
| Email dell'account, stato di verifica, ruolo | Visibili e necessari alla gestione dell'account. |
| Salt e parametri di derivazione, versione del formato | Visibili; non sono segreti. |
| Verificatore di autenticazione, sessioni e stato degli inviti | Gestiti dal server, protetti come dati sensibili. |
| Identificatori opachi, revisioni, dimensioni e tempi di sincronizzazione | Metadati operativi visibili. |

La ricerca dei contenuti avviene sul client. Log e messaggi di errore non includono segreti, header di autorizzazione, inviti, codici email o payload del vault.

Un dispositivo compromesso mentre il vault è aperto può accedere ai dati. Il furto dei dati server può consentire tentativi offline contro Master Password deboli. La cifratura autenticata rileva modifiche ai ciphertext, ma da sola non prova che il server abbia restituito la versione più recente e non impedisce la cancellazione dei dati. Questi limiti saranno trattati nel modello delle minacce.

## 5. Gerarchia delle chiavi

Il client usa Argon2id con salt casuale per account. I parametri sono versionati e calibrati sui dispositivi target; il client impone limiti minimi e massimi ai parametri ricevuti dal server.

Dal materiale derivato si ottengono, con HKDF-SHA-256 e contesti distinti, una chiave per proteggere la chiave vault e materiale separato per l'autenticazione. Il materiale inviato al server non deve consentire di derivare la chiave di cifratura. Se il protocollo usa una credenziale derivata riutilizzabile, questa resta un segreto di autenticazione e richiede protezione da furto e replay.

La chiave vault è casuale, a 256 bit, generata sul client e conservata sul server soltanto cifrata. AES-256-GCM cifra i contenuti e autentica i metadati di contesto. Ogni operazione deve usare un nonce unico per la propria chiave, anche con più dispositivi e modifiche offline.

Il cambio della Master Password riprotegge la chiave vault e aggiorna il materiale di autenticazione con un'operazione coerente. La rotazione della chiave vault è un'operazione distinta e richiede la ricifratura dei contenuti.

Il documento `crypto-protocol.md` dovrà fissare formati byte per byte, normalizzazione delle password, contesti HKDF, parametri, gestione nonce, autenticazione, rotazione e vettori di test prima dell'implementazione. Questo documento non costituisce da solo una specifica crittografica implementabile.

## 6. Inizializzazione del server

1. L'amministratore configura volume dati, hostname pubblico e SMTP e avvia i container.
2. Una procedura locale crea il primo account amministratore e ne verifica l'email; l'attivazione del vault segue le stesse regole crittografiche degli altri account.
3. L'inizializzazione è consentita una sola volta e non è un endpoint pubblico che assegna il ruolo amministratore al primo visitatore.
4. L'amministratore genera inviti personali monouso, con scadenza e revoca, e comunica URL e invito all'utente attraverso un canale scelto da lui.

Non sono previsti password predefinite o segreti condivisi tra installazioni. Il codice d'invito viene generato con un generatore casuale crittograficamente sicuro; il server ne conserva una rappresentazione verificabile, non il valore originale. Le azioni amministrative richiedono autorizzazione distinta dalle normali azioni sul vault.

L'amministratore può gestire accessi e inviti, ma non sbloccare i vault degli altri utenti.

## 7. Primo avvio, discovery e registrazione

1. L'app mostra URL server e codice d'invito.
2. Interroga `/api/v1/config` tramite HTTPS per verificare protocollo, identità dell'istanza e funzionalità supportate. L'endpoint pubblico non rivela segreti o dati degli account.
3. Verifica l'invito; il collegamento resta provvisorio finché la registrazione non termina. Il codice non è necessario per i futuri login e non viene conservato come password dell'app.
4. L'utente inserisce email e Master Password. Il client genera e protegge la chiave vault e prepara il materiale di autenticazione.
5. Il server crea una registrazione pendente e invia il codice email. Tale stato non permette l'accesso alle API del vault.
6. Il codice ha scadenza, numero limitato di tentativi e limiti ai reinvii. Le registrazioni interrotte possono essere riprese senza consumare definitivamente l'invito.
7. Alla verifica corretta, attivazione dell'account e consumo dell'invito avvengono atomicamente. Le registrazioni concorrenti non possono riutilizzare lo stesso invito.
8. L'app salva il server e l'account selezionato e apre il vault.

Il codice email dimostra il controllo iniziale dell'indirizzo: non è un secondo fattore richiesto nei login successivi e non sblocca il vault.

## 8. Login, sblocco e sessioni

Il login online autentica l'account presso il server. Lo sblocco rende utilizzabile sul dispositivo la chiave vault: sono operazioni separate.

- Su un nuovo dispositivo sono necessarie email e Master Password, ma non un nuovo invito per un account esistente.
- Su un dispositivo configurato l'app ricorda server ed email. Richiede la Master Password per sbloccare il vault oppure propone la biometria se abilitata.
- Il client può conservare una sessione revocabile secondo la politica che sarà definita nel contratto API. Nessuna sessione server sostituisce la chiave necessaria alla decifratura.
- La biometria autorizza l'accesso al materiale locale protetto dal sistema: non si limita a una finestra grafica. Se la protezione richiesta non è disponibile, si usa la Master Password senza dichiarare una protezione hardware inesistente.
- Il blocco automatico elimina i riferimenti alle chiavi in uso e riduce la permanenza dei dati sensibili in memoria. Non si promette una cancellazione perfetta della memoria in un runtime gestito.
- Il logout elimina sessioni e materiale locale di sblocco; la rimozione della cache cifrata segue una scelta esplicita e documentata.

La verifica email non viene richiesta a ogni login. Modifica dell'email, revoca dei dispositivi e altre operazioni sensibili richiederanno politiche dedicate prima di essere aggiunte.

## 9. Vault locale e sincronizzazione

Il client conserva ciphertext e metadati minimi in una cache locale. Contenuti decifrati e indici di ricerca non sono salvati in chiaro su disco.

Gli oggetti hanno identificatori opachi e revisioni controllate dal server. Le modifiche indicano la revisione di partenza; gli aggiornamenti concorrenti producono un conflitto esplicito, senza sovrascrivere silenziosamente una versione. Le cancellazioni sono sincronizzate con marcatori e una politica di conservazione documentata.

Le modifiche offline rimangono cifrate in una coda persistente e vengono inviate dopo il ripristino della sessione online. Le operazioni sono idempotenti per evitare duplicazioni durante i tentativi ripetuti. Account e istanze hanno cache e credenziali separate.

La revoca server impedisce nuove operazioni online, ma non cancella una copia già scaricata da un dispositivo offline. Il server non può garantire disponibilità o freschezza assoluta dei dati: backup e controllo delle revisioni sono parte del progetto.

## 10. TOTP, autofill e passkey

Il TOTP richiesto usa HMAC-SHA1, sei cifre e intervallo standard di 30 secondi. Il segreto rimane nel vault cifrato e i codici sono calcolati localmente. Una differenza nell'orologio del dispositivo può renderli non validi.

Password e passphrase sono generate con casualità crittograficamente sicura. Il dizionario delle passphrase e la sua licenza saranno inclusi e verificati prima della distribuzione.

Autofill e provider passkey verificano il sito o l'app richiedente attraverso le informazioni di origine e identità fornite dal sistema operativo. L'autorizzazione dell'utente e la verifica del relying party non sono sostituite da una semplice corrispondenza testuale del nome.

Le passkey per altri siti sono distinte dal login al nostro server, che inizialmente resta basato sulla Master Password. Le chiavi private delle passkey sincronizzabili sono cifrate nel vault. Le chiavi di un token FIDO2 hardware non esportabile restano sul token e non possono essere copiate nel vault.

Le integrazioni native saranno validate su dispositivi reali. Il supporto in browser Windows potrà richiedere un componente specifico: non si assume che la sola UI Flutter fornisca autofill universale.

## 11. Recovery e backup

La recovery key opzionale è un segreto casuale generato sul client e consegnato all'utente. Protegge un involucro aggiuntivo della chiave vault. Il suo uso e l'eventuale ripristino dell'autenticazione dovranno essere definiti nel protocollo; il possesso dell'email da solo non recupera il vault.

Chi possiede recovery key e dati cifrati corrispondenti può recuperare il vault. Perdita della Master Password, della recovery key e di ogni dispositivo ancora sbloccabile può rendere i contenuti irrecuperabili.

I backup includono database, involucri delle chiavi e versioni del formato e sono eseguiti con una procedura SQLite coerente; non basta copiare arbitrariamente un database in uso in modalità WAL. Configurazione e segreti operativi sono salvati separatamente e protetti.

Il ripristino viene provato su una nuova istanza. Backup, recovery key e copie esportate richiedono conservazione sicura; non vengono inclusi nel repository.

## 12. CasaOS, risorse e pubblicazione

Argon2id viene eseguito sui client. Il backend rimane a istanza singola con pool e concorrenza limitati, limiti sulle dimensioni dei payload e timeout. Anche la verifica server delle credenziali riceve un budget di risorse. Consumo effettivo e limiti Docker saranno misurati insieme ai carichi di Immich e Jellyfin, senza promettere in anticipo una quantità fissa di RAM.

I container operano con privilegi minimi e volumi espliciti. Il servizio non richiede modalità privilegiata o accesso al socket Docker. Il tunnel non concede accesso amministrativo a CasaOS.

GitHub conterrà codice, istruzioni, esempi senza segreti e controlli automatici. Restano esclusi database, file di ambiente reali, token Cloudflare, credenziali SMTP, chiavi di firma e dati degli utenti. La licenza del progetto dovrà essere scelta prima della pubblicazione.

Le release Android e Windows avranno procedure di build, firma e verifica documentate. Una prima versione funzionale non sarà presentata come equivalente a un password manager sottoposto ad audit indipendente.

## 13. Verifiche prima dell'uso reale

- Vettori crittografici identici su Android e Windows; rifiuto di ciphertext alterati e password errate.
- Registrazione, inviti concorrenti, codici scaduti e limiti ai tentativi.
- Isolamento tra utenti su ogni operazione, inclusi identificatori e sincronizzazione.
- Sessioni scadute o revocate, sblocco locale e cambio server.
- Conflitti offline, cancellazioni e ripresa dopo interruzione.
- Backup e ripristino con accesso ai contenuti recuperati.
- Nessuna Master Password, chiave o credenziale del vault in richieste server, log e file locali in chiaro.
- Accesso remoto funzionante con port forwarding disabilitato e senza esposizione degli altri servizi CasaOS.

## 14. Ordine di lavoro e prossimi documenti

Su richiesta dell'utente dell'8 ottobre 2026, si procede per moduli completi con i relativi test, senza richiedere una verifica manuale dopo ogni file. Le verifiche automatiche sono eseguite durante lo sviluppo; le prove dell'utente si concentrano su passaggi utilizzabili come avvio del server, registrazione, login e client. Ogni file consegnato contiene un'implementazione completa del proprio compito. I documenti `threat-model.md`, `crypto-protocol.md` e `api-contract.md` precedono l'implementazione delle funzioni di sicurezza che descrivono.

Durante le implementazioni si verificano i componenti con test significativi e compatibilità reale. Non sono consentiti segnaposto di implementazione nei file consegnati.

## 15. Riferimenti tecnici

- Flutter, piattaforme e integrazione nativa: https://docs.flutter.dev/resources/faq
- Argon2id e vettori di test: https://www.rfc-editor.org/rfc/rfc9106
- SQLite, impieghi e limiti: https://www.sqlite.org/whentouse.html
- Cloudflare Tunnel, connessioni in uscita: https://developers.cloudflare.com/tunnel/
- Android Credential Provider: https://developer.android.com/identity/sign-in/credential-provider
- Provider passkey Windows: https://github.com/MicrosoftDocs/windows-dev-docs/blob/docs/hub/apps/develop/security/third-party.md
