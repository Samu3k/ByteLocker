# Protocollo crittografico PM1

Versione del documento: 1.0  
Data: 7 ottobre 2026  
Stato: specifica proposta, con vettore sintetico verificato; implementazione applicativa e revisione indipendente non ancora eseguite.  
Riferimenti locali: [architettura](architecture.md), [modello delle minacce](threat-model.md).

## 1. Perimetro e significato delle regole

PM1 definisce derivazione, separazione delle chiavi, autenticazione tramite HTTPS, involucri della chiave vault, cifratura degli oggetti e recupero. «Deve» indica un requisito di interoperabilità o sicurezza. Il contratto API definirà endpoint, sessioni e transazioni rispettando queste regole.

Le primitive sono standard; il formato PM1 e la loro composizione sono specifici del progetto, non un protocollo standardizzato o già sottoposto ad audit. Non si implementano manualmente AES, Argon2, HKDF o HMAC. La disponibilità delle primitive e le prestazioni devono essere provate su Android e Windows prima di accettare una libreria.

Il backend e il proxy HTTPS non ricevono Master Password, recovery key o chiave vault in chiaro. Ricevono invece credenziali derivate riutilizzabili per l'autenticazione. PM1 non è un PAKE, non offre autenticazione resistente al phishing e non impedisce il riutilizzo di una credenziale derivata rubata. Questa scelta è esplicita: nessuna protezione dal replay viene simulata con challenge HMAC artigianali.

## 2. Convenzioni binarie

- `||` indica concatenazione di byte, non concatenazione di rappresentazioni testuali.
- Le etichette tra virgolette sono byte ASCII esatti, senza terminatore NUL.
- Tutti gli interi del formato PM1 sono unsigned big-endian, con larghezza indicata. L'endianness interna di Argon2 è gestita dalla libreria standard.
- `SHA256` restituisce 32 byte. `HKDF(IKM, salt, info)` indica HKDF-SHA-256 completo, Extract e Expand, con output di 32 byte.
- Nel trasporto JSON i byte sono Base64url RFC 4648 senza padding. Il decoder rifiuta padding, alfabeti alternativi e codifiche non canoniche, verificando la ricodifica.
- Gli identificatori `server_id`, `account_id`, `vault_id`, `epoch_id`, `object_id`, `recovery_id` e `device_id` sono 16 byte. Non sono stringhe UUID. Sono generati da un CSPRNG; il valore tutto zero è riservato.
- `server_id` nasce all'inizializzazione dell'istanza. Il server assegna `account_id` alla registrazione pendente. Il client genera `vault_id` ed `epoch_id`; il server associa tali ID all'account e ne verifica l'unicità richiesta.
- Tutti i segreti casuali sono generati da un CSPRNG del sistema o da una libreria verificata che lo usa. Date, contatori e generatori pseudocasuali ordinari non sono sorgenti di chiavi.

Email e hostname non vengono usati come salt o identità crittografica: possono cambiare senza cambiare le chiavi. Il client verifica comunque l'origine HTTPS e lega cache e sessioni al server selezionato. Un `server_id` dichiarato dal server non sostituisce TLS.

## 3. Master Password e Argon2id

La Master Password viene codificata in UTF-8 senza BOM, senza trim, case folding o normalizzazione Unicode. I caratteri combinanti e precomposti restano distinti. Stringhe con surrogati non validi sono rifiutate; spazi iniziali e finali sono significativi.

In creazione e cambio password il client richiede almeno 12 valori scalari Unicode e al massimo 1.024 byte UTF-8; non impone classi di caratteri. La lunghezza minima non equivale a una garanzia di robustezza: la UI propone una passphrase lunga. La derivazione rifiuta input vuoto o oltre 1.024 byte prima di allocare Argon2.

| Parametro client PM1 | Valore |
| --- | --- |
| Variante e versione | Argon2id, versione 0x13 / 19 |
| Salt password | 16 byte casuali, nuovi per ogni cambio password |
| Output | 32 byte |
| Secret e associated data Argon2 | Vuoti |
| Profilo predefinito | m = 65.536 KiB, t = 3, p = 4 |
| Altri profili ammessi | m = 131.072 oppure 262.144 KiB; t = 3, p = 4 |

La memoria indicata è totale, non per lane. Il client accetta soltanto queste tre tuple e la versione indicata; una configurazione remota non può introdurre altri valori. Nessun fallback automatico a PBKDF2 o parametri inferiori è consentito. Un dispositivo incompatibile mostra un errore. Eventuali cambi della lista richiedono una revisione esplicita del protocollo e relativi test.

La configurazione server può proporre un profilo ammesso per un nuovo account; il client conferma la scelta e conserva quello effettivamente usato. Un account esistente usa il proprio descrittore, non il profilo corrente della discovery. Per aggiornare il profilo si esegue il cambio credenziali della sezione 10.

Il descrittore password `D` ha esattamente 30 byte: algoritmo u8 = 1, versione Argon2 u8 = 19, m u32, t u32, p u32, salt 16 byte. L'algoritmo 1 significa Argon2id, non AES.

## 4. Separazione delle chiavi

Siano `C = server_id || account_id || vault_id` e `S_identity = SHA256("PM1/identity" || C)`.

1. `M = Argon2id(UTF8(Master Password), salt_password, m, t, p, output=32)`.
2. `K_password = HKDF(M, S_identity, "PM1/password-wrap")`.
3. `A_password = HKDF(M, S_identity, "PM1/authentication")`.
4. `K_vault` è un segreto casuale indipendente di 32 byte, generato sul client.

`K_password` protegge la chiave vault; `A_password` autentica al server. Il client non invia `M` o `K_password`. Conoscere `A_password` non fornisce direttamente `K_password`; resta possibile tentare Master Password candidate usando salt e identità conosciuti.

`M`, `K_password` e `A_password` non sono conservati su disco. Dopo l'operazione i riferimenti sono eliminati e i buffer mutabili azzerati dove possibile; non si promette cancellazione perfetta della memoria gestita. Lo sblocco ordinario mantiene in memoria soltanto le chiavi necessarie al vault e i token di sessione richiesti.

## 5. Autenticazione e verificatore server

Registrazione e login inviano `A_password` come 32 byte codificati Base64url nel corpo di una richiesta HTTPS. Mai in URL, query string, log o email. L'accesso alle API usa poi un token di sessione distinto.

Il server genera un salt verificatore di 16 byte e conserva `V_password = Argon2id(A_password, salt_server, m=19.456 KiB, t=2, p=1, version=19, output=32)`. Secret e associated data sono vuoti. Il confronto è costante nel tempo. Il server conserva algoritmo, parametri, salt e verificatore; non conserva `A_password` recuperabile.

Questa seconda derivazione tratta una credenziale casuale derivata, non riceve la Master Password e non sostituisce la derivazione client. La concorrenza iniziale di verifica è limitata a due operazioni per istanza, con coda limitata e rate limit definiti nel contratto API. Il backend non accetta parametri del verificatore scelti dal chiamante.

Prima del login il client riceve `server_id`, `account_id`, `vault_id`, descrittore `D` e `credential_generation`. Tutti sono input non fidati fino ai controlli previsti. Il server deve usare risposte sintetiche coerenti per email sconosciute e risposte di errore uniformi; la strategia precisa sarà fissata nel contratto API senza promettere indistinguibilità assoluta dei tempi.

Cloudflare può osservare `A_password` e token perché termina HTTPS. Il loro furto può permettere accesso online ai ciphertext e abusi dell'account; non fornisce direttamente `K_vault`. Un futuro PAKE richiederebbe una versione di protocollo e una migrazione distinte.

Il primo amministratore segue la stessa derivazione client. La procedura locale del backend autorizza una registrazione amministrativa tramite capability monouso: non chiede la Master Password nel terminale e non deriva la chiave vault sul server.

## 6. Formato dell'involucro PME1

Un involucro è `H || ciphertext || tag`, dove `H` è l'intestazione completa, inclusi i metadati variabili. Non si cifra o autentica la serializzazione JSON esterna. Il JSON trasporta il blob binario senza modificarlo.

| Offset | Campo | Byte |
| --- | --- | --- |
| 0 | Magic ASCII `PME1` | 4 |
| 4 | kind | 1 |
| 5 | flags, deve essere zero | 1 |
| 6 | suite, u16 = 1 | 2 |
| 8 | server_id | 16 |
| 24 | account_id | 16 |
| 40 | vault_id | 16 |
| 56 | epoch_id | 16 |
| 72 | object_id | 16 |
| 88 | generation, u64 | 8 |
| 96 | plaintext_length, u32 | 4 |
| 100 | envelope_salt | 32 |
| 132 | nonce AES-GCM | 12 |
| 144 | metadata_length, u32 | 4 |
| 148 | metadata | metadata_length |

La suite 1 è HKDF-SHA-256 più AES-256-GCM con tag intero di 16 byte. Il ciphertext ha esattamente `plaintext_length` byte; il tag segue immediatamente. La lunghezza totale è `148 + metadata_length + plaintext_length + 16`. Byte finali, troncamenti, overflow e campi non validi sono rifiutati.

| kind | Significato, radice e vincoli |
| --- | --- |
| 1 | Chiave vault protetta dalla password. Radice `K_password`; object_id zero; generation = credential_generation; metadata = D di 30 byte; plaintext = K_vault di 32 byte. |
| 2 | Chiave vault protetta dal recupero. Radice `K_recovery`; object_id zero; generation = recovery_generation; metadata = recovery_id di 16 byte; plaintext = K_vault di 32 byte. |
| 3 | Oggetto sincronizzabile o tombstone. Radice `K_vault`; object_id non zero; generation = revisione oggetto; metadata vuoti; plaintext UTF-8 JSON. |
| 4 | Stato locale cifrato, non caricato sul server. Radice `K_vault`; object_id = device_id; generation = versione stato locale; metadata vuoti; plaintext UTF-8 JSON. |

Tutte le generation partono da 1; zero e incremento oltre u64 sono rifiutati. Epoch e identità devono corrispondere al contesto atteso. Gli ID zero sono consentiti solo per object_id nei kind 1 e 2. Kind, suite e flag sconosciuti sono rifiutati senza fallback.

Il plaintext dei kind 3 e 4 è limitato a 1.048.576 byte e deve essere non vuoto. Non è prevista compressione. Il descrittore del kind 1 viene validato prima di Argon2 e deve coincidere byte per byte con quello della registrazione o del prelogin. Il confronto delle generation attese è distinto dalla verifica del tag.

## 7. Cifratura, AAD e strategia nonce

Per ogni nuova cifratura il client genera indipendentemente `envelope_salt` di 32 byte e nonce di 12 byte casuali. Costruisce `H`, quindi deriva `K_envelope = HKDF(radice, envelope_salt, "PM1/envelope-key" || SHA256(H))`.

AES-256-GCM usa `K_envelope`, il nonce di `H`, il plaintext e AAD uguale a tutti i byte di `H`. Il risultato è ciphertext più tag di 16 byte. La sottochiave viene usata per una sola operazione di cifratura e non viene salvata.

Una modifica genera sempre salt e nonce nuovi, anche se il contenuto sembra uguale. Il retry di rete ritrasmette gli stessi byte già cifrati: non riesegue AES con la medesima sottochiave su dati diversi. Salt e nonce di test non sono mai usati in produzione. Un errore del CSPRNG blocca l'operazione.

La sicurezza dell'unicità è probabilistica, non una garanzia matematica di assenza di collisioni. Per q salt casuali a 256 bit, la probabilità approssimata di collisione è q(q−1)/2^257; fino a 2^32 cifrature resta circa 2^-193. Anche una collisione del solo nonce non implica riutilizzo della chiave AES, grazie alla sottochiave per involucro. Il progetto non usa contatori nonce condivisi tra dispositivi offline; un ripristino non deve ripristinare lo stato interno del CSPRNG.

Per decifrare: validare dimensioni e campi; confrontare identità e contesto attesi; derivare la sottochiave; verificare il tag; solo dopo interpretare il plaintext. Nessun byte non autenticato è reso visibile, indicizzato o usato per autofill. Non si espongono errori dettagliati che costituiscano un oracolo crittografico remoto.

L'AAD lega contenuto, tipo, account, vault, epoch, oggetto e generation. Non dimostra freschezza assoluta contro un server ostile: un involucro storico completo può essere ancora valido.

## 8. Contenuti e revisioni

Il payload applicativo è un oggetto JSON UTF-8 senza BOM, chiavi duplicate, NaN o Infinity. Non è richiesta serializzazione canonica per cifrare: si autenticano i byte effettivamente prodotti. Il parser applicativo deve imporre schema e limiti prima dell'uso.

Per il vault, schema 1 identifica le credenziali di base e le tombstone; schema 2 aggiunge TOTP e schema 3 aggiunge passkey, secondo api-contract.md. Un record normale contiene `deleted=false`, tipo e contenuti applicativi; una tombstone contiene soltanto `schema=1` e `deleted=true`. Username, email dei servizi, password, URL, note, tag, TOTP, passkey e tempi applicativi restano all'interno del ciphertext. Lo schema dettagliato dei record sarà fissato insieme ai modelli dati; PM1 tratta tali campi come payload opaco e non ne dipende per derivare chiavi.

Un nuovo oggetto ha revisione 1. Una modifica alla revisione n produce un involucro con generation n+1 e indica n come base dell'operazione server. La transazione confronta la base, applica i byte ricevuti e aggiorna la revisione; non riscrive l'intestazione. Un conflitto richiede una decisione client e una nuova cifratura su base aggiornata.

Il cliente confronta anche gli ID e la revisione del trasporto con l'intestazione autenticata. Il server applica l'autorizzazione usando l'account della sessione, indipendentemente dall'AAD. La sincronizzazione di tombstone segue gli stessi vincoli. I contatori server di pagina o raccolta non sono una firma crittografica del dataset.

Lo stato locale kind 4 contiene checkpoint e coda offline secondo uno schema locale versionato. Non può contenere la sola copia di una chiave necessaria a decifrare sé stesso. Salt, descrittori e involucri password possono essere conservati in chiaro come metadati non segreti; i contenuti e gli indici persistenti restano cifrati.

## 9. Registrazione e primo accesso

1. Discovery e invito autorizzano la creazione di un contesto pendente, con account_id stabile, server_id verificato tramite HTTPS e vault_id scelto dal client.
2. Il client genera epoch_id, K_vault e salt password, deriva K_password e A_password e crea un involucro kind 1 con credential_generation = 1.
3. Invia descrittore, identificatori, A_password e involucro cifrato. Il server controlla struttura e coerenza degli ID, crea il verificatore e non può verificare il tag senza la chiave client.
4. Il codice email attiva l'account e consuma l'invito in un'unica transazione. Non viene usato come input delle chiavi.
5. Dopo autenticazione, il client scarica l'involucro, confronta il contesto atteso, verifica il tag e recupera K_vault.

Registrazioni interrotte e retry non generano chiavi diverse per il medesimo stato pendente senza una sostituzione esplicita dell'intero materiale. L'attivazione non combina mai verificatore di una proposta e involucro di un'altra.

## 10. Cambio Master Password o profilo KDF

Richiede una sessione valida e la verifica di A_password corrente. Il client verifica localmente il vecchio involucro prima di preparare la modifica. La conferma della Master Password è distinta dallo sblocco biometrico.

Genera salt password nuovo, seleziona un profilo ammesso, deriva le nuove chiavi e crea un kind 1 della stessa K_vault ed epoch con credential_generation incrementata. Il server genera un nuovo salt verificatore.

Una transazione confronta la credential_generation precedente e sostituisce descrittore, verificatore e involucro; invalida tutte le sessioni precedenti, inclusa quella chiamante. Il client esegue un nuovo login. In caso di risposta persa, verifica lo stato usando le nuove credenziali; un rifiuto non autorizza una sovrascrittura basata sulla vecchia generation.

Gli oggetti non sono ricifrati. L'involucro recovery resta valido: recovery_generation è indipendente da credential_generation. I dispositivi devono invalidare i dati di sblocco biometrico quando apprendono il cambio credenziali; un dispositivo offline non può conoscerlo immediatamente.

Il cambio password non revoca involucri storici già rubati né una K_vault già conosciuta. Una compromissione richiede valutare la rotazione della chiave vault e dei segreti dei servizi.

## 11. Recovery key opzionale

Il client genera `R`, segreto casuale di 32 byte, e recovery_id casuale di 16 byte. La rappresentazione utente è il prefisso ASCII `PMR1-` seguito dalla Base64url canonica senza padding di R: 43 caratteri dopo il prefisso. Non contiene checksum. Il parser può eliminare solo whitespace ASCII esterno; non corregge caratteri interni o alfabeti errati.

Le chiavi di recupero sono `K_recovery = HKDF(R, S_identity, "PM1/recovery-wrap" || recovery_id)` e `A_recovery = HKDF(R, S_identity, "PM1/recovery-authentication" || recovery_id)`.

Il client crea un involucro kind 2 di K_vault, con recovery_generation = 1 alla prima attivazione. Il server conserva l'involucro e un verificatore di A_recovery con gli stessi parametri server della sezione 5 e salt distinto. R e K_recovery non vengono inviati. Il client chiede all'utente di conservare e confermare la recovery key; R non viene salvata automaticamente sul dispositivo.

L'abilitazione, la sostituzione e la disabilitazione richiedono sessione valida e A_password corrente, con confronto della recovery_generation attesa; una sostituzione incrementa la generation e usa R e recovery_id nuovi. La disabilitazione rimuove involucro e verificatore server. Un registro mantiene la generation monotona anche se il recupero viene riabilitato.

### Recupero online

1. Il client riceve il contesto account e recovery_id, inserisce R e deriva A_recovery e K_recovery.
2. A_recovery autentica una sessione limitata di recupero: permette il download dell'involucro recovery e la sostituzione delle credenziali, senza normali scritture nel vault o privilegi amministrativi aggiuntivi.
3. Il client verifica il kind 2 e recupera K_vault. Se il tag fallisce, non procede al reset.
4. Crea salt, credenziali e involucro password nuovi. Una transazione confronta le generation, sostituisce il materiale password e revoca tutte le sessioni precedenti e quella recovery.
5. Esegue login normale. Il recupero mantiene lo stesso vault ed epoch e non attiva una nuova verifica email.

A_recovery è una credenziale di reset riutilizzabile, visibile al proxy HTTPS durante l'uso. Rubarla può consentire reset o sabotaggio dell'account, ma non deriva K_recovery o R. L'email da sola non decifra il vault. Un reset amministrativo senza R può soltanto creare un vault vuoto dopo una scelta distruttiva esplicita; non è il recupero dei dati.

Con un backup completo, il client può decifrare offline l'involucro recovery e gli oggetti usando R. Questo non ripristina automaticamente l'autorizzazione online. La revoca server della recovery key non revoca copie storiche già in possesso di un attaccante.

## 12. Rotazione della chiave vault

La rotazione genera K_vault ed epoch_id nuovi e ricifra tutti gli oggetti e le tombstone conservate, con nuove sottochiavi per ogni involucro. Gli ID degli oggetti restano stabili; le revisioni ripartono da 1 nel nuovo epoch. Il server distingue gli oggetti per vault, epoch e object_id.

Prima della rotazione il client sincronizza le proprie modifiche e scarica il dataset completo della revisione di raccolta corrente. Verifica e decifra tutti gli oggetti: un fallimento blocca la rotazione. Gli altri dispositivi offline non possono essere considerati automaticamente sincronizzati.

Il client prepara una nuova generazione credenziali con salt password nuovo, nuovo involucro password e nuovo verificatore. Se recovery è attiva, richiede R e crea il nuovo involucro recovery con recovery_generation incrementata; in alternativa l'utente deve disabilitare esplicitamente recovery nella medesima operazione.

Il server riceve uno staging cifrato, invisibile alle letture normali. Il commit confronta epoch, generation credenziali/recovery e revisione della raccolta precedente, verifica completezza rispetto agli ID correnti e sostituisce atomicamente epoch, involucri, credenziali e dataset. Una modifica concorrente rifiuta il commit; il client non perde il dataset attivo. Lo staging ha quote e scadenza definite nell'API.

Il commit revoca tutte le sessioni e il client esegue un nuovo login. Risposte perse vengono risolte verificando il nuovo epoch senza ripetere alla cieca la rotazione. Il client invalida lo sblocco biometrico precedente. Gli altri dispositivi devono autenticarsi e scaricare il nuovo epoch prima di scrivere.

Code offline del vecchio epoch non sono inviate automaticamente al nuovo. Il client le conserva cifrate e propone recupero esplicito usando la vecchia chiave ancora disponibile localmente, prima di eliminarle. Se tale chiave non è più disponibile, non promette di recuperarle. Backup storici restano decifrabili con le rispettive credenziali: la rotazione non cancella copie altrui.

## 13. Sblocco locale e biometria

La biometria non deriva chiavi dalla Master Password. Un contenitore nativo protetto dal sistema conserva K_vault insieme a server_id, account_id, vault_id, epoch_id e credential_generation. L'accesso deve essere vincolato alla verifica utente dalle API crittografiche OS, non soltanto da una finestra di conferma.

Il formato nativo è locale e non intercambiabile tra Android e Windows; non viene caricato sul server o ripristinato come segreto di sblocco da backup applicativi. L'implementazione verifica le capacità hardware e le condizioni di invalidazione. In assenza delle capacità richieste si usa la Master Password, senza dichiarare una protezione equivalente.

La sessione server resta distinta. K_vault da sola non consente di ricalcolare A_password. Il modulo Android implementato sigilla esplicitamente anche A_password già derivata, con descrittore e origine, nello stesso contenitore hardware: dopo l'autorizzazione biometrica esegue un nuovo login online e verifica identità, generazione ed epoch. Non salva Master Password o refresh token. Questa scelta permette l'autenticazione a chi riuscisse a estrarre il payload: richiede protezione hardware e autenticazione per uso. La cache offline non è ancora implementata; la revoca di una sessione non cancella dati già scaricati né revoca la credenziale derivata.

## 14. TOTP e materiale passkey

PM1 cifra integralmente segreti TOTP e materiale passkey come parte del payload kind 3. I codici TOTP non sono calcolati dal backend.

Il profilo TOTP iniziale è RFC 6238 con HMAC-SHA1, T0 = 0, intervallo 30 secondi, sei cifre e contatore floor(UnixTime/30) codificato su otto byte big-endian. La troncatura dinamica HOTP produce un valore a 31 bit, ridotto modulo 1.000.000 e formattato con zeri iniziali. Il segreto importato è decodificato da Base32 prima del calcolo; nel payload cifrato si conserva il segreto Base32 canonico, non un URI in chiaro nei log. Algoritmi o intervalli diversi non vengono interpretati silenziosamente come questo profilo.

Le chiavi private esportabili delle passkey sono contenuto cifrato, insieme a credential ID, relying party e user handle. Il modulo Android usa ES256/P-256, PKCS8/SPKI e schema 3, secondo android-security.md e api-contract.md. PM1 non modifica i formati o i messaggi WebAuthn e non rende esportabili le chiavi di token hardware non esportabili.

## 15. Vettori e verifiche di interoperabilità

I byte fissi seguenti sono esclusivamente dati sintetici pubblici. Non sono credenziali, nonce o chiavi utilizzabili in produzione. I valori sono stati calcolati con `cryptography` 50.0.1 e verificati con round-trip AES-GCM e rifiuto di un'AAD alterata. Non costituiscono ancora una verifica indipendente Android/Windows.

### Vettore completo: derivazione e involucro password

Gli intervalli esadecimali seguenti includono entrambi gli estremi e indicano byte consecutivi crescenti, non una stringa letterale.

| Input | Valore |
| --- | --- |
| Master Password | `Test-only master password 2026!` |
| Salt password | byte da `00` a `0f` |
| server_id | byte da `00` a `0f` |
| account_id | byte da `10` a `1f` |
| vault_id | byte da `20` a `2f` |
| epoch_id | byte da `30` a `3f` |
| object_id | 16 byte zero |
| Profilo Argon2id | 65.536 KiB, t=3, p=4, v=19 |
| credential_generation | 1 |
| K_vault | byte da `60` a `7f` |
| envelope_salt | byte da `80` a `9f` |
| nonce | byte da `a0` a `ab` |
| Salt verificatore server | byte da `40` a `4f` |
| R per vettore recovery | byte da `c0` a `df` |
| recovery_id | byte da `e0` a `ef` |

| Output | Esadecimale atteso |
| --- | --- |
| S_identity | `51c275a262172a54711f0d1a4a89475c0cf1aea18a9d00ab35492f698f4a16b7` |
| M | `9ceb69de4aca56d1dad915bd1f65cfdc23f9b0b6a990bfb5af745be6755057e8` |
| K_password | `70c6a4425a9c6cf54720100f08098e64f8ffa14e54a0e2cec8ff8df44e167c16` |
| A_password | `fca131d785fbe0fa95ae0c305e383793fe1b6902b8c1f9ad722bb6460eec19c4` |
| V_password | `06f50329db5db376a50a198dd15c3936d9062ce50dd93e4dc12dd6c6e9732e31` |
| K_recovery | `9b3d7a9b502ff9b747a55ab456dcee15ea75026d2ec4b0327928106796b40c2a` |
| A_recovery | `556e21615ab12b54457507bb467780ffe63318256e09552ed6e696ab6cfe61d2` |
| D | `0113000100000000000300000004000102030405060708090a0b0c0d0e0f` |
| K_envelope | `e35187d5b2589a340149d81f784fe5f4cafd756a703ae6d930a38b8542237692` |
| Ciphertext | `a5656aa25fd4d401ceeeb391808aae8f6801f2c8f5cc96f70ede1533b146a56f` |
| Tag | `bbf822bc077e3e9bc4c603dcf01f2af7` |

H è esattamente di 178 byte; l'involucro completo è di 226 byte. L'involucro completo atteso, senza whitespace nell'interpretazione esadecimale, è:

```text
504d453101000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000000000000000000000000000000000000100000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab0000001e0113000100000000000300000004000102030405060708090a0b0c0d0e0fa5656aa25fd4d401ceeeb391808aae8f6801f2c8f5cc96f70ede1533b146a56fbbf822bc077e3e9bc4c603dcf01f2af7
```

### Verifiche complementari

- Con chiave AES-256 di 32 byte zero, nonce di 12 byte zero, plaintext di 16 byte zero e AAD vuota: ciphertext `cea7403d4d606b6e074ec5d3baf39d18`, tag `d0d1c8a799996bf0265b98b5d48ab919`. Questo è un controllo della primitiva, non un involucro PM1.
- Le librerie devono superare i vettori ufficiali Argon2id RFC 9106 sezione 5.3 e HKDF-SHA-256 RFC 5869 appendice A.1, oltre al vettore PM1.
- Per il segreto TOTP ASCII `12345678901234567890`, tempo Unix 59, il codice a sei cifre atteso è `287082`; tempo 1.111.111.109: `081804`. Si controllano anche tutti i vettori SHA1 di RFC 6238, usando otto cifre come richiesto dai vettori originali.
- Cambiare un byte in account_id, ciphertext o tag del vettore PM1 deve fallire. Passare un contesto atteso differente deve fallire anche se il blob è integro.
- Vanno provati UTF-8 con spazi e caratteri combinanti, profili KDF fuori lista, lunghezze incoerenti, generation zero, blob oltre limite, chiavi errate e Base64url non canonica.
- Kind 2, 3 e 4 richiedono round-trip su entrambe le piattaforme, controlli di contesto, tombstone, dati al limite e negativi. Il solo vettore password non basta a dichiarare il protocollo verificato.

## 16. Garanzie, limiti e riferimenti

PM1 protegge confidenzialità e integrità dei contenuti con chiavi client. Non garantisce disponibilità, cancellazione delle copie altrui, freschezza globale contro un server ostile, protezione di un client completamente compromesso o robustezza di una Master Password debole. Password e TOTP nello stesso vault possono essere esposti insieme.

Prima dell'uso reale servono implementazioni interoperabili, verifiche del modello delle minacce e revisione della composizione crittografica. Il documento è completo per il livello crittografico descritto; schema applicativo, contratto di rete e formati dei contenitori nativi appartengono ai successivi moduli e devono rispettarlo.

- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106): primitive, profilo a memoria ridotta e vettori.
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869): Extract/Expand e separazione attraverso info.
- [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final): cifratura autenticata e requisiti degli IV.
- [OWASP — Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): riferimento per il profilo del verificatore server, distinto dal KDF client.
- [RFC 4648 — Base encodings](https://www.rfc-editor.org/rfc/rfc4648): Base64url.
- [RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238): algoritmo e vettori temporali.


