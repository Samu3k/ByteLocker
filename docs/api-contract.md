# Contratto API v1

Versione: 1.0  
Data: 7 ottobre 2026  
Stato: contratto del prodotto; discovery, registrazione, login, sessioni, GET account/material, oggetti vault e sincronizzazione server implementati localmente. Le altre API restano pianificate.  
Documenti collegati: [architettura](architecture.md), [minacce](threat-model.md), [protocollo PM1](crypto-protocol.md).

## 1. Convenzioni e trasporto

La base pubblica è `https://<hostname>/api/v1`. Il client usa un'origine HTTPS verificata e non inoltra credenziali attraverso redirect. Il backend non interpreta hostname forniti dal client come destinazioni da contattare. Nessun endpoint riceve la Master Password, la recovery key R, K_password o K_vault in chiaro.

Richieste e risposte con corpo usano JSON UTF-8, `Content-Type: application/json`; errori usano `application/problem+json`. JSON con chiavi duplicate, proprietà sconosciute nella richiesta, tipi errati o byte UTF-8 invalidi è rifiutato. GET non ha corpo; 204 non ha corpo. Il client tollera proprietà aggiuntive nelle risposte, ma non enum, formati o versioni di sicurezza sconosciuti.

Tutte le risposte, inclusa discovery, usano `Cache-Control: no-store`. I proxy non memorizzano le risposte API; non sono previste cookie session o CORS per client web. Token, codici, inviti e credenziali non compaiono in URL, errori o log.

| Tipo | Regola |
| --- | --- |
| `Id` | 16 byte non zero, Base64url canonica senza padding: 22 caratteri. |
| `Secret` | 32 byte, Base64url canonica senza padding: 43 caratteri. |
| `U64` | Stringa decimale canonica da `0` a `18446744073709551615`; niente segno o zeri iniziali. Le generation PM1 devono essere maggiori di zero. |
| `Time` | Timestamp UTC RFC 3339, millisecondi, formato `YYYY-MM-DDTHH:mm:ss.sssZ`. |
| `Descriptor` | D di 30 byte definito in PM1, Base64url canonica. |
| `Envelope` | Intero blob PME1, Base64url canonica, validato strutturalmente secondo PM1. |

Nelle tabelle gli oggetti elencano tutti i campi richiesti; `?` significa proprietà opzionale e `null` significa un valore esplicitamente ammesso. Gli enum sono case-sensitive. Un `{id}` nel percorso è un parametro, non un esempio di valore.

L'email account v1 è ASCII, massimo 254 byte: un solo `@`, parte locale massimo 64 byte, caratteri alfanumerici e `. _ + -`, senza punti iniziali/finali o consecutivi; dominio con almeno due label DNS valide. Si eliminano soltanto spazi ASCII esterni e si converte l'intero indirizzo in minuscolo. È una politica identificativa del prodotto, non una promessa che ogni servizio email ignori la distinzione maiuscole/minuscole. Non si rimuovono punti o suffissi `+`. Email internazionalizzate non sono supportate in v1. Master Password segue invece la codifica senza trim di PM1.

## 2. Errori e precondizioni

L'errore contiene `type: "about:blank"`, `title` coerente con lo status HTTP, `status` numerico, `code` stabile e `request_id: Id` generato dal server. `detail` opzionale contiene solo una spiegazione generica. Non si restituiscono stack trace, email, token, blob o esistenza di account nei fallimenti pubblici di autenticazione.

| HTTP | code principale | Significato |
| --- | --- | --- |
| 400 | `invalid_request` | Sintassi, tipo, codifica, valore o formato PM1 non validi. |
| 401 | `invalid_credentials` / `invalid_token` | Autenticazione fallita, account non attivo oppure token scaduto/revocato. |
| 403 | `insufficient_scope` | Token valido ma azione non consentita. |
| 404 | `not_found` | Risorsa assente o appartenente ad altro account. |
| 409 | `state_conflict` / `epoch_changed` / `snapshot_changed` | Stato incompatibile; nessuna scrittura applicata. |
| 409 | `idempotency_conflict` / `registration_unavailable` | Chiave operazione riutilizzata diversamente o attivazione non disponibile. |
| 410 | `registration_expired` / `rotation_expired` | Capability valida per una risorsa scaduta. |
| 412 | `revision_mismatch` | If-Match non corrisponde allo stato attuale. |
| 413 | `payload_too_large` | Corpo oltre il limite. |
| 415 | `unsupported_media_type` | Tipo di contenuto o compressione non ammessi. |
| 428 | `precondition_required` | If-Match richiesto ma assente. |
| 429 | `rate_limited` | Quota o limite ai tentativi; header Retry-After in secondi. |
| 503 | `temporarily_unavailable` | Verifica credenziali satura, SMTP o storage non disponibili; Retry-After se noto. |

Le API richiedono prima autenticazione e autorizzazione e solo dopo rivelano precondizioni sulle risorse private. Un token di recupero valido non riceve informazioni su altri account. Errori TLS o di rete non diventano successi API.

ETag forti di v1, inclusi i doppi apici, sono `"a:<credential_generation>:<recovery_generation>:<epoch_id>"` per il materiale account e `"o:<epoch_id>:<revision>"` per gli oggetti. La recovery_generation può essere zero solo quando recovery non è mai stata configurata. If-Match accetta esattamente un ETag forte; niente wildcard o lista. Gli ETag non sono firme crittografiche.

## 3. Sessioni, credenziali e autorizzazione

Le classi di token sono separate nel database; un token di una classe non è accettato dalle altre.

| Classe | Header e durata | Permessi |
| --- | --- | --- |
| Normale | `Authorization: Bearer <access_token>`; 15 minuti | API del proprio account e vault; amministrazione solo se ruolo admin attuale. |
| Refresh | Solo corpo di `/auth/refresh`; scadenza inattività 7 giorni, assoluta famiglia 30 giorni | Emissione token della stessa famiglia. |
| Registrazione | `Authorization: Registration <registration_token>`; 24 ore | Solo la propria registrazione pendente. |
| Recupero | `Authorization: Recovery <recovery_token>`; 10 minuti, senza refresh | Download involucro recovery e reset del proprio account. |

Access, refresh, registration e recovery token sono Secret casuali del server. Sono conservati come SHA-256 dei byte token, mai in chiaro nel database. Non sono JWT. Anche un access token non scaduto richiede una famiglia attiva e un account attivo. Ruolo e generation sono verificati nello stato server, senza affidarsi a dichiarazioni client.

Un refresh token è monouso. La transazione lo consuma e crea nuovi access e refresh token; il precedente access token è revocato. Il riutilizzo di un refresh consumato revoca l'intera famiglia. I digest consumati restano fino alla scadenza assoluta per rilevare il riuso. Nessuna finestra di replay o cache recuperabile dei token è prevista in v1.

Il client serializza i refresh. Se perde la risposta, non ritenta il vecchio refresh: esegue login con la Master Password. Un riavvio può conservare il refresh nell'archivio OS protetto. Lo sblocco biometrico del vault non ricalcola la credenziale password e non rinnova da solo una famiglia scaduta.

Il server verifica A_password e A_recovery usando i verificatori PM1. Le azioni sensibili richiedono `current_auth_secret: Secret` nel corpo oltre alla sessione; il backend non considera lo sblocco grafico un'autenticazione aggiuntiva. Un fallimento restituisce 401 generico senza revocare automaticamente altre sessioni per permettere un attacco di blocco account.

## 4. Discovery e salute

### GET `/config` — pubblico, 200

Risposta: `api_version: "1"`, `crypto_protocol: "PM1"`, `envelope_format: "PME1"`, `server_id: Id`, `registration_mode: "invitation"`, `email_verification: "registration_only"`, `kdf_profiles: array` dei tre oggetti `{memory_kib, iterations, parallelism, argon_version}` previsti da PM1, `default_kdf_profile` dello stesso tipo e `features`.

`features` contiene booleani `offline_sync: true`, `recovery: true`, `shared_vaults: false`. Non dichiara che autofill o passkey siano disponibili sul dispositivo: quelle capacità dipendono dal client. Non espone SMTP, segreti, conteggi utenti, identità admin o dettagli dell'host.

GET `/healthz` appartiene al servizio interno, fuori dalla base API: 200 senza informazioni sensibili se il processo risponde, 503 se non pronto. Non è instradato dal tunnel pubblico. La discovery verifica compatibilità, non garantisce disponibilità futura.

Stato dell'implementazione al 10 ottobre 2026: discovery, salute interna, registrazione, login, sessioni, lettura del materiale cifrato account e API vault sono disponibili nel server di sviluppo locale. La discovery aggiunge `registration_available`, vero soltanto quando Gmail è configurato localmente; non è una prova che le credenziali SMTP siano state verificate. Restituisce `offline_sync: false`, `recovery: false`, `shared_vaults: false` fino all'implementazione delle rispettive capacità. I valori `true` sopra descrivono il contratto del prodotto completo, non funzionalità già pronte. Il controllo di salute usa un listener separato, predefinito `127.0.0.1:8081`; le API usano `127.0.0.1:8080`. Le API auth e account/sessions sono attive anche senza Gmail. Cambio credenziali, recupero, rotazione vault e amministrazione HTTP restano da implementare e restituiscono 404.

## 5. Inviti e inizializzazione amministratore

La procedura locale produce una capability d'invito admin monouso di 32 byte. Il ruolo viene memorizzato dal server, non accettato nella registrazione. Dopo l'attivazione del primo amministratore, tutti gli altri inviti e pendenti admin sono invalidati atomicamente. Il terminale non riceve la Master Password.

Un invito normale ha Id server, Secret casuale, scadenza 7 giorni per default e destinatario opzionale. Il server conserva SHA-256 del segreto. Un invito valido non è una sessione e non permette lettura del vault.

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| POST `/admin/invitations` | Normale admin + current_auth_secret; `email?: string`, `expires_in_seconds?: integer` tra 300 e 604800 | 201: `invitation_id`, `invitation_secret`, `expires_at`, `email: string|null`, `scope: "user"`. Il segreto è mostrato una sola volta. |
| GET `/admin/invitations` | Normale admin; `after?: Id`, `limit?: integer` 1–100, default 50 | 200: `items` ordinati per byte invitation_id, `next_after: Id|null`; ogni item ha invitation_id, email, expires_at, `status: "active"|"consumed"|"revoked"|"expired"`. Nessun segreto. |
| DELETE `/admin/invitations/{invitation_id}` | Normale admin | 204, revoca se presente; retry 204. Un invito consumato non annulla l'account già attivato. |

POST invito non usa cache idempotente con segreti: una risposta persa richiede revocare l'invito visibile nella lista e generarne un altro. L'invito privato viene comunicato fuori dall'app secondo la scelta dell'amministratore.

## 6. Registrazione e verifica email

### POST `/registrations` — pubblico, 201

Corpo: `invitation_secret: Secret`, `email: string`, `vault_id: Id` generato dal client. Un invito non valido restituisce 401 `invalid_credentials`. Se ha destinatario, l'email deve corrispondere dopo normalizzazione; errore generico identico.

Risposta: `registration_id: Id`, `registration_token: Secret`, `server_id: Id`, `account_id: Id`, `vault_id: Id`, `expires_at: Time`, `credential_generation: "1"` e `recovery_generation: "0"`.

La registrazione pendente dura 24 ore o fino alla scadenza/revoca dell'invito, se precedente. L'invito non viene consumato né bloccato definitivamente da questa operazione. Più pendenti possono esistere, entro le quote; account_id è stabile per il singolo pendente. Una risposta persa può creare un nuovo pendente: i vecchi scadono senza attivare account.

Email già attive producono un contesto pendente con risposta della stessa forma, ma non ricevono email e non possono diventare un secondo account. Il server non comunica pubblicamente la ragione. I vincoli di unicità sono comunque applicati alla verifica finale. Email sintetiche o stati pendenti non permettono login.

### PUT `/registrations/{registration_id}/material` — token Registration, 202

Corpo: `epoch_id: Id`, `password_descriptor: Descriptor`, `auth_secret: Secret` = A_password e `password_envelope: Envelope` kind 1. Le identità sono quelle del pendente; credential_generation = 1. Recovery viene abilitata solo dopo il primo login.

Il server valida struttura e coerenza, salva un verificatore PM1 e l'involucro, quindi accoda l'email in un outbox transazionale. Risposta: `status: "verification_pending"`, `expires_at: Time`. Il server non verifica il tag AES perché non possiede la chiave.

Un retry con il materiale identico verifica auth_secret contro il verificatore e confronta descrittore, epoch e involucro: restituisce 202 senza inviare un'altra email. Materiale differente restituisce 409 `state_conflict`. Per cambiare la proposta si annulla il pendente e se ne crea uno nuovo; nessuna mescolanza di chiavi e verificatori.

### Codice e altri endpoint pendenti

Il codice email ha otto cifre decimali casuali, generazione senza bias, validità 10 minuti e massimo cinque tentativi per emissione. Il server conserva HMAC-SHA-256 su registration_id e codice con chiave operativa dedicata, non un semplice hash attaccabile offline in pochi tentativi. Il codice non viene inviato nel corpo delle risposte API.

| Metodo e percorso | Richiesta | Risposta e regole |
| --- | --- | --- |
| GET `/registrations/{registration_id}` | Registration | 200: `status: "awaiting_material"|"verification_pending"|"verified"`, expires_at. |
| POST `/registrations/{registration_id}/resend` | Registration; corpo `{}` | 202: status verification_pending, expires_at del pendente. Almeno 60 secondi tra emissioni; massimo cinque/ora e dieci per pendente. Nuova emissione invalida la precedente. |
| POST `/registrations/{registration_id}/verify` | Registration; `code: string` esattamente otto cifre | 204 se verifica riuscita; 400 `invalid_verification_code` per codice errato/scaduto; 429 dopo i tentativi ammessi per quella emissione. |
| DELETE `/registrations/{registration_id}` | Registration | 204; annulla e invalida il token. Non consuma l'invito. |

Verify controlla codice, scadenze, stato invito e unicità dell'email, poi crea l'account, associa il vault e consuma l'invito in un'unica transazione. Un'altra attivazione concorrente restituisce 409 registration_unavailable. Nessun ruolo viene letto dal corpo della richiesta.

Dopo attivazione il token Registration resta valido per 10 minuti solo per GET stato e ripetizione di verify come conferma 204; non invia email e non emette sessioni. Il client effettua login normale. Scadenze e consumo codice sono controllati nell'istante della transazione, non solo prima dell'operazione.

Resend e verify richiedono stato verification_pending, salvo la conferma verify di un account appena attivato. In stato awaiting_material restituiscono 409 state_conflict. Resend non estende la vita del pendente: la validità del codice è il minimo tra dieci minuti e il tempo residuo di registrazione/invito. Dopo annullamento il token non è più utilizzabile.

L'outbox che contiene il codice per SMTP è cifrato con una chiave operativa separata; il payload viene eliminato dopo consegna o scadenza. L'email non include inviti, credenziali di login o blob. Un errore SMTP non attiva l'account: retry e resend restano limitati, e un outbox saturo produce 503.

Implementazione locale: gli endpoint di questa sezione sono attivi soltanto con configurazione Gmail presente. Le quote persistenti di creazione contano anche gli inviti errati, con HMAC per IP/email e massimo 10.000 eventi nell'ora. Il filtro locale aggiunge venti richieste/minuto/IP per le API di registrazione e cinque invii materiale/minuto/pendente autenticato; questi contatori hanno capienza limitata e si azzerano al riavvio. Gli altri rate limit della sezione 14 e l'interpretazione di proxy fidati restano da implementare prima dell'esposizione. La creazione raccoglie i pendenti scaduti: dopo la raccolta le relative capability restituiscono 401 anziché 410. La verifica non emette sessioni: si prosegue con login separato. Il client non è ancora disponibile.

## 7. Login e gestione sessioni

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| POST `/auth/prelogin` | Pubblico; `email: string` | 200: server_id, account_id, vault_id, password_descriptor, credential_generation. |
| POST `/auth/login` | Pubblico; email, account_id, vault_id, credential_generation, `auth_secret: Secret`, `device_id: Id`, `device_name: string` max 80 caratteri, `platform: "android"|"windows"` | 200: account_id, vault_id, `session_id: Id`, access_token, refresh_token, `access_expires_at`, `refresh_expires_at`, `session_expires_at` come Time. |
| POST `/auth/refresh` | Pubblico; `refresh_token: Secret` | 200: session_id, access_token, refresh_token e gli stessi tre tempi. |
| POST `/auth/logout` | Normale; corpo `{}` | 204; revoca l'intera famiglia corrente. Token già invalidi restituiscono 401. |
| GET `/account/sessions` | Normale | 200: `items`, ciascuno con session_id, device_id, device_name, platform, created_at, last_used_at, session_expires_at e `current: boolean`; massimo dieci famiglie attive. |
| DELETE `/account/sessions/{session_id}` | Normale | 204 per una famiglia propria, anche già revocata; 404 per ID di altro account. |

Prelogin usa per email sconosciute o non attive identificatori e salt sintetici stabili, derivati da HMAC con chiave operativa e contesti distinti sulla email normalizzata, più profilo predefinito e generation 1. Non alloca un account. Per un account attivo restituisce il materiale reale. La politica riduce l'enumerazione, ma profili personalizzati, cambi generation e tempi possono restare indizi; non si dichiara indistinguibilità assoluta.

Login sconosciuto esegue una verifica fittizia con costo server PM1 prima del 401, entro gli stessi limiti. Il server controlla email, ID, generation e credenziale, ma restituisce lo stesso errore per tutti i fallimenti. Non chiede un nuovo codice email.

Implementazione locale: login ha quote persistenti di cinque/minuto/email e dieci/minuto/IP, anche per fallimenti; refresh trenta/minuto/famiglia e sessanta/minuto/IP. Il riuso noto viene rilevato e revoca prima del filtro persistente refresh. Il registro HMAC ha massimo 10.000 eventi nella finestra mobile di un minuto. La cronologia refresh ha massimo 100.000 digest globali: non viene rimossa prima della scadenza assoluta, nemmeno dopo logout; login e rinnovo raccolgono le famiglie assolutamente scadute. Filtri locali aggiungono venti prelogin/minuto/IP e limiti aggregati delle API autenticate di 120/minuto/account e 600/minuto/IP. Il filtro locale precede il database: una richiesta già respinta per quota locale non esegue il rilevamento riuso. Gli header di proxy non sono fidati; i filtri locali si azzerano al riavvio. La gestione dei proxy e le protezioni per le API future restano da completare prima dell'esposizione.

L'attività della sessione viene aggiornata al rinnovo e durante le API autenticate, accorpando le scritture quando è passato almeno un minuto. Il rinnovo deve essere serializzato dal client: una risposta persa richiede un nuovo login; ripetere il vecchio refresh può revocare la sessione. Il materiale account restituisce soltanto il contesto pubblico e l'involucro cifrato, con recovery disabilitata e campi recovery null fino alla relativa implementazione.

Un device_id non è una prova di possesso: ogni login crea una famiglia distinta. Oltre dieci famiglie il login restituisce 409 `session_limit`; non revoca dispositivi silenziosamente. Un client già autenticato può rimuoverne una; la procedura locale amministrativa per revocare le proprie sessioni sarà aggiunta prima della distribuzione.

## 8. Stato account e cambio credenziali

### GET `/account/material` — Normale, 200

Risposta: server_id, account_id, vault_id, epoch_id, `email`, `role: "user"|"admin"`, credential_generation, password_descriptor, password_envelope, recovery_generation, `recovery_enabled: boolean`, `recovery_id: Id|null`, `recovery_envelope: Envelope|null`. Header ETag account. Verificatori e salt server non sono restituiti.

### PUT `/account/credentials` — Normale, If-Match account, 200

Corpo: current_auth_secret, `new_auth_secret: Secret`, `new_password_descriptor: Descriptor`, `new_password_envelope: Envelope`. Nuovo descrittore con salt diverso, stesso vault/epoch, generation precedente + 1; involucro kind 1 coerente.

La transazione ricontrolla generation e account attivo, sostituisce descrittore, verificatore e involucro e revoca ogni sessione. Risposta: `credential_generation`, `epoch_id`, `reauthentication_required: true`. Il token corrente non funziona dopo il commit. Per risposta persa il client usa prelogin e nuovo login, non un retry autenticato con il vecchio token.

### PUT `/account/recovery` — Normale, If-Match account, 200

Corpo: current_auth_secret, `recovery_id: Id`, `recovery_auth_secret: Secret`, `recovery_envelope: Envelope` kind 2. La generation recovery incrementa di uno dal valore corrente; se mai configurata, diventa 1. Richiede un recovery_id nuovo e identità/epoch coerenti. Risposta: recovery_generation, `recovery_enabled: true`; ETag aggiornato. Invalida tutte le sessioni Recovery precedenti senza modificare le sessioni normali.

### POST `/account/recovery/disable` — Normale, If-Match account, 200

Corpo: current_auth_secret. Se recovery è attiva, rimuove involucro/verificatore, incrementa recovery_generation e revoca i token Recovery. Se già disabilitata, mantiene la generation. Risposta: recovery_generation, `recovery_enabled: false`; ETag aggiornato. Nessuna richiesta riceve R o K_recovery.

## 9. Recupero online

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| POST `/recovery/prelogin` | Pubblico; email | 200: server_id, account_id, vault_id, recovery_id. Se account assente, non attivo o recovery disabilitata, valori sintetici stabili e nessun indicatore di disponibilità. |
| POST `/recovery/login` | Pubblico; email, account_id, vault_id, recovery_id, `recovery_auth_secret: Secret` | 200: `recovery_token: Secret`, expires_at; errore 401 uniforme, con verifica fittizia se necessario. |
| GET `/recovery/material` | Recovery | 200: server_id, account_id, vault_id, epoch_id, credential_generation, recovery_generation, recovery_id, recovery_envelope; ETag account. |
| PUT `/recovery/credentials` | Recovery, If-Match account; new_auth_secret, new_password_descriptor, new_password_envelope | 200: credential_generation, epoch_id, reauthentication_required true; nuovo kind 1, stessa chiave vault attesa sul client, stessa epoch, generation password + 1. |

Il token Recovery resta vincolato alle generation password e recovery viste al login. Qualsiasi cambiamento lo invalida. Il client verifica il tag recovery prima del reset; il backend può validare solo il formato e il contesto del nuovo involucro, non che contenga la medesima K_vault.

Il reset sostituisce atomicamente il materiale password e revoca tutte le sessioni normali e Recovery. Mantiene recovery_id, recovery_generation e il suo involucro. Si prosegue con login normale, senza email. Non sono previsti endpoint pubblici di recupero tramite sola email o reset distruttivo amministrativo in v1.

## 10. Scrittura degli oggetti e idempotenza

Stato locale: gli endpoint delle sezioni 10 e 11 sono implementati nel backend. Quote iniziali fisse secondo la sezione 14; configurazione operatore e staging/commit di rotazione restano pianificati. La discovery mantiene offline_sync falso fino all'implementazione del client. Il registro misura i byte dei campi serializzati, escluso overhead SQLite/WAL/backup; le conferme scadute vengono raccolte alla scrittura successiva. I contatori U64 sono salvati in otto byte big-endian, mantenendo l'intero intervallo e l'ordine oltre il limite degli interi SQLite con segno.

La API espone soltanto il vault dell'account autenticato. Non accetta owner_id o account_id come selettori di autorizzazione. Il backend verifica la struttura dell'involucro kind 3 ma non può decifrarlo né distinguere un record da una tombstone.

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| GET `/vault/objects/{object_id}` | Normale | 200: epoch_id, object_id, `revision: U64`, `sequence: U64`, `envelope: Envelope`; ETag oggetto. 404 se assente. |
| POST `/vault/objects` | Normale, Idempotency-Key; epoch_id, object_id, envelope | 201: epoch_id, object_id, revision, sequence e `collection_revision: U64`; ETag oggetto, revision 1. 409 se ID già presente. |
| PUT `/vault/objects/{object_id}` | Normale, If-Match oggetto, Idempotency-Key; epoch_id, envelope | 200: epoch_id, object_id, revision, sequence e collection_revision; ETag oggetto, generation nel blob = precedente + 1. |

Non esiste DELETE server dell'oggetto: il client cifra una tombstone e la invia con PUT. In v1 le tombstone non sono eliminate automaticamente e contano nelle quote. Un nuovo oggetto non riutilizza un object_id già presente. Recuperare un elemento cancellato è una nuova revisione cifrata dello stesso oggetto.

Ogni commit incrementa la collection_revision del vault di uno e assegna tale valore alla sequence dell'oggetto. Tutto avviene nella stessa transazione delle precondizioni. Il server non cambia i byte del blob. Un mismatch epoch restituisce 409 epoch_changed; una revisione non corrispondente restituisce 412.

`Idempotency-Key` è un Id casuale per operazione logica. È richiesto solo per POST/PUT oggetti e PUT di oggetti nello staging rotazione. Il server associa chiave ad account, classe operazione, metodo, percorso, If-Match e digest del corpo originale, con registro transazionale. Il digest è SHA-256: questi corpi contengono solo ciphertext e metadati, mai auth_secret.

Le conferme di scrittura non ripetono l'envelope, già disponibile al client: il registro idempotenza conserva soltanto digest e risposta compatta, non una copia del payload. Limiti e pulizia del registro non eliminano oggetti del vault.

Una ripetizione identica entro 48 ore restituisce lo stesso status, corpo ed ETag anche se la revisione è avanzata; la risposta storica non è considerata stato attuale dal client. Una ripetizione differente produce 409 idempotency_conflict. Il replay è verificato dopo autenticazione/scope e prima delle precondizioni della scrittura. Dopo 48 ore, POST duplicato restituisce conflitto e PUT con base vecchia 412: il client rilegge lo stato, senza generare una nuova operazione alla cieca.

## 11. Sincronizzazione coerente

### GET `/vault/state` — Normale, 200

Risposta: server_id, account_id, vault_id, epoch_id, credential_generation, recovery_generation, `collection_revision: U64`, `object_count: integer`, `stored_bytes: U64`. Una epoch nuova e vuota ha collection_revision 0.

### GET `/vault/sync` — Normale, 200

Query obbligatoria: `epoch_id: Id`, `since: U64`, `ceiling: U64`, `after_sequence: U64`; opzionale `limit: integer` 1–100, default 50. Deve valere since ≤ after_sequence ≤ ceiling. La prima pagina usa after_sequence = since. Ceiling è la collection_revision appena letta; una sincronizzazione iniziale usa since = 0.

Il server richiede che epoch e collection_revision correnti corrispondano a epoch_id e ceiling per ogni pagina. Se non corrispondono, restituisce 409 epoch_changed o snapshot_changed. La lettura e questo controllo sono eseguiti nella stessa transazione SQLite.

Risposta: epoch_id, `snapshot_revision: U64` = ceiling, `items` ordinati per sequence crescente, `next_after_sequence: U64|null`. Ogni item contiene object_id, revision, sequence ed envelope. Sono selezionate le versioni correnti con sequence maggiore di after_sequence e non oltre ceiling. Non è un archivio delle versioni intermedie di uno stesso oggetto.

La pagina rispetta limit e un massimo di 4 MiB JSON; può contenere meno elementi del limite. Next è la sequence dell'ultimo elemento solo se esistono altri risultati; null indica pagina finale. Almeno un oggetto valido deve poter entrare nella pagina, salvo lista vuota. Since e ceiling invariati vengono ripetuti in tutte le richieste.

Il client verifica gli involucri e accumula le pagine in uno staging locale cifrato. Solo dopo l'ultima pagina applica atomicamente gli aggiornamenti e porta il checkpoint a ceiling. Un errore non modifica la copia attiva. Snapshot_changed elimina quello staging e riparte dal precedente checkpoint; epoch_changed richiede nuovo materiale e il percorso di rotazione, preservando la coda offline.

Non esiste una fotografia persistente lato server: se arrivano scritture tra le pagine si riparte. Questo evita transazioni lunghe, ma traffico continuo può ritardare la sincronizzazione; non si promette progresso sotto scritture infinite. Le tombstone conservate rendono recuperabili anche i dispositivi rimasti offline a lungo. Un server ostile può comunque mentire sul dataset, come descritto nel modello delle minacce.

## 12. Staging e commit di rotazione vault

Tutti gli endpoint richiedono sessione Normale; ogni risorsa appartiene all'account chiamante. Una sola rotazione attiva per account, durata massima 60 minuti, dimensioni entro le quote. Una sessione persa può essere sostituita da un nuovo login della stessa generation; la rotazione non appartiene al solo token originario.

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| POST `/vault/rotations` | If-Match account; current_auth_secret, `base_collection_revision: U64`, `new_epoch_id: Id` | 201: rotation_id, expires_at, base_epoch_id, base_collection_revision, `expected_object_count: integer`, new_epoch_id, `status: "staging"`. |
| GET `/vault/rotations` | Nessun corpo | 200: `items` con le rotazioni proprie non scadute, massimo una in staging; campi della risposta creazione. Consente ritrovare una creazione con risposta persa. |
| GET `/vault/rotations/{rotation_id}` | Nessun corpo | 200: campi creazione e `uploaded_count: integer`, `uploaded_bytes: U64`; stato staging o committed. |
| PUT `/vault/rotations/{rotation_id}/objects/{object_id}` | Idempotency-Key; `envelope: Envelope` | 200: object_id, `digest: string` SHA-256 del blob decodificato in esadecimale minuscolo. |
| POST `/vault/rotations/{rotation_id}/commit` | If-Match account; corpo definito sotto | 200: epoch_id, credential_generation, recovery_generation, collection_revision, reauthentication_required true. |
| DELETE `/vault/rotations/{rotation_id}` | Nessun corpo | 204; elimina staging. Non annulla una rotazione committed. |

Gli involucri caricati sono kind 3, hanno identità correnti, nuovo epoch, object_id del percorso e generation 1. Ogni object_id deve appartenere al dataset attivo al momento del controllo. Ogni ID può essere caricato una sola volta: duplicato identico è confermato, duplicato diverso restituisce 409 state_conflict. Upload non modifica il dataset attivo o la sua collection_revision.

Commit contiene current_auth_secret, new_auth_secret, new_password_descriptor, new_password_envelope e `recovery_action: "keep_disabled"|"replace"|"disable"`.

- keep_disabled è valido solo se recovery era disabilitata; non include campi recovery e conserva la recovery_generation.
- replace richiede recovery attiva e `new_recovery_id`, `new_recovery_auth_secret`, `new_recovery_envelope`; ID può coincidere con quello corrente se il client mantiene R. Il kind 2 ha generation recovery + 1 e nuovo epoch.
- disable richiede recovery attiva, non include campi recovery e incrementa recovery_generation rimuovendo involucro e verificatore. Il client richiede conferma esplicita prima di inviarlo.

La transazione verifica stato, scadenza, account ETag, vecchio epoch e base_collection_revision. Il set degli ID caricati deve coincidere con tutti gli ID correnti, tombstone incluse; il numero da solo non basta. Controlla nuovo materiale PM1 e quote e sostituisce dataset, epoch, credenziali e recovery atomicamente. Gli oggetti ricevono revision 1 e sequence da 1 a N, ordinati per byte object_id; collection_revision diventa N, oppure 0 per dataset vuoto.

Il commit invalida tutte le sessioni normali e Recovery. Una risposta persa viene risolta con prelogin, nuove credenziali e controllo epoch. I vecchi token non ricevono risposte memorizzate del commit. Il registro committed senza segreti resta 48 ore per la diagnosi; lo staging scaduto viene eliminato. Le copie storiche nei backup non vengono cancellate da questa API.

## 13. Amministrazione degli account

| Metodo e percorso | Richiesta | Risposta |
| --- | --- | --- |
| GET `/admin/accounts` | Normale admin; after opzionale Id, limit 1–100 default 50 | 200: items ordinati per account_id, next_after; campi account_id, email, role, `status: "active"|"disabled"`, created_at. Nessun blob o verificatore. |
| POST `/admin/accounts/{account_id}/disable` | Normale admin; current_auth_secret | 204; disabilita e revoca tutte le sessioni dell'utente. |
| POST `/admin/accounts/{account_id}/enable` | Normale admin; current_auth_secret | 204; abilita senza riattivare vecchie sessioni. |

Un amministratore non può disabilitare sé stesso o l'ultimo amministratore attivo: 409 state_conflict. In v1 non sono previsti cambio ruolo remoto, cambio email, cancellazione definitiva dell'account, vault condivisi o download amministrativo dei vault. Non vengono introdotti endpoint che promettono di cancellare le copie offline di un utente.

## 14. Quote, rate limit e risorse

I valori sono default iniziali da misurare sulla macchina CasaOS. Sono configurabili dall'operatore entro limiti validati; ridurre una quota sotto l'uso corrente non cancella dati e consente letture o operazioni che riducono il consumo. Parametri KDF client restano vincolati a PM1, indipendentemente dalle quote.

| Risorsa | Default |
| --- | --- |
| Corpo API ordinario | 16 KiB; endpoint con envelope: 2 MiB. Compressione richiesta non supportata. |
| Pagina sync | 4 MiB JSON e massimo 100 oggetti. |
| Oggetti per vault | 10.000, tombstone incluse. |
| Dati attivi per vault / istanza | 64 MiB / 512 MiB di blob decodificati. |
| Staging rotazione | 64 MiB/account, 128 MiB/istanza, massimo due staging globali. |
| Pendenti registrazione | 100 globali; massimo cinque per invito e tre per email. |
| Inviti non consumati | 1.000 globali. |
| Registro idempotenza | 20.000 conferme/account, 100.000 globali, massimo 64 MiB di dati serializzati; scadenza 48 ore. Saturazione: 429 prima di applicare una nuova scrittura. |
| Verifiche Argon2 server | Due attive, coda globale massimo 16; oltre il limite 503. |
| Timeout | Lettura corpo 15 s, esecuzione handler 30 s, idle HTTP 60 s; invio SMTP fuori dalla richiesta. |

Rate limit iniziali a finestre mobili: discovery 60/min/IP; prelogin normale e recovery insieme 20/min/IP; login/password/recovery e conferme auth_secret 10/min/IP e cinque/min/account o email normalizzata; refresh 30/min/famiglia; nuova registrazione cinque/ora/IP e tre/ora/email; verifica codice secondo la sezione 6; API autenticate 120/min/account e 600/min/IP. I limiti si combinano e non sostituiscono quote globali; nessun blocco account permanente provocabile da richieste anonime.

Per invio email: dieci/ora/destinatario e 100/ora/istanza, oltre ai limiti resend; outbox massimo 100 messaggi. Quote email colpite generano risposte generiche senza rivelare account attivi. SMTP usa trasporto autenticato e protetto e non viene configurato mediante API pubbliche.

I contatori email anonimi usano HMAC della email normalizzata con chiave operativa; i contatori si applicano anche a email assenti. L'IP esterno viene letto dagli header del proxy solo quando la connessione arriva dal connettore configurato fidato; header inoltrati da altre origini non hanno valore. Nessuna logica di sicurezza si basa soltanto sull'IP.

Sono usate chiavi operative casuali distinte per dati sintetici prelogin, HMAC codici, contatori email e cifratura outbox. Sono segreti server, diversi dalle chiavi vault, esclusi da GitHub e conservati nei backup operativi protetti. Rate limit effettivi e quota idempotenza/staging devono essere applicati prima di creare lavoro costoso; il registro idempotenza non conserva corpi o credenziali in chiaro.

## 15. Ripristino, compatibilità e verifiche

Il ripristino da backup avviene offline rispetto al tunnel. Prima di riaprire il servizio si eliminano sessioni normali, Recovery e pendenti, inviti non consumati, codici/outbox e staging; si invalidano i registri idempotenza del vecchio stato. Gli account e i vault restano. server_id è conservato se si ripristina la stessa istanza, altrimenti serve una migrazione client esplicita: modificarlo rompe il contesto crittografico PM1.

Il client deve gestire server restaurati con revisioni storiche senza scartare automaticamente dati locali più recenti. Il contratto non garantisce rilevamento assoluto di rollback su un dispositivo nuovo. I dati di backup e recupero seguono il protocollo PM1.

API v1 non cambia significato di campi, generation o blob. Una futura versione incompatibile avrà base e negoziazione nuove. Funzioni dichiarate nella discovery sono capacità implementate: fino alla loro implementazione il servizio non dichiara pronto un endpoint soltanto perché previsto da questo documento.

Prima della distribuzione si verificano almeno:

- Percorso registrazione completo, email solo iniziale, retry materiale e verify con risposta persa.
- Consumo concorrente di invito, unico account per email e bootstrap amministrativo non pubblico.
- Fallimenti uniformi prelogin/login/recovery, limiti tentativi e saturazione Argon2.
- Accesso utente A a tutte le risorse dell'utente B; token di classe diversa su ogni endpoint.
- Refresh concorrente, riutilizzo, logout, revoca e famiglie scadute.
- Cambio password e recovery atomici, risposta persa e token invalidati.
- Scritture concorrenti, tombstone, retry identico/diverso e scadenza dell'idempotenza.
- Sync multi-pagina con scrittura durante il percorso: nessuna applicazione parziale al client.
- Rotazione con ID mancante, modifica concorrente, scadenza, commit e crash tra staging e risposta.
- Quote reali di payload, disco e memoria con Immich e Jellyfin attivi.
- Ripristino con dati decifrabili e vecchie capability inutilizzabili.

Queste sono prove richieste, non risultati già ottenuti. Lo schema dei contenuti cifrati viene definito nei modelli client; il backend tratta gli Envelope come blob con intestazione validata.

### 15.1. Payload delle credenziali implementato nel client

Il backend non interpreta questo schema: è plaintext esclusivamente all'interno di un involucro PM1 kind 3. Il client implementa `schema: 1`, `deleted: false`, `type: "credential"`, più i campi stringa `title`, `username`, `email`, `password`, `url`, `notes` e l'array di stringhe `tags`. Tutti i campi sono obbligatori nel formato serializzato; i valori opzionali del modulo sono stringhe vuote o array vuoto. Il titolo deve contenere testo diverso da spazi. Il client non modifica gli spazi delle password.

I limiti sono byte UTF-8: titolo 200; username/email 1.024 ciascuno; password/URL 4.096 ciascuno; note 65.536. Massimo 32 tag distinti, non vuoti, da 100 byte ciascuno. Stringhe con surrogati non validi sono rifiutate. Versioni, tipi, campi sconosciuti o mancanti bloccano la lettura del nuovo snapshot: nessuna sostituzione automatica con valori vuoti che potrebbe perdere dati. Le estensioni future richiedono una migrazione esplicita del modello.

Le credenziali con TOTP usano `schema: 2`: stessi campi dello schema 1 più la stringa obbligatoria `totp`, contenente il segreto Base32 canonico senza padding (10–128 byte decodificati). Il profilo è fisso: HMAC-SHA1, sei cifre, 30 secondi, epoch Unix. Il modulo accetta anche link otpauth con parametri compatibili e salva soltanto il segreto normalizzato. Configurazioni non supportate, duplicati nei parametri e Base32 con bit residui non nulli vengono rifiutati. Il segreto è all'interno del payload cifrato, mai nei metadati server o nella ricerca. Le voci prive di TOTP continuano a usare schema 1; la rimozione del segreto ripristina schema 1. I client precedenti non possono leggere schema 2 e devono essere aggiornati prima di usare questa funzione.

Una tombstone contiene esattamente `{"schema":1,"deleted":true}`. Non conserva i campi della credenziale nella nuova versione cifrata. Copie e backup precedenti possono ancora contenere i dati; non è cancellazione sicura della cronologia o del disco.

Il client attuale esegue una lettura online completa da `since = 0`, conserva gli oggetti verificati in memoria e pubblica l'elenco solo dopo tutte le pagine. Non salva checkpoint, cache, bozze o coda offline su disco. Le scritture con esito incerto conservano i byte cifrati originali e la chiave di idempotenza solo nella sessione corrente. Il blocco o la chiusura perde questo tentativo locale. Per questo `offline_sync` resta falso.

## 16. Riferimenti

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html): status e precondizioni If-Match.
- [RFC 9457 — Problem Details](https://www.rfc-editor.org/rfc/rfc9457.html): forma degli errori HTTP con estensioni del progetto.
- [Protocollo PM1](crypto-protocol.md): formati, identità, derivazione e limiti crittografici.

Scadenze, quote, endpoint e strategie di sincronizzazione sono decisioni del progetto, non valori imposti dagli RFC.

### Credenziale con passkey: schema 3

Stessi campi dello schema 1, più totp (segreto Base32 canonico oppure null) e passkey (oggetto obbligatorio con esattamente otto campi): algorithm intero -7, rp_id, user_id, user_name, display_name, credential_id, private_key e public_key. I byte sono Base64url canonico senza padding: user_id 1–64 byte, credential_id 32 byte, private_key PKCS8 massimo 512 byte, public_key SPKI massimo 256 byte. Algoritmo ES256 e curva P-256 sono controllati dal provider prima dell'uso. rp_id è un dominio ASCII minuscolo con etichette valide; user_name e display_name hanno 1–256 byte UTF-8 validi. Nessuno di questi campi viene esposto nei metadati server.

Togliendo la passkey, il record torna allo schema 2 se conserva TOTP, altrimenti allo schema 1. La tombstone resta schema 1. Client che non supportano schema 3 rifiutano il record: aggiornare tutti i dispositivi prima dell'uso. Il contratto del contenitore biometrico e del provider Android è descritto in android-security.md.

### Sessioni: aggiornamento server 0.2.3

Dal server 0.2.3 il limite di dieci sessioni attive è mantenuto chiudendo, solo dopo autenticazione valida, la sessione meno recentemente usata quando un nuovo accesso raggiunge il limite. La famiglia chiusa e i suoi refresh token vengono rimossi nella stessa transazione del nuovo accesso. Un'autenticazione fallita non cambia le sessioni esistenti. Non cambiano formato delle richieste, durata dei token o schema SQLite. I server precedenti possono restituire 409/session_limit.

### Organizzazione del vault: schema 4 (client 0.3.0)

Le credenziali aggiungono `category_id` nullable (ID Base64url canonico di 16 byte), `favorite` booleano e `logo` nullable (slug ASCII minuscolo, lettere/cifre/trattini, da 1 a 80 caratteri, primo carattere alfanumerico). `generic` forza l'iniziale. Sono obbligatori tutti i campi precedenti, con `totp` e `passkey` nullable. Il client emette schema 4 solo quando almeno una informazione organizzativa è presente; lo mantiene anche quando si rimuove la passkey ma resta una categoria, un preferito o un logo esplicito.

Le categorie sono oggetti separati dello stesso vault, con payload esatto `{"schema":4,"deleted":false,"type":"category","title":"Lavoro"}`. Il titolo segue il limite di 200 byte UTF-8. Il riferimento delle credenziali usa l'object_id della categoria, quindi una rinomina non richiede riscritture delle credenziali. Il client impedisce nomi duplicati nel proprio snapshot e la rimozione di categorie non vuote. Creazioni concorrenti da snapshot differenti possono comunque produrre nomi uguali: gli ID restano distinti. Una categoria mancante viene mostrata come Senza categoria. Nessun campo organizzativo è visibile al server.

Il server conserva questi payload cifrati senza modifiche alle API. Client precedenti non leggono schema 4: aggiornare tutti i dispositivi dello stesso account prima dell'uso. Le tombstone restano schema 1. Dettagli e installazione in [update-0.3.0.md](update-0.3.0.md).

## Pannello amministratore, versione 0.2.0

GET /admin e GET /brand.png servono la pagina pubblica di accesso e il logo. GET /api/v1/admin/accounts richiede Authorization: Bearer con una chiave operatore dedicata, non un access token utente. Nessun cookie, CORS o segreto in query. Un solo header Authorization; richieste GET senza corpo e cursore opzionale after con ID canonico. Risposta items (account_id, email, role, created_at) e next_after, massimo 100 account per pagina. Nessuna chiave, verificatore, contenuto vault o dato del codice email. Accesso senza chiave, con chiave errata, revocata, scaduta o associata a un account che non mantiene il ruolo admin: 401. Massimo due operazioni amministrative simultanee, oltre tale limite 429.

La chiave viene generata localmente con panel-key dopo la prima attivazione admin, ha entropia di 256 bit, scade dopo 24 ore, sostituisce la precedente e viene conservata nel database come SHA-256. panel-revoke la invalida. Questo percorso consente soltanto la lettura dei metadati account; non conferisce accesso ai vault o agli altri endpoint. Il browser la conserva in memoria per cinque minuti senza interazioni e la rimuove quando la pagina viene lasciata. Le risposte hanno Cache-Control no-store, Referrer-Policy no-referrer, CSP restrittiva e protezione contro l'incorporamento in frame. Assets serviti localmente senza CDN.
## Gestione amministrativa, server 0.2.2

Estende il pannello 0.2.0: la chiave dedicata ora consente anche inviti e cancellazione. Richiede che il proprietario sia ancora admin e active, verificato nella stessa transazione dell'operazione. Nessun accesso al plaintext del vault. Nessuna migrazione aggiuntiva rispetto allo schema 9.

- POST /api/v1/admin/invitations: JSON email (protocol.Email obbligatoria), ttl_hours (intero 1–168). Risposta 201 con invitation_id, email, invitation_secret e expires_at. Segreto mostrato soltanto alla creazione; nessun invio automatico dell'invito. Ruolo sempre user. Account già registrato: 409 account_exists. Limite globale inviti attivi: 429 invitation_limit.
- POST /api/v1/admin/accounts/delete: JSON account_id e confirm_email obbligatori. Successo 204; account assente o email diversa: 409 confirmation_mismatch; qualsiasi amministratore: 403 administrator_protected. Rimuove account, sessioni/token e vault tramite vincoli CASCADE, registrazioni/coda email collegate e revoca gli inviti ancora attivi per la stessa email. Tutto nella stessa transazione. Non cancella copie nei dispositivi, nei backup o residui fisici SQLite.

Entrambe richiedono Authorization: Bearer con chiave pannello, application/json, corpo massimo 4096 byte, nessun parametro query. Campi sconosciuti/duplicati, null o valori mancanti non validi sono rifiutati. Nessun cookie/CORS: le origini browser estranee e Sec-Fetch-Site cross-site sono rifiutati; un client senza Origin deve comunque presentare la chiave dedicata. La pagina conferma la cancellazione riscrivendo l'email, disabilita invii doppi e non ripete automaticamente modifiche con esito incerto.
