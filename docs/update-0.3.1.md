# ByteLocker client 0.3.1 e server CasaOS 0.2.3

## Correzione dello sblocco dopo l'uso delle passkey

Il server precedente consentiva dieci sessioni attive e poi restituiva HTTP 409 `session_limit`. Chiudere un processo o un'attività Android delle passkey non garantisce che il logout arrivi al server; riaperture ripetute possono quindi esaurire le sessioni. Il client mostrava un generico conflitto, senza distinguere questo caso.

Server 0.2.3: dopo aver verificato completamente le credenziali, il nuovo accesso chiude la sessione attiva utilizzata meno di recente, se il limite è raggiunto. Rimangono al massimo dieci sessioni attive. Sono invalidati anche i token di rinnovo della sessione chiusa. Un accesso con credenziali errate non chiude alcuna sessione. Account e vault non vengono rimossi. Su un dispositivo la cui sessione è stata chiusa occorre sbloccare nuovamente il vault.

Client 0.3.1 riconosce il codice `session_limit` dei server precedenti e indica di aggiornare CasaOS. La passkey salvata per un sito resta distinta dall'autenticazione dell'account ByteLocker. Questo difetto è riproducibile nei test; la conferma sul telefono richiede la stessa prova dopo l'aggiornamento. Se persiste, annotare il testo esatto dell'errore e il momento in cui appare, senza condividere password, inviti o chiavi.

## Copia del codice 2FA

Il pulsante Copia codice 2FA appare accanto alle sei cifre sia su Android sia su Windows, anche nell'anteprima dell'editor. Il codice viene calcolato all'istante del tocco: un codice ancora visibile ma appena scaduto non viene copiato. Non viene copiato il segreto TOTP. Usa le protezioni native degli appunti introdotte nella 0.3.0.

## Pacchetti client

- Windows: chiudi l'app, estrai tutto `ByteLocker-Windows-0.3.1.zip` in una nuova cartella e avvia l'eseguibile. Non spostare solo ByteLocker.exe.
- Android ARM64: installa `ByteLocker-0.3.1-android-arm64.apk` sopra la versione esistente. Non disinstallare prima. Il pacchetto usa compilazione Flutter release, senza motore di debug/hot reload, ma mantiene esplicitamente la firma privata di prova precedente per consentire l'aggiornamento. Non è un pacchetto Play Store; per la distribuzione pubblica serve una chiave release dedicata.
- Per risolvere il limite di sessioni aggiorna **anche il server a 0.2.3**, seguendo la guida sotto. Il solo APK non può correggere il controllo sul server.

Schema cifrato 4, categorie, preferiti, loghi e API mantengono la compatibilità con 0.3.0. I client precedenti a 0.3.0 non leggono categorie e preferiti.

APK firmato: circa 24,5 MB, contro 103,7 MB della 0.3.0 debug, una riduzione di circa il 76%. Firma v2/v3 verificata e certificato identico; versione 0.3.1, build 7, ARM64, applicazione non debuggabile. Compilazione Windows release e avvio del pacchetto verificati. Il binario di manutenzione è Linux x86_64 statico e include le attribuzioni delle dipendenze in maintenance/third_party.

## Aggiornamento CasaOS con backup prima della sostituzione

Il pacchetto `bytelocker-casaos-0.2.3.zip` include sorgenti server e cartella maintenance con lo strumento Linux x86_64. Non include data, secrets, .env o credenziali. Sono conservati anche i vecchi pacchetti finché la nuova versione non è confermata.

1. Estrai il pacchetto e trasferisci il contenuto in `/DATA/AppData/bytelocker`, sostituendo solo i file distribuiti. Conserva **data, secrets e .env**.
2. Esegui un backup del server attuale, ancora prima di ricompilare:

```sh
cd /DATA/AppData/bytelocker
sudo chmod 755 maintenance/bytelocker-maintenance
sudo sh maintenance/backup.sh
```

Deve terminare con `Backup verificato` e lasciare il server healthy. Il backup usa una copia SQLite coerente mentre il server resta attivo e non riavvia Cloudflare. Un contenitore di manutenzione temporaneo, senza rete e con UID 10001, produce la copia; usa l'immagine locale già installata e il nuovo strumento montato in sola lettura. Non serve ricompilare prima il server. In caso di errore fermati prima della sostituzione dell'immagine.

3. Compila e avvia il nuovo server:

```sh
sudo docker compose build bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d --force-recreate bytelocker cloudflared
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml ps
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=100 cloudflared
```

Cloudflare condivide la rete del contenitore ByteLocker: dopo una sostituzione occorre ricreare entrambi. Questa volta il Quick Tunnel può cambiare indirizzo. Usa il nuovo URL HTTPS mostrato nei log nei client e nel collegamento `/admin`; non cancellare o ricreare gli account. La manutenzione giornaliera invece non ferma né riavvia il servizio o il tunnel.

4. Accedi dai client aggiornati e prova lo sblocco dopo aver creato una passkey. Il limite già raggiunto si risolve al primo accesso valido con il nuovo server.
5. Dopo un backup manuale riuscito puoi attivare la pianificazione:

```sh
sudo sh maintenance/install-daily.sh
```

Esegue un backup giornaliero alle 03:30 nel fuso orario del server. Dettagli, controllo e ripristino in [backup-casaos.md](backup-casaos.md).

## Verifiche

Suite Go completa superata; ripristino su copie sintetiche con account, oggetti cifrati, chiavi e configurazione; copia WAL e snapshot online verificati; archivi corrotti, percorsi estranei, link, destinazioni esistenti e schema/chiavi non corrispondenti rifiutati. Script provato con Docker simulato, inclusi snapshot, creazione e verifica falliti: nessun arresto/riavvio del backend o di cloudflared. Lo script e il binario Linux non sono stati eseguiti sul server CasaOS dell'utente.

67 test Flutter superati, analisi senza segnalazioni; prova Flutter/Go reale con SQLite temporaneo e consegna email simulata superata. Compilazioni e firme sono verificate nella consegna. Nessuna email reale inviata e nessun account reale eliminato dai test.
