# Backup privati di ByteLocker su CasaOS

Strumenti per Linux x86_64 e installazione `/DATA/AppData/bytelocker`. Compatibili con database schema 9 del server 0.2.2 e 0.2.3. Non richiedono Go, Python o SQLite installati sul server; il binario incluso è autonomo. Richiedono Docker Compose, flock, sha256sum e, per la pianificazione, cron attivo.

## Cosa viene salvato

Database SQLite, instance.keys, configurazione .env, password applicativa Gmail se presente, file Compose. Lo snapshot online incorpora anche le transazioni già confermate nel WAL, senza doverlo distribuire separatamente. Sono esclusi sorgenti, build client e file non previsti. Identità server, account e contenuti cifrati vengono verificati su una copia isolata, senza creare account, migrare il database o inviare email. Ogni file ha un hash SHA-256 nel manifest; gzip verifica anche la propria integrità.

**L'archivio non è cifrato nel suo insieme e contiene segreti operativi, compresa la password applicativa Gmail.** Cartella 0700, file 0600 e uso root proteggono l'accesso locale Linux. Non pubblicarlo su GitHub, non inviarlo agli amici e non caricarlo su uno spazio pubblico. I vault restano cifrati dal client; il manifest non contiene email degli utenti o segreti. Gli hash rilevano errori accidentali, non autenticano un archivio sostituito intenzionalmente da chi può riscrivere anche il manifest.

## Primo backup

```sh
cd /DATA/AppData/bytelocker
sudo chmod 755 maintenance/bytelocker-maintenance
sudo sh maintenance/backup.sh
```

Prima del fermo lo script controlla i percorsi dei volumi. Installazioni con dati o segreto Gmail esterni al progetto sono rifiutate: adattare esplicitamente la procedura anziché creare una copia incompleta. Non eseguire altri comandi amministrativi o aggiornamenti in parallelo.

Lo script lascia attivi ByteLocker e cloudflared. Un contenitore temporaneo usa lo strumento incluso con UID/GID 10001, senza rete, con filesystem di base in sola lettura, memoria massima 128 MiB e CPU limitata. Gli vengono montati soltanto il binario e la cartella dati; non riceve Gmail, .env o il socket Docker. L'immagine è quella già presente sul server, senza scaricamenti.

La copia consistente usa [SQLite VACUUM INTO](https://www.sqlite.org/lang_vacuum.html#vacuum_with_an_into_clause), che produce una copia compatta senza modificare il database originale. Poi il processo sul server crea l'archivio con la configurazione privata e lo verifica estraendolo in una cartella temporanea. Gli snapshot vengono rimossi dopo l'uso. In caso di spegnimento forzato può restare una cartella privata `.bytelocker-snapshot-*` in data; non viene usata dal backend. Limite attuale degli archivi: 2 GiB complessivi non compressi e 1 MiB per ogni file di configurazione/segreto. Lo spazio libero deve contenere snapshot, copia temporanea e archivio. Il database e il WAL dal vivo mantengono proprietà e permessi del servizio.

Gli archivi vengono scritti in `/DATA/Backups/bytelocker/bytelocker-AAAAMMGGTHHMMSSZ.tar.gz`, con impronta `.sha256`. I nomi usano UTC. Un secondo backup nello stesso secondo rifiuta di sostituire il primo. Non si sovrascrivono copie preesistenti.

## Backup giornaliero

Dopo aver verificato il primo backup manuale:

```sh
sudo sh /DATA/AppData/bytelocker/maintenance/install-daily.sh
```

L'installer controlla che cron sia attivo, crea solo `/etc/cron.d/bytelocker-backup` e un log privato `/var/log/bytelocker-backup.log`. Ripeterlo non duplica la pianificazione; rifiuta un file cron omonimo non riconosciuto. Orario: 03:30 **nel fuso del server**. Se cron manca o è fermo, l'installer si interrompe con un messaggio; installazione/attivazione del servizio dipendono dalla distribuzione CasaOS.

Per controllare l'esito:

```sh
sudo tail -n 30 /var/log/bytelocker-backup.log
sudo ls -lh /DATA/Backups/bytelocker
```

I backup non vengono cancellati automaticamente. Controlla lo spazio libero e conserva anche una copia su un disco separato: una cartella sullo stesso disco non protegge dal guasto del disco. Copia insieme archivio e impronta, su supporto privato o cifrato. Non distribuire mai questi file con l'app.

Per disattivare solo la pianificazione ByteLocker:

```sh
sudo rm -- /etc/cron.d/bytelocker-backup
```

Non rimuove archivi o log. Il cron non viene attivato dal semplice trasferimento dei file.

## Prova di ripristino separata

Sostituisci il nome dell'archivio con quello realmente creato. La destinazione non deve esistere:

```sh
sudo mkdir -p /DATA/Restore
sudo chmod 700 /DATA/Restore
sudo /DATA/AppData/bytelocker/maintenance/bytelocker-maintenance restore \
  -archive /DATA/Backups/bytelocker/bytelocker-AAAAMMGGTHHMMSSZ.tar.gz \
  -destination /DATA/Restore/bytelocker-prova
```

Il risultato deve riportare `status: verified` e gli stessi server_id, accounts e objects del backup. La prova non avvia il backend e non usa Gmail. La destinazione già esistente viene rifiutata; usa un altro nome per una nuova prova. I file rimangono privati e appartengono a root. La cartella di prova contiene anche .env e il segreto Gmail: trattala come il backup.

Puoi verificare senza lasciare una copia estratta:

```sh
sudo /DATA/AppData/bytelocker/maintenance/bytelocker-maintenance verify \
  -archive /DATA/Backups/bytelocker/bytelocker-AAAAMMGGTHHMMSSZ.tar.gz
```

## Ripristino effettivo sul server

Eseguilo solo quando vuoi tornare deliberatamente allo stato del backup: le modifiche successive non sono contenute nella copia. Verifica prima l'archivio e conserva una copia dello stato attuale. Arresta il backend e non eseguire comandi amministrativi mentre sostituisci i dati.

Il comando restore crea sempre una nuova cartella. Da quella copia verificata recupera **insieme** la cartella data, .env e il segreto Gmail; conserva separatamente i file attuali prima di qualsiasi sostituzione. Non estrarre un tar direttamente sopra il server attivo. Per il percorso dati standard, prima di riavviare i file ripristinati in data devono appartenere a UID/GID 10001 e restare privati:

```sh
sudo chown -R 10001:10001 /DATA/AppData/bytelocker/data
sudo chmod 700 /DATA/AppData/bytelocker/data
```

Ripristinare il solo .db senza WAL e instance.keys può perdere dati o impedire l'avvio. Usa il pacchetto sorgente della versione compatibile per ricostruire il servizio; poi controlla healthy e l'accesso con un client. Il ripristino può riportare in vita inviti e sessioni validi al momento della copia: rigenera/revoca le autorizzazioni operative se necessario. La verifica tecnica conferma identità, struttura, chiavi e contenuti cifrati conservati, ma non sostituisce una prova di accesso con la propria Master Password dopo il recupero.

## Compilazione per sviluppatori

Dalla cartella backend, con Go 1.27 e dipendenze del progetto:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false \
  -ldflags='-s -w' -o ../maintenance/bytelocker-maintenance ./cmd/maintenance
go test ./...
node maintenance-tests/backup-wrapper.cjs
```

Per ARM64 ricompila con GOARCH=arm64. Il pacchetto qui consegnato è per il server x86_64 dell'utente. I sorgenti e gli script sono versionabili; archivi, chiavi, .env e password restano esclusi.
