# Un server ByteLocker indipendente

Ogni installazione genera la propria identità, le proprie chiavi operative e il proprio database. Il client non ha un server centrale predefinito. Questa guida usa CasaOS/Linux x86_64, Docker Compose e la cartella standard `/DATA/AppData/bytelocker`.

I pacchetti server sono nelle [Releases](https://github.com/Samu3k/ByteLocker/releases). Repository e download della beta sono pubblici. Il pacchetto contiene sorgenti/configurazioni di esempio, non account o segreti di un'altra istanza.

## 1. Prepara una nuova installazione

Trasferisci il pacchetto server 0.2.3 in `/DATA/AppData/bytelocker` ed estrailo senza creare un ulteriore livello di cartelle. Apri il terminale:

```sh
cd /DATA/AppData/bytelocker
docker --version
docker compose version
uname -m
```

Per il binario di manutenzione incluso è richiesto x86_64. Su ARM64 puoi compilare lo strumento dai sorgenti con GOARCH=arm64.

Solo se è una nuova installazione, crea la directory dati senza toccare una cartella esistente:

```sh
if [ -e data ] || [ -L data ]; then
  echo "La cartella data esiste già: controlla l'installazione prima di continuare."
else
  sudo mkdir data
  sudo chown 10001:10001 data
  sudo chmod 700 data
fi
```

Se la cartella esiste già, segui la guida di aggiornamento invece della procedura per una nuova istanza. Il database e instance.keys devono rimanere insieme.

## 2. Configura l'email sul server

Copia `.env.example` in `.env` solo se quest'ultimo non esiste. Nel file privato imposta PM_SMTP_USERNAME al tuo indirizzo Gmail e mantieni i percorsi standard dei dati e del segreto.

```sh
test -e .env || cp .env.example .env
sudo chmod 600 .env
sudo mkdir -p secrets
sudo chmod 700 secrets
sudo nano .env
```

Genera una password per le app Google seguendo la [guida del fornitore](https://support.google.com/accounts/answer/185833). Non usare la password normale dell'account. Crea un file privato con la sola password applicativa, evitando di inserirla nella riga di comando o nella cronologia del terminale:

```sh
sudo nano secrets/gmail-app-password
sudo chown 10001:10001 secrets/gmail-app-password
sudo chmod 600 secrets/gmail-app-password
```

La password viene letta dal server tramite file montato; non entra nel client, nell'immagine Docker o nei sorgenti. Non caricare .env o secrets su GitHub.

## 3. Compila e avvia

```sh
sudo docker compose build bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml up -d bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml ps
sudo docker compose logs --tail=30 bytelocker
```

Attendi healthy e l'abilitazione della registrazione/mittente email. Un errore Gmail va risolto prima di provare la registrazione. Non condividere password o log che contengano segreti.

Il Compose non pubblica una porta sul PC/server host: il servizio ascolta sulla rete del contenitore. Il pannello web è /admin; il vault è nei client.

## 4. Un collegamento HTTPS per le prove

Per la prova iniziale puoi aggiungere il Quick Tunnel opzionale:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=100 cloudflared
```

Nei log appare un indirizzo `https://your-tunnel.trycloudflare.com`. Usa l'indirizzo effettivo della tua istanza nei client e aggiungi /admin per il pannello. Non pubblicare il tuo indirizzo personale nella repository. Non occorre una VPN sui client né aprire porte del router con questo collegamento uscente.

Il Quick Tunnel è temporaneo: nome e disponibilità possono cambiare. Prima della distribuzione stabile prepara un'origine HTTPS stabile per la tua installazione. [Documentazione Cloudflare](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)

## 5. Primo amministratore e utenti

Sulla nuova istanza genera un invito iniziale amministratore:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data bootstrap
```

Conserva privatamente l'invitation_secret mostrato. Nel client collega il server e crea il tuo account con quell'invito, confermando il codice email. Il bootstrap si chiude dopo l'attivazione del primo amministratore.

Poi genera la chiave del pannello, valida 24 ore:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-key
```

Inserisci admin_panel_key nel pannello HTTPS /admin. Da lì puoi generare inviti utente vincolati all'email ed eliminare account utente con conferma. Gli amministratori sono protetti; il contenuto dei vault non viene mostrato.

Per invitare dal terminale, con un'email di esempio da sostituire:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data invite -email friend@example.com -ttl 24h
```

Non condividere la chiave del pannello o il tuo account: ogni persona riceve il proprio invito e sceglie una Master Password.

## 6. Backup e aggiornamenti

```sh
sudo chmod 755 maintenance/bytelocker-maintenance
sudo sh maintenance/backup.sh
```

Dopo il primo backup verificato, prova un ripristino in una nuova cartella. Poi, con cron attivo, puoi installare la pianificazione:

```sh
sudo sh maintenance/install-daily.sh
```

La pianificazione è giornaliera alle 03:30 nel fuso del server. Gli archivi sono privati, non cifrati nel loro insieme, e contengono anche segreti operativi: conserva una copia su un supporto separato e protetto, senza distribuirla con l'app.

[Backup e ripristino](../backup-casaos.md) · [Aggiornamento 0.3.1 / 0.2.3](../update-0.3.1.md)
