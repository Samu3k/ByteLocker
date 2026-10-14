# ByteLocker su CasaOS: installazione di prova

Il pacchetto contiene sorgenti, Dockerfile e configurazione Compose: non è un'immagine già pubblicata su Docker Hub o un'app presente nello store CasaOS. Va compilato sul server. Prima installazione guidata dal terminale; il file Compose include i metadati CasaOS per una successiva importazione. Non avviare una seconda copia dalla dashboard mentre quella del terminale è attiva.

## Stato verificato e limiti

Sono validate con Docker Compose 5.6.0 le configurazioni base, base+tunnel e base+Gmail+tunnel. I comandi server/admin hanno superato i test. I tre binari Go sono compilabili per Linux amd64 e arm64 senza CGO. L'utente ha confermato su CasaOS x86_64 la build Docker, l'avvio healthy, l'invio email, il collegamento tramite Quick Tunnel e l'uso dei client Android e Windows. L'aggiornamento del comando invite e la prova con gli amici devono ancora essere eseguiti sul suo server.

Usare account e credenziali sintetici. Questa è una modalità di sviluppo: protezioni proxy complete, backup online verificato e revisione indipendente restano da completare. Gli IP inoltrati dal proxy non sono fidati; dietro il tunnel le quote IP sono condivise tra gli utenti. Il primo amministratore si crea con bootstrap; dopo la sua attivazione il comando locale invite crea inviti per utenti normali legati all'email. Non è presente un pannello di amministrazione multiutente.

## Cosa viene installato

- Backend Go/SQLite: un container, un database locale persistente, utente 10001:10001, filesystem di sistema in sola lettura, capabilities rimosse. Limite 384 MiB RAM e una CPU; non rappresenta una misura del consumo reale. Il picco della compilazione non è incluso in questi limiti.
- Dati in /DATA/AppData/bytelocker/data, comprese le chiavi operative data/secrets/instance.keys. Sono chiavi del servizio email/quote, non del vault.
- Nessuna porta host e nessuna modifica al router. API e health ascoltano solo sul loopback del container. Il tunnel opzionale condivide la rete del backend e punta esclusivamente alla porta API 8080; health 8081 non viene pubblicata.
- Cloudflared 2026.10.0, immagine fissata tramite digest; massimo 128 MiB RAM. Il tunnel non parte con la configurazione base e non si riavvia automaticamente.
- Nessun accesso al socket Docker, a Immich, a Jellyfin o ai loro volumi.

Il tunnel gratuito fornisce un URL HTTPS pubblico temporaneo; chi conosce l'URL può raggiungere le API, che richiedono la propria autenticazione. Non è una rete privata. Cloudflare termina HTTPS e può osservare traffico e metadati di autenticazione; il contenuto del vault è cifrato dal client anche dentro HTTPS. L'autenticazione email interattiva di Cloudflare non va abilitata davanti a queste API: il client Flutter non la supporta.

## 1. Trasferimento e controllo strumenti

Apri CasaOS al suo indirizzo locale e carica il file bytelocker-casaos-test.zip nella cartella /DATA/AppData/bytelocker tramite il gestore file. Estrailo: Dockerfile, compose.yaml e backend devono trovarsi direttamente in questa cartella, senza una sottocartella duplicata. La cartella non deve già contenere un'altra installazione ByteLocker. Non trasferire backend/data dal PC durante questa prima prova: creeremo un'istanza nuova, con identità propria.

Nel terminale Linux del server:

```sh
cd /DATA/AppData/bytelocker
docker version
docker compose version
uname -m
```

Serve Docker Compose v2 o successivo, con supporto delle opzioni usate. Se un comando restituisce un errore, fermarsi e condividere soltanto quell'errore. Non installare strumenti o cambiare servizi di CasaOS alla cieca. Se Docker segnala permessi insufficienti, usare sudo davanti ai comandi Docker. Non aggiungere utenti al gruppo docker senza valutarne i privilegi.

## 2. Cartella dati e primo avvio isolato

Per questa nuova installazione, verifica prima che data non esista:

```sh
test ! -e /DATA/AppData/bytelocker/data
```

Se il comando fallisce, fermarsi e verificare la cartella; non cambiare proprietario di dati preesistenti. Se riesce:

```sh
sudo mkdir /DATA/AppData/bytelocker/data
sudo chown 10001:10001 /DATA/AppData/bytelocker/data
sudo chmod 700 /DATA/AppData/bytelocker/data
docker compose config --quiet
docker compose build bytelocker
docker compose up -d bytelocker
docker compose ps
docker compose exec bytelocker /usr/local/bin/bytelocker-healthcheck
docker compose logs --tail=30 bytelocker
```

Attendi lo stato healthy. Il controllo stato termina senza testo se riesce. Senza Gmail la registrazione è disabilitata: è previsto. Non usare http://INDIRIZZO-LOCALE:8080 nell'app: questa configurazione non pubblica quella porta. Non c'è una pagina web del vault sul server; l'interfaccia è nel client Android/Windows.

## 3. Gmail, prima di esporre le API

La password richiesta è una password per le app Google, distinta dalla password Gmail normale e dalla Master Password ByteLocker. Segui la [guida Google](https://support.google.com/accounts/answer/185833?hl=it); dipende dalla disponibilità della funzione per il tuo account. Non inviare password, file o schermate di segreti in chat.

Per una nuova cartella secrets:

```sh
test ! -e /DATA/AppData/bytelocker/secrets
```

Se riesce:

```sh
sudo install -d -m 0700 /DATA/AppData/bytelocker/secrets
sudo install -m 0600 /dev/null /DATA/AppData/bytelocker/secrets/gmail-app-password
sudo nano /DATA/AppData/bytelocker/secrets/gmail-app-password
```

Scrivi solo la password per le app nell'editor e salva. Se nano non è presente, usa un editor locale del server che non registri il contenuto nella cronologia dei comandi. Non mettere il segreto direttamente in un comando. Poi:

```sh
sudo chown 10001:10001 /DATA/AppData/bytelocker/secrets/gmail-app-password
cp .env.example .env
chmod 600 .env
nano .env
```

In .env compila solo PM_SMTP_USERNAME con la tua email Gmail; lascia i percorsi predefiniti. La password resta esclusivamente nel file separato, montato in sola lettura. La directory secrets host resta accessibile solo all'amministratore; Docker monta direttamente il file con proprietario 10001:10001.

```sh
docker compose -f compose.yaml -f compose.gmail.yaml config --quiet
docker compose -f compose.yaml -f compose.gmail.yaml up -d bytelocker
docker compose -f compose.yaml -f compose.gmail.yaml ps
```

Questo valida formato e lettura del file, non le credenziali presso Gmail: la verifica avviene al primo invio. In caso di errore il backend non parte; non disabilitare TLS o i controlli per aggirarlo.

## 4. Primo invito

```sh
docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data bootstrap
```

Conserva invitation_secret privatamente; verrà usato nel modulo Crea un account. Non pubblicare l'output. L'invito non è una password server permanente e non contiene la Master Password. Il comando non manda email o crea account. Per elencare gli inviti senza segreti usa lo stesso comando sostituendo bootstrap con list. Il bootstrap si chiude dopo l'attivazione del primo amministratore.

Per invitare un utente normale dopo la prima attivazione, vedi [Prova privata con gli amici](friends-test.md). Il comando invite richiede -email, permette una durata da 5 minuti a 7 giorni e non può creare amministratori. La registrazione consuma l'invito solo dopo la verifica email.

## 5. Attivazione volontaria del tunnel di prova

Solo dopo che backend e Gmail sono configurati, esegui:

```sh
docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d
docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=60 cloudflared
```

Nei log compare https://nome-casuale.trycloudflare.com. Apri quell'indirizzo seguito da /api/v1/config nel browser: devi vedere il JSON ByteLocker e registration_available true. Nel client inserisci solo l'origine HTTPS, senza /api/v1/config; crea l'account con invito e codice email usando una Master Password nuova di prova. Verifica poi login e una credenziale sintetica.

I [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/) non richiedono account o dominio, hanno un nome che cambia a ogni creazione e nessuna garanzia di disponibilità. Non aggiungere --allowed-mail: richiede un flusso browser incompatibile con le API del client. Non promettere un URL stabile o uso definitivo.

Il cambio URL richiede un nuovo collegamento nell'app e una nuova abilitazione biometrica per quella origine. Il database resta lo stesso; non reinstallare il server per cambiare URL. La creazione e l'uso passkey possono richiedere di ricollegare il server anche nell'attività Android separata.

## Arresto, riavvio e backup

Per chiudere subito l'accesso pubblico:

```sh
docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml stop cloudflared
```

Per fermare anche il backend:

```sh
docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml down
```

I dati bind mount rimangono; non eliminare data/secrets o rigenerare instance.keys. Dopo il riavvio del server il backend riparte, il tunnel deve essere avviato volontariamente con il comando della sezione 5. Prima di ricreare o aggiornare il backend, ferma il tunnel e poi usa insieme tutti i file Compose attivi per ricreare i servizi: condividono lo spazio di rete.

Per un backup di questa prova, chiudi tunnel e backend, poi copia privatamente l'intera data (database, WAL/SHM se presenti e chiavi operative), la configurazione .env e il file Gmail separato. Proteggi il backup e verifica il ripristino su un'istanza isolata prima di fidarti. Non copiare solo passwordmanager.db mentre il servizio è attivo. Non ripristinare due backend sullo stesso volume e non usare filesystem di rete per SQLite.

Fonti configurazione: [Docker Compose](https://docs.docker.com/reference/compose-file/services/), [specifiche app CasaOS](https://github.com/IceWhaleTech/CasaOS-AppStore/blob/main/CONTRIBUTING.md). Immagini e digest verificati sul registro Docker ufficiale il 11 ottobre 2026; nessuna immagine del progetto è stata pubblicata.
