# ByteLocker su CasaOS — comandi da tenere a portata di mano

Guida per l'installazione standard in `/DATA/AppData/bytelocker`, con Gmail e Cloudflare Quick Tunnel già configurati. Esegui i comandi nel **terminale del server CasaOS**, uno alla volta. Se compare un errore, fermati prima del passaggio successivo.

**Situazione attuale:** client 0.3.2, server 0.2.3. Per aggiornare soltanto Android o Windows **non devi ricompilare il server**.

[Avvio](#1-avviare-il-server) · [Indirizzo](#2-trovare-lindirizzo-cloudflare) · [Chiave admin](#3-generare-la-chiave-admin) · [Inviti](#4-invitare-un-amico) · [Aggiornamento](#5-aggiornare-e-ricompilare-il-server) · [Backup](#6-backup-manuale-e-giornaliero)

## 1. Avviare il server

Apri la cartella corretta ogni volta che apri un nuovo terminale:

```sh
cd /DATA/AppData/bytelocker
```

Avvia i servizi già installati e controllali:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml ps
```

Aspetta che **bytelocker** risulti `healthy` e **cloudflared** risulti avviato. Non occorre ricompilare a ogni avvio. Se il tunnel parte di nuovo, controlla l'indirizzo nella sezione seguente.

Per una prima installazione completa, inclusa la configurazione Gmail, usa invece la [guida di installazione](self-hosting.md).

## 2. Trovare l'indirizzo Cloudflare

```sh
cd /DATA/AppData/bytelocker
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=100 cloudflared
```

Cerca **Your quick Tunnel has been created!**: subito sotto trovi l'indirizzo HTTPS da inserire nell'app. Se hai appena avviato il tunnel e non è ancora apparso, attendi qualche secondo e ripeti il comando.

Per estrarre soltanto l'ultimo indirizzo presente nei log disponibili:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --no-color cloudflared 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -n 1
```

Se i log iniziali sono già stati ruotati, il comando può non trovare l'URL: controlla quello salvato nel client. Un risultato vuoto, da solo, non dimostra che il tunnel sia fermo.

Usa l'indirizzo così:

| Dove | Cosa inserire |
| --- | --- |
| Client Android / Windows | L'origine HTTPS, senza percorsi aggiunti |
| Pannello amministratore | Lo stesso indirizzo, seguito da `/admin` |
| Controllo dal browser | Lo stesso indirizzo, seguito da `/api/v1/config` |

Il Quick Tunnel è temporaneo: al riavvio o alla ricreazione può cambiare nome. Se cambia, comunica il nuovo URL agli amici e aggiorna il collegamento CasaOS. **Gli account e le password restano nel database: non crearli di nuovo.**

## 3. Generare la chiave admin

```sh
cd /DATA/AppData/bytelocker
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-key
```

Copia il valore **admin_panel_key** e inseriscilo nel pannello `/admin`. La chiave vale **24 ore**; generarne una nuova sostituisce quella precedente. Non è la Master Password e non è un invito per gli amici.

Non pubblicare la chiave in screenshot o issue e non inviarla agli utenti. Il comando non modifica i vault.

## 4. Invitare un amico

Puoi creare l'invito direttamente dal pannello `/admin`, inserendo l'email dell'amico. In alternativa, sostituisci l'email di esempio nel comando:

```sh
cd /DATA/AppData/bytelocker
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data invite -email friend@example.com -ttl 24h
```

Condividi privatamente **invitation_secret** e indirizzo HTTPS. Ogni persona usa l'email invitata e sceglie la propria Master Password. L'invito dura 24 ore; l'email di verifica viene inviata quando l'amico si registra. L'invito stesso va comunicato da te.

Per vedere gli inviti:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data list
```

**Agli amici basta il [link della release GitHub](https://github.com/Samu3k/ByteLocker/releases/tag/v0.3.2)** per scaricare l'APK Android o lo ZIP Windows. Non devono installare il server CasaOS e non serve un account GitHub per scaricare i file pubblici.

## 5. Aggiornare e ricompilare il server

Questa procedura serve **quando aggiorni il backend**, non per un semplice aggiornamento dei client. È pensata per l'installazione standard già funzionante; per cambiamenti di schema o versione segui anche le note della release scelta.

### A. Trasferisci i file distribuiti

Scarica il pacchetto server della versione scelta, estrailo e copia i file distribuiti in `/DATA/AppData/bytelocker`. Mantieni la stessa struttura: `Dockerfile`, `backend`, file Compose e `maintenance` devono essere nella cartella principale dell'installazione.

**Conserva `data`, `secrets` e `.env`.** Non sostituirli con dati di un'altra installazione, non cancellarli e non caricarli su GitHub. L'archivio server distribuito non contiene queste configurazioni private.

### B. Esegui il backup prima della compilazione

Con il server attuale ancora avviato:

```sh
cd /DATA/AppData/bytelocker
sudo chmod 755 maintenance/bytelocker-maintenance
sudo sh maintenance/backup.sh
```

Prosegui soltanto se termina con **Backup verificato**. Gli archivi restano in `/DATA/Backups/bytelocker`. Il backup non riavvia il server o il tunnel.

### C. Compila

```sh
sudo docker compose build bytelocker
```

La prima compilazione può richiedere diversi minuti. Aspetta il messaggio finale di compilazione riuscita prima di proseguire.

### D. Avvia la versione aggiornata

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d --force-recreate bytelocker cloudflared
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml ps
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=30 bytelocker
```

Vengono ricreati entrambi perché Cloudflare condivide la rete del contenitore ByteLocker. Attendi `healthy`, poi recupera **il nuovo indirizzo** dalla sezione 2. I volumi e gli account vengono conservati.

Non usare `docker compose down -v`, non eliminare la cartella dati e non ripetere il bootstrap per aggiornare. Il bootstrap serve soltanto alla creazione del primo amministratore su una nuova installazione.

## 6. Backup manuale e giornaliero

Per una copia manuale:

```sh
cd /DATA/AppData/bytelocker
sudo sh maintenance/backup.sh
```

Dopo una copia riuscita e una prova di ripristino separata, con cron attivo puoi attivare la copia giornaliera:

```sh
sudo sh maintenance/install-daily.sh
```

L'orario è **03:30 nel fuso del server**. Controlla gli esiti con:

```sh
sudo tail -n 30 /var/log/bytelocker-backup.log
```

Gli archivi contengono anche segreti operativi: mantienili privati e conserva una copia protetta su un supporto separato. Non estrarre un backup sopra il server attivo: segui la [guida di verifica e ripristino](../backup-casaos.md).

## Se compare un errore

| Messaggio / situazione | Cosa controllare |
| --- | --- |
| `no configuration file provided` | Esegui prima `cd /DATA/AppData/bytelocker`. |
| `permission denied` sul socket Docker | Usa i comandi con `sudo`, come indicato sopra. |
| `health: starting` | Attendi e ripeti `ps`; se resta così, leggi i log ByteLocker. |
| L'indirizzo vecchio non funziona | Recupera l'URL del tunnel attuale, senza ricreare gli account. |
| Chiave pannello scaduta | Genera una nuova `panel-key`; non serve ricompilare. |
| Errori Gmail / verifica email | Controlla la configurazione privata e i log; non pubblicare password o chiavi. |

[Torna alla panoramica](README.md) · [Installazione completa](self-hosting.md) · [Aggiornamento server 0.2.3](../update-0.3.1.md)
