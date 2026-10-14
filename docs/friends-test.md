# ByteLocker: inviti per la prova privata

Ogni amico usa lo stesso indirizzo HTTPS del server e un account separato con la propria Master Password. Non condividere il tuo account o un invito amministratore. Il Quick Tunnel resta temporaneo; questa procedura non rende il servizio pronto per password reali o distribuzione pubblica.

## Aggiornamento del solo comando amministrativo

Il pacchetto bytelocker-friends-update.zip contiene soltanto sorgenti modificati e documentazione, senza dati, configurazione o segreti. Trasferiscilo su CasaOS ed estrailo in /DATA/AppData/bytelocker, sostituendo esclusivamente i file sorgente omonimi. Non rimuovere o sostituire data, secrets o .env.

Nel terminale:

```sh
cd /DATA/AppData/bytelocker
sudo docker compose build bytelocker
sudo docker compose run --rm --no-deps --entrypoint /usr/local/bin/bytelocker-admin bytelocker -h
```

Il comando di aiuto deve mostrare invite -email address. La build aggiorna l'immagine locale; run avvia soltanto uno strumento amministrativo temporaneo che usa il volume dati esistente. Il backend e cloudflared già avviati non vengono ricreati. Non eseguire up, down o restart: non serve per questo aggiornamento e ricreare cloudflared può cambiare il tuo URL. Le API di registrazione esistenti già accettano il ruolo user. Nessuna nuova migrazione del database è inclusa.

## Invito di un amico

Sostituisci amico@example.com con la sua email reale:

```sh
sudo docker compose run --rm --no-deps --entrypoint /usr/local/bin/bytelocker-admin bytelocker -data-dir /data invite -email amico@example.com -ttl 24h
```

L'output contiene invitation_id, email, scope user, scadenza e invitation_secret. Il segreto è mostrato solo alla creazione. Comunica privatamente all'amico l'indirizzo HTTPS attuale e invitation_secret. Non pubblicare l'output o inviarlo in chat di supporto. Questo comando non invia email: il codice arriva quando l'amico completa la registrazione nell'app.

L'amico installa il client Android o Windows, collega il server, sceglie Crea un account, inserisce la stessa email dell'invito, il codice invito e la propria Master Password, quindi conferma il codice ricevuto via email. Alla riapertura accede al proprio account ricordato. Non occorre installare un client VPN o aprire porte sul router.

## Elenco e revoca

```sh
sudo docker compose run --rm --no-deps --entrypoint /usr/local/bin/bytelocker-admin bytelocker -data-dir /data list
sudo docker compose run --rm --no-deps --entrypoint /usr/local/bin/bytelocker-admin bytelocker -data-dir /data revoke -id ID_INVITO
```

L'elenco non mostra i segreti. Revocare un invito impedisce una nuova attivazione ma non elimina un account già creato e non revoca le sue sessioni. Un invito scaduto, revocato, consumato o usato con un'altra email non può attivare l'account.

## Verifica con due persone

Per questa prima prova usate soltanto credenziali inventate. Ciascuno crea una voce con un nome diverso, chiude e riapre l'app, controlla il proprio elenco e modifica la propria voce. Nessuno deve vedere le voci dell'altro. I test automatici verificano attivazione con ruolo user, consumo, email, scadenza, revoca e isolamento degli oggetti e della sincronizzazione tra account; la prova con i dispositivi e il servizio email reale resta da eseguire.

Prima dell'uso quotidiano restano backup con ripristino verificato, rinnovo client delle sessioni, indirizzo stabile e revisione di sicurezza. Nessun vault web nel browser è incluso.
