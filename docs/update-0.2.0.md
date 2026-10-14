# ByteLocker 0.2.0: logo, blocco ritardato e amministrazione

## Client Android e Windows

Logo fornito dall'utente, conservato anche nel formato originale. Icone native convertite nel formato richiesto dalle piattaforme. Il vault resta sbloccato per cinque minuti consecutivi fuori dall'app: tornare prima azzera l'attesa; un nuovo cambio di finestra avvia un nuovo intervallo. Le transizioni inactive/hidden/paused non prolungano l'intervallo. Un timer cancella chiavi e contenuto degli editor; al rientro viene ricontrollata la scadenza anche se il sistema ha sospeso i timer. La chiusura dell'app e il blocco manuale restano immediati. La biometria è disponibile su Android se già abilitata; Windows Hello non è incluso.

Aggiorna l'APK senza disinstallare l'app per conservare il collegamento e la biometria. L'APK è ancora una build debug per la prova privata. Su Windows chiudi la vecchia versione, estrai tutto lo ZIP e avvia ByteLocker.exe. La nuova versione usa lo stesso profilo dell'utente Windows.

## Server CasaOS: backup prima dell'aggiornamento

L'aggiornamento introduce la migrazione 9 con una tabella per la chiave amministratore. Account, identità del server e vault esistenti vengono mantenuti. Un vecchio backend non può aprire un database già aggiornato: per tornare indietro serve il backup precedente. Non usare i vecchi comandi admin dopo l'aggiornamento.

Trasferisci il pacchetto bytelocker-casaos-0.2.0.zip su CasaOS. Estrailo in /DATA/AppData/bytelocker sostituendo i soli sorgenti e la documentazione. Non contiene data, secrets, .env o altre configurazioni personali; non eliminare questi elementi dal server.

Compila prima l'immagine, mentre il vecchio servizio continua a funzionare:

```sh
cd /DATA/AppData/bytelocker
sudo docker compose build bytelocker
```

Poi arresta il servizio per un backup coerente. Questo interrompe temporaneamente l'accesso degli amici. Il tunnel verrà ricreato e probabilmente riceverà un nuovo indirizzo.

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml stop cloudflared bytelocker
sudo install -d -m 0700 /DATA/AppData/bytelocker-backups
sudo sh -c 'umask 077; tar -czf /DATA/AppData/bytelocker-backups/pre-0.2.0-$(date +%Y%m%d-%H%M%S).tar.gz -C /DATA/AppData/bytelocker data secrets .env'
```

Verifica che tar termini senza errori. Il backup contiene credenziali del servizio e deve restare privato. Questo crea una copia coerente, ma non sostituisce una prova di ripristino isolata.

Avvia il backend aggiornato e ricrea il tunnel per collegarlo alla sua nuova rete:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d --force-recreate bytelocker cloudflared
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml ps
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=60 cloudflared
```

Usa il nuovo indirizzo HTTPS nei client, tramite Cambia server o account. L'account e i vault restano gli stessi perché il volume data non viene sostituito. La biometria Android è legata anche all'origine HTTPS: se cambia, accedi con Master Password e riabilitala per il nuovo indirizzo.

## Apertura del pannello

Apri https://INDIRIZZO-TUNNEL/admin. La pagina iniziale mostra il logo e l'accesso amministratore. Il pannello legge email, ruolo, identificativo account e data di creazione, con pagine di 100 account. Nessuna credenziale, chiave, verifica email, contenuto vault o verificatore di autenticazione viene esposto. Non include cancellazione utenti o modifica dei ruoli.

Genera una chiave dedicata dal terminale:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-key
```

Inserisci admin_panel_key nel pannello. Non è la Master Password, non apre i vault ed è valida 24 ore. È una chiave riservata a chi amministra CasaOS, mai agli amici. Ogni generazione invalida la precedente. Il database conserva solo l'hash; il browser la tiene soltanto in memoria, senza cookie/localStorage e senza inserirla nell'URL. Il pannello si blocca dopo cinque minuti senza interazioni o quando lasci la pagina. La chiave è autorizzata solo finché l'account amministratore associato mantiene il ruolo admin. Il browser rifiuta l'invio tramite HTTP, eccetto localhost per sviluppo.

Per invalidarla immediatamente:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-revoke
```

## Icona e apertura dalla home CasaOS

Nelle impostazioni della scheda ByteLocker imposta l'interfaccia web su https://INDIRIZZO-TUNNEL/admin e l'icona su https://INDIRIZZO-TUNNEL/brand.png. L'app già avviata dal terminale non va installata una seconda volta. Se la tua versione di CasaOS non mostra questi campi, condividi la schermata delle sole impostazioni della scheda, senza segreti, per adattare il collegamento.

compose.casaos-panel.yaml fornisce gli stessi metadati per un'importazione CasaOS gestita: scheme https, hostname, port_map 443, index /admin e icon. Richiede BYTELOCKER_PUBLIC_HOST nell'ambiente di Compose o in .env, con il solo hostname attuale. Non pubblica porte e non avvia un altro servizio. Dopo un cambio del Quick Tunnel aggiorna anche il collegamento CasaOS e l'URL dell'icona. L'importazione deve adottare l'installazione esistente, non creare un backend duplicato sullo stesso volume. Le impostazioni effettive della scheda richiedono verifica sul CasaOS dell'utente.
