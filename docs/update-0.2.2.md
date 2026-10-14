# ByteLocker server 0.2.2: gestione utenti dal pannello

Questo aggiornamento riguarda soltanto il server CasaOS. I client Android e Windows 0.2.1 restano compatibili. Non cambia lo schema del database, che resta alla versione 9.

## Funzioni del pannello

- Aggiungi un utente: inserisci l'email, scegli 24 ore, 3 giorni o 7 giorni e premi Genera invito. L'invito assegna soltanto il ruolo utente ed è utilizzabile una volta, esclusivamente per l'email indicata.
- Copia codice: condividi privatamente il codice e l'indirizzo HTTPS del server con il destinatario. Il codice viene mostrato soltanto alla creazione, non può essere recuperato ed è cancellato dalla pagina all'uscita. Non viene inviata un'email d'invito automatica. La verifica email durante la registrazione continua a usare Gmail.
- Elimina: riscrivi l'email e premi Elimina definitivamente. Gli account amministratore non possono essere eliminati, nemmeno tramite API. L'operazione rimuove l'account, le sessioni, i token di rinnovo e il vault cifrato, oltre ai tentativi di registrazione e agli inviti ancora attivi per quell'email. Non cancella dati già scaricati dai dispositivi, copie nei backup o residui fisici del database. Non è una cancellazione remota dei dispositivi.

Il destinatario crea personalmente il proprio account dall'app e sceglie la Master Password. Il pannello non crea password e non legge i vault.

La chiave amministratore dedicata ora autorizza anche queste modifiche. Rimane valida 24 ore, revocabile con panel-revoke e sostituibile con panel-key. La pagina si blocca dopo cinque minuti senza interazioni. I comandi di invito non servono più, ma la generazione di una nuova chiave amministratore alla scadenza richiede ancora il terminale CasaOS.

## Aggiornamento da 0.2.1

1. Estrai bytelocker-casaos-0.2.2.zip e copia il contenuto in /DATA/AppData/bytelocker, sostituendo i sorgenti. Conserva data, secrets e .env.
2. Compila la nuova immagine:

```sh
cd /DATA/AppData/bytelocker
sudo docker compose build bytelocker
```

3. Arresta il servizio e crea un backup coerente. L'accesso degli amici viene temporaneamente interrotto:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml stop cloudflared bytelocker
sudo install -d -m 0700 /DATA/AppData/bytelocker-backups
sudo sh -c 'umask 077; tar -czf /DATA/AppData/bytelocker-backups/pre-0.2.2-$(date +%Y%m%d-%H%M%S).tar.gz -C /DATA/AppData/bytelocker data secrets .env'
```

4. Soltanto se il backup termina senza errori, avvia la nuova versione:

```sh
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml up -d --force-recreate bytelocker cloudflared
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml ps
sudo docker compose -f compose.yaml -f compose.gmail.yaml -f compose.quick-tunnel.yaml logs --tail=100 cloudflared
```

5. Il Quick Tunnel può ricevere un nuovo indirizzo. Usa quello indicato nei log nei client e nei collegamenti CasaOS. Apri https://NUOVO-INDIRIZZO/admin, aggiorna la pagina e genera una nuova chiave dedicata:

```sh
sudo docker compose exec bytelocker /usr/local/bin/bytelocker-admin -data-dir /data panel-key
```

Inserisci admin_panel_key nel pannello, senza condividerla con gli amici. Verifica l'invito con un account di prova. Per verificare Elimina usa esclusivamente un account di prova che puoi cancellare.

## Verifiche per sviluppatori

I test Go coprono autorizzazione, chiavi scadute/revocate e amministratore disabilitato, conferma email, protezione amministratori, inviti vincolati all'email, rimozione delle sessioni e del vault, invalidazione degli inviti preesistenti e rollback in caso di errore. I test HTTP includono registrazione tramite invito generato dal pannello, cancellazione, richieste ambigue e origine estranea.

Il test browser backend/panel-tests/admin-panel.cjs usa solo un server locale simulato con utenti fittizi. Richiede Node e Playwright con Chromium disponibile; BYTELOCKER_BROWSER permette di indicare un browser compatibile già installato. BYTELOCKER_PREVIEW_DIR abilita screenshot in una cartella esistente. Eseguirlo dalla radice del progetto con node backend/panel-tests/admin-panel.cjs. Nessun test usa account o email reali.
