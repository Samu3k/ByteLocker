# Pubblicazione: sorgenti, pacchetti e dati privati

## Il confine da rispettare

La repository e i pacchetti contengono l'applicazione riutilizzabile. Una singola installazione contiene invece URL configurato, account, sessioni, database, chiavi operative e credenziali email. Questi dati non devono essere trasferiti nella repository, nemmeno quando è privata.

I percorsi API come /api/v1/config, /auth/login o /vault/sync sono parte del protocollo e devono essere conosciuti dal client. Non sono credenziali. Un URL configurato dall'utente è necessariamente visibile sul suo dispositivo e nelle richieste che effettua: la protezione del server dipende da HTTPS, autenticazione, autorizzazioni e inviti, non dalla sola segretezza del nome.

## Controlli predisposti

- Copia sorgenti in una repository dedicata, con nuova cronologia: nessun caricamento della cartella personale o dei vecchi pacchetti.
- .gitignore esclude dati, segreti, backup, keystore, .env, profili locali, build, cartelle effimere e pacchetti compilati.
- `scripts/check-publication.cjs` controlla i file realmente presenti nell'indice Git. Rifiuta file privati/generati, URL Quick Tunnel personali, percorsi del PC, chiavi private PEM e alcuni formati di token noti. Non stampa i valori trovati.
- L'opzione `--staged` legge il contenuto effettivamente aggiunto all'indice, anche se la copia sul disco è diversa. Il controllo è usato da un hook locale e da GitHub Actions.
- Un test Flutter verifica che una nuova installazione mostri il campo server vuoto e non effettui richieste di discovery prima della scelta dell'utente.
- I pacchetti vengono caricati come asset di release separati, dopo verifica dei contenuti e delle impronte. Non si allegano cartelle dati, backup o profili utente.

Il controllo personalizzato è una protezione aggiuntiva e non riconosce qualsiasi segreto possibile. Prima di pubblicare nuove configurazioni o nuove integrazioni va comunque revisionato il contenuto. Se un segreto è stato caricato, cancellarlo dall'ultima versione non basta: va revocato/sostituito e va controllata la cronologia interessata. [Indicazioni GitHub](https://docs.github.com/en/code-security/concepts/secret-security/secret-leakage-risks)

## Configurazioni escluse

| Dato | Dove resta |
| --- | --- |
| URL/email/identità dell'account ricordato | Profilo privato del client sul singolo dispositivo |
| Master Password e chiavi sbloccate | Memoria del client; contenitore biometrico opzionale Android |
| Database SQLite e chiavi operative | data sul server |
| Mittente email e percorsi privati | .env sul server |
| Password applicativa Gmail | secrets sul server |
| Chiavi di firma Android | Archivio privato dell'operatore/build, fuori da Git |
| Token GitHub | Git Credential Manager o sistema segreti CI, fuori dai file del progetto |
| Backup | Directory privata esterna al progetto e supporto separato |

I certificati/fingerprint pubblici dei browser in privileged_apps.json servono a verificare il chiamante del provider passkey; non sono chiavi private. I vettori in client/test/fixtures contengono materiale sintetico per i test, non account dell'operatore.

## Prima di ogni commit e rilascio

Dalla radice della repository, con Node e Git:

```sh
git config core.hooksPath .githooks
git add <file-revisionati>
node --test scripts/check-publication.test.cjs
node scripts/check-publication.cjs --staged
git diff --cached --stat
```

Non usare git add sull'intera cartella personale. Il controllo si applica alla repository del progetto e non cancella file privati dal PC. I pacchetti di release sono distribuiti separatamente e restano esclusi dall'indice.

Prima di rendere la repository pubblica: controlla anche vecchi commit, issue, schermate, log Actions e asset delle release; scegli una licenza, configura la firma pubblica e completa le verifiche di sicurezza/dispositivo previste dalla roadmap. Cambiare visibilità non deve essere usato per ospitare il server personale.
