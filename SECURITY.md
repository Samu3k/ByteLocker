# Sicurezza di ByteLocker

ByteLocker è in sviluppo e non ha ancora una revisione crittografica indipendente. La versione corrente è destinata alle prove private; protocollo e limiti sono documentati in docs/crypto-protocol.md, docs/threat-model.md e docs/android-security.md.

## Segnalare un problema

Non pubblicare una vulnerabilità con dettagli sfruttabili in una issue aperta. Contatta privatamente il proprietario della repository tramite un canale già concordato; usa il reporting privato GitHub se viene abilitato. Non è ancora dichiarato un programma bug bounty o un tempo garantito di risposta.

Descrivi versione, piattaforma, passaggi riproducibili con dati sintetici e impatto osservato. Non inviare password, chiavi, token, inviti, vault, backup, database o credenziali Gmail. Oscura indirizzi personali, email, identificativi e metadati non necessari nelle schermate.

## Gestione di un segreto esposto

Revoca e sostituisci la credenziale coinvolta. La rimozione dal codice corrente non la elimina dalla cronologia, dai fork o dai pacchetti già scaricati. Valuta separatamente le sessioni, gli inviti e le chiavi operative interessati; non eliminare account o vault senza una procedura di recupero verificata.

## Confini attuali

Il gestore possiede database e metadati degli account, ma non riceve Master Password o chiave del vault. La compromissione di un client sbloccato può esporre i suoi contenuti. Il protocollo personalizzato richiede revisione indipendente; l'esistenza dei test non sostituisce tale revisione.

Un indirizzo server tenuto privato è comunque raggiungibile quando esposto tramite tunnel. Gli inviti regolano la registrazione; non sostituiscono autenticazione e autorizzazioni delle API. I backup contengono segreti operativi e devono restare protetti.
