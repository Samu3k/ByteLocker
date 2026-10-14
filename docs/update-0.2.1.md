# ByteLocker 0.2.1: trasparenza e dettagli delle credenziali

## Cosa cambia

Il logo originale ha già uno sfondo trasparente. La conversione precedente aveva aggiunto un riempimento nero: ora tutte le immagini e le icone mantengono il canale trasparente, senza ridisegnare il logo. Sono aggiornati Android, Windows e il logo del pannello server e della scheda CasaOS. Il launcher Android può applicare il proprio sfondo o la propria maschera alle icone adattive.

Nei client, un clic sulla credenziale apre i dettagli in sola lettura. Username, email, URL, note e tag sono consultabili; la password resta mascherata e si mostra con il pulsante dell'occhio. I codici TOTP sono visibili senza mostrare il segreto; per le passkey vengono mostrati sito e utente. La matita nella lista o nei dettagli apre la modifica. Il pulsante Torna al vault riporta alla lista. Aprire i dettagli non salva né modifica la credenziale.

Resta il blocco dopo cinque minuti consecutivi fuori dall'app introdotto nella 0.2.0. Windows Hello non è incluso.

## Android

Installa ByteLocker-0.2.1-android-arm64.apk come aggiornamento senza disinstallare ByteLocker. Conserva così il profilo locale e le impostazioni biometriche. Questa è una build debug per la prova privata sul telefono ARM64. Non è una release per Play Store.

## Windows

Chiudi ByteLocker, estrai completamente ByteLocker-Windows-0.2.1.zip in una nuova cartella e avvia ByteLocker.exe al suo interno. Non spostare soltanto il file exe: servono anche le librerie e la cartella data distribuite nello ZIP. Il profilo personale rimane nella posizione già usata dall'app.

## CasaOS

Il pacchetto bytelocker-casaos-0.2.1.zip contiene i sorgenti aggiornati e la documentazione, senza dati o segreti personali. La versione dello schema rimane 9, come nella 0.2.0. Se il server è precedente alla 0.2.0, viene applicata anche la migrazione del pannello amministratore.

Segui [la procedura completa di backup e aggiornamento](update-0.2.0.md), utilizzando il pacchetto 0.2.1 al posto di quello 0.2.0 e chiamando il backup pre-0.2.1. Conserva sempre data, secrets e .env. La nuova immagine Docker deve essere compilata e il container ricreato: copiare il PNG da solo non aggiorna il logo incorporato nel server.

La ricreazione del Quick Tunnel può cambiare l'indirizzo HTTPS: aggiorna in quel caso i client e il collegamento CasaOS. L'icona della scheda usa https://INDIRIZZO-TUNNEL/brand.png; il pannello usa https://INDIRIZZO-TUNNEL/admin. Se CasaOS mostra ancora il vecchio logo, aggiorna la pagina e reimposta l'URL dell'icona aggiungendo ?v=021 per rinnovare la cache.

## Verifica sul dispositivo

Apri una credenziale: devono apparire i dettagli senza campi modificabili e senza Salva. Mostra e nascondi la password, poi usa la matita e verifica che si apra l'editor. Torna alla lista senza salvare: i dati devono rimanere invariati. Verifica il logo su uno sfondo chiaro e uno scuro. Queste prove sui dispositivi e su CasaOS completano i controlli automatici eseguiti durante lo sviluppo.
