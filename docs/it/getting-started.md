# Primo utilizzo di ByteLocker

## Se sei stato invitato a un server

1. Installa il client per il tuo dispositivo: APK ARM64 su Android o ZIP completo su Windows. Su Windows estrai la cartella intera prima di avviare l'app.
2. Chiedi al gestore **in privato** l'indirizzo HTTPS del server e il tuo codice d'invito. Questi dati non sono presenti nell'app scaricata.
3. Inserisci solo l'origine HTTPS, per esempio `https://vault.example.com`, senza /admin o /api/v1/config, e premi Controlla server.
4. Scegli Crea un account. Usa la stessa email a cui è vincolato l'invito, il codice d'invito e una Master Password personale.
5. Conferma le otto cifre ricevute via email e accedi con la Master Password. Il codice email non viene chiesto a ogni sblocco.
6. Crea una credenziale di prova, chiudi e riapri l'app e verifica che venga richiesto lo sblocco del tuo account ricordato.

La Master Password non viene inviata al gestore del server. Non condividerla con altri. Il recupero della Master Password non è ancora disponibile: sceglila e custodiscila con attenzione.

Ogni utente vede il proprio vault. La chiave amministratore non va inviata agli amici e non è il codice d'invito.

## Cosa puoi fare nel vault

- Tocca una voce per leggere i dettagli; la matita apre la modifica.
- Usa Copia accanto a username, email, password, URL o codice 2FA. La password resta nascosta finché non premi l'occhio.
- Crea categorie come Personale o Lavoro e assegna i login dall'editor. Le stelle aggiungono i preferiti.
- Su Windows usa la barra laterale; su Android apri il menu in alto a sinistra per categorie, preferiti e tag.
- Il logo si riconosce dal sito/nome. Puoi sceglierlo manualmente dall'editor se il risultato automatico non è adatto.

Per il 2FA inserisci nel campo Segreto 2FA la chiave Base32 o il link otpauth del servizio, non il codice a sei cifre. È supportato il profilo TOTP SHA-1, sei cifre e trenta secondi. Mantieni data e ora automatiche.

## Android: impronta e passkey

Dopo il login, apri Impostazioni per attivare la biometria se disponibile. L'abilitazione richiede un'autenticazione di sistema; l'impronta non sostituisce la scelta iniziale della Master Password.

Le passkey dei siti sono una funzione delle singole credenziali. Abilita ByteLocker come provider nelle impostazioni Android e avvia la creazione dal sito/app compatibile. La passkey viene restituita al sito solo dopo un salvataggio cifrato confermato. Vedi [supporto e limiti Android](../android-security.md).

## Se il server cambia indirizzo

Il gestore deve comunicare privatamente il nuovo URL. Dalla schermata di connessione scegli Cambia server o account e aggiorna l'indirizzo. Usa il tuo account esistente: non crearne un altro. Il client confronta l'identità server e dell'account prima di accettare il collegamento. Può essere necessario riabilitare la biometria per la nuova origine.

Un Quick Tunnel cambia nome quando viene ricreato e non garantisce disponibilità. Questa modalità è per le prove; l'indirizzo configurato deve essere raggiungibile perché il vault non ha ancora una cache offline.

## Prima di coinvolgere gli amici

Il gestore aggiorna il server a 0.2.3 e distribuisce client 0.3.1. Per ciascun amico genera un invito con ruolo utente, vincolato alla sua email, dal pannello amministratore. L'invito viene condiviso privatamente; il pannello non invia automaticamente l'email di invito. La verifica email parte quando la persona si registra.

Fate una prova con credenziali inventate, verificando isolamento tra account, riapertura, copia, biometria e salvataggio da due dispositivi dello stesso utente. Il gestore deve verificare un backup e un ripristino separato sul proprio server prima di affidargli dati importanti.

La repository e i download della beta sono pubblici. Questo non concede accesso al server del gestore: ogni utente deve ricevere un invito personale. Chi desidera un'istanza propria segue [self-hosting](self-hosting.md).
