# Android: impostazioni, biometria e passkey

## Prova sul telefono

APK di sviluppo ARM64: `client/build/app/outputs/apk/debug/app-debug.apk`. Compilazione riuscita; non è una release distribuita o certificata. Il Galaxy A56 con Android 16 soddisfa il requisito di versione; disponibilità della biometria e protezione hardware vengono controllate sul dispositivo. Usare account e credenziali di prova.

1. Installa l'APK e collega un backend raggiungibile tramite HTTPS valido. `127.0.0.1` sul telefono indica il telefono, non il PC. Questo APK non abilita HTTP locale; il backend attuale ascolta solo sul PC. La connessione sicura dal telefono deve quindi essere predisposta prima della prova completa, senza aprire porte del router.
2. Accedi e apri l'ingranaggio. Tema: Scuro ByteLocker (predefinito), Chiaro o Segui il sistema. La scelta è ricordata su Android; su Windows resta in memoria.
3. Configura prima un'impronta nelle impostazioni Android. Nel vault attiva Sblocco biometrico e conferma il dialogo del sistema. Dopo il blocco scegli lo sblocco biometrico. Server ed email sono ricordati dopo un accesso riuscito su Android.
4. Da Gestore passkey Android abilita ByteLocker. Dal sito/app di prova avvia Crea passkey e scegli ByteLocker nel selettore Android. Accedi al vault richiesto, controlla sito/account e associa la passkey a una voce esistente oppure a una nuova. L'app restituisce il successo al sito solo dopo il salvataggio cifrato confermato.
5. Per usarla, avvia l'accesso con passkey dal sito/app, seleziona ByteLocker, sblocca e conferma la credenziale corrispondente. Se annulli, non viene restituita una firma.

Sono da verificare sul telefono: selettore Android e browser, creazione e successivo accesso a un servizio di prova, annullamento, ritorno dal background, cambio delle impronte e indisponibilità del backend. Nessuno di questi passaggi è dichiarato già collaudato su dispositivo reale. Il riconoscimento del viso è ammesso solo se Android lo classifica come biometria forte.

## Contenitore biometrico

Android 11+; Android Keystore AES-256-GCM con autenticazione biometrica forte per ogni uso, Cipher associato al BiometricPrompt e verifica della protezione hardware della chiave. Nessun ripiego su una chiave software o sul solo esito di una finestra grafica. Il cambio delle impronte invalida la chiave secondo la politica Keystore.

Il payload locale contiene K_vault, la credenziale di autenticazione già derivata A_password, descrittore e identità origin/server/account/vault/epoch/generazione. Non contiene Master Password o refresh token. Conservare A_password sigillata è una scelta esplicita: consente un nuovo login online dopo l'autorizzazione biometrica; un dispositivo compromesso che recuperasse il payload potrebbe autenticarsi e decifrare il vault. Il blob cifrato vive in noBackupFilesDir, con AAD per lo slot server/email, e non viene sincronizzato. Il backend non riceve questo contenitore.

Il client confronta identità e generazione con il server prima di accettare lo sblocco. Il passaggio in background blocca il vault, invalida le operazioni pendenti e tenta la revoca della sessione. Il solo stato inactive durante il dialogo biometrico è gestito come dialogo di sistema; hidden/paused bloccano comunque. Non è ancora disponibile una cache offline.

## Provider passkey

Android 14+, servizio protetto da BIND_CREDENTIAL_PROVIDER_SERVICE e attività interna non esportata. Ogni richiesta apre un contesto separato e richiede un accesso fresco e la scelta esplicita. Nessun indice dei siti o delle chiavi private viene scritto in chiaro per il selettore Android.

Profilo iniziale: ES256/P-256, attestazione none, credenziali discoverable sincronizzabili, contatore zero, flag UP/UV/BE/BS. Una passkey per voce, con chiave privata PKCS8 e pubblica SPKI cifrate nel record schema 3. I record precedenti restano leggibili; aggiornare tutti i client prima di usare schema 3. L'editor conserva la passkey durante le modifiche e permette la rimozione con conferma. Rimuoverla dal vault non la revoca sul sito; backup precedenti possono conservarla.

Browser: identità verificata tramite CallingAppInfo e allowlist firmatari/package; origine HTTPS e corrispondenza RP controllate, clientDataHash fornito dal sistema usato senza ricalcolo. App native: verifica HTTPS Digital Asset Links del relying party, relazione delegate_permission/common.get_login_creds, package e certificato APK. Questa verifica contatta il dominio del servizio; non è una richiesta di favicon. Niente redirect o indirizzi di rete privata. Richieste non supportate sono rifiutate: algoritmi diversi, attestazioni diverse, PRF/altre estensioni (eccetto credProps alla creazione), Related Origin Requests e selezioni con più opzioni get.

La lista browser è una copia statica della [lista Google](https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json), acquisita il 10 ottobre 2026, in android/app/src/main/assets/privileged_apps.json. SHA-256: 0891EE2507894999EAD3EB4F42E17936A2E8ED8F8FD95592535C9811EF319481. Nessun download a runtime; prima di una release controllare la fonte ufficiale, revisionare le variazioni e aggiornare hash e test. Non accettare allowlist arbitrariamente fornite dal richiedente.

Il provider Windows, Windows Hello e autofill password restano moduli separati. Nessuna certificazione FIDO o revisione crittografica indipendente è stata svolta.

## Verifiche eseguite

54 test Flutter superati, analisi senza segnalazioni; cinque test JVM superati su registrazione/firma ES256 verificata indipendentemente, clientDataHash browser, RP/credenziali/parametri non validi, origini ingannevoli e associazione Digital Asset Links. Prova Flutter/Go reale con SQLite temporaneo superata, includendo accesso con credenziale derivata dal contenitore simulato e sincronizzazione cifrata di passkey/TOTP. La biometria nei test Flutter è simulata: non verifica chip, impronta o dialoghi del Galaxy A56.

Riferimenti: [provider Android](https://developer.android.com/identity/sign-in/credential-provider), [biometria con CryptoObject](https://developer.android.com/identity/sign-in/biometric-auth), [WebAuthn](https://www.w3.org/TR/webauthn-3/).


## Aggiornamento Android 0.1.1

Il collegamento locale conserva solo origine HTTPS, server_id, email normalizzata, account_id e vault_id: JSON versionato con scrittura atomica in noBackupFilesDir/linked-account.json, nella directory privata dell'app. Non è un contenitore di segreti e non contiene password, chiavi o token. Al riavvio il client ricontrolla la discovery HTTPS e confronta server_id; un'identità diversa non viene accettata automaticamente. Errori di rete lasciano intatto il collegamento, con Riprova e Cambia server o account. Il login verifica anche account_id e vault_id prima di pubblicare il vault. La persistenza Windows resta da implementare.

La schermata dell'account ricordato mostra email non modificabile, Master Password e pulsante biometrico soltanto se risulta un'abilitazione locale. Il collegamento è salvato solo dopo login riuscito. Il Quick Tunnel può comunque cambiare URL: in quel caso occorre aggiornarlo tramite Cambia server o account e riabilitare l'impronta per la nuova origine.

Corretto l'ordine delle operazioni Keystore: updateAAD viene eseguito sul Cipher restituito dal prompt, dopo l'autorizzazione, prima di doFinal. La chiave resta vincolata a biometria forte per uso. La conferma di attivazione ricontrolla che il contenitore sia stato salvato; cancellazione e invalidazione hanno messaggi distinti. La prova fisica dell'impronta sul Galaxy A56 resta necessaria.

Cinque nuovi test coprono metadati senza segreti, riapertura con sola password e rilevamento biometria, rifiuto del cambio identità server, rete assente con retry e abilitazione/sblocco biometrico simulato dopo ricreazione della schermata. Totale: 54 test client passati; prova Go opzionale esclusa da questo conteggio. Il backend non richiede modifiche per questo aggiornamento.


## Aggiornamento 0.2.0

Il logo fornito sostituisce le icone native e appare nelle schermate del client. Il blocco del vault avviene dopo cinque minuti consecutivi in background; rientrare prima annulla il timer, mentre chiusura e blocco manuale sono immediati. La scadenza viene verificata nuovamente al rientro, anche se Android ha sospeso i timer. Gli editor vengono svuotati alla scadenza. Impronta e riapertura sul Galaxy A56 sono state confermate dall'utente per la versione precedente. La prova fisica del nuovo intervallo resta da effettuare. Windows ora conserva il collegamento al server e all'account; Windows Hello resta escluso.

