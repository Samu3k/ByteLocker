# ByteLocker — client Android e Windows

Versione **0.3.1+7**, Flutter **3.47.7 stable**, Dart **3.13.5**. Dipendenze fissate in pubspec.lock. [Panoramica](../README.md) · [Primo utilizzo](../docs/getting-started.md) · [Sicurezza Android](../docs/android-security.md)

## Funzioni

Collegamento a un server HTTPS scelto dall'utente, registrazione tramite invito e codice email, login con Master Password, vault online cifrato, ricerca, credenziali in sola lettura, modifica con matita, categorie, preferiti e tag. Catalogo locale di 3.365 loghi, con selezione manuale. Codici TOTP SHA-1 a 6 cifre/30 secondi e pulsanti di copia; Android aggiunge temi, biometria e provider passkey sui dispositivi compatibili.

Nessun server personale o account è incorporato. Il collegamento salvato dopo il login contiene soltanto origine HTTPS, identità server/account/vault ed email; rimane nel profilo locale. Password, chiavi e sessioni sbloccate restano in memoria, salvo il contenitore biometrico Android opzionale protetto dal Keystore.

![Vault Windows con dati sintetici](../docs/images/031-vault-desktop.png)

## Verifica e avvio

Con Flutter nel PATH, dalla cartella client:

```sh
flutter pub get
flutter analyze
flutter test --concurrency=1
flutter run -d windows
```

Per una build Windows servono Visual Studio con sviluppo desktop C++ e il relativo SDK Windows. Per Android servono Android SDK e JDK compatibili con il progetto Gradle; esegui `flutter doctor -v` per verificare l'ambiente. Flutter genera local.properties e i file effimeri della piattaforma: non pubblicarli.

## Build Windows

```sh
flutter build windows --release
```

Distribuisci **tutta** `build/windows/x64/runner/Release`, comprese DLL, asset e dipendenze runtime Visual C++ necessarie. L'eseguibile da solo non basta. Il collegamento utente è nel profilo Windows, fuori dal pacchetto.

## Build Android

```sh
flutter build apk --debug --target-platform android-arm64
flutter build apk --release --target-platform android-arm64
```

La release non applica una firma debug automatica: firma l'APK con uno strumento/configurazione appropriato e verifica il certificato prima di distribuirlo. Per aggiornare una build già installata, applicationId e certificato devono corrispondere e versionCode deve aumentare. La 0.3.1 distribuita per la prova privata è stata firmata esplicitamente con la stessa chiave delle versioni precedenti; quella chiave non fa parte del repository. La firma pubblica/Play Store richiede una chiave dedicata e una procedura separata.

Le build pubbliche devono essere prodotte in un ambiente pulito. Non aggiungere configurazioni di server personali, file .env, keystore o token come asset o dart-define.

## Server locale per sviluppo

Solo in debug è disponibile l'opt-in HTTP locale:

```sh
flutter run -d windows --dart-define=PM_ALLOW_LOCAL_HTTP=true
```

Usa `http://127.0.0.1:8080` sul PC o `http://10.0.2.2:8080` nell'emulatore Android. Il flag viene ignorato in profile/release; le distribuzioni richiedono HTTPS. Non è una configurazione del server personale e non viene abilitata nei pacchetti consegnati.

## Prova con backend Go reale

Il test usa SQLite temporaneo e consegna email simulata. Nessuna email reale viene inviata e il server personale non viene usato. Imposta percorsi assoluti del tuo SDK e del client; da backend, su PowerShell:

```powershell
$env:BYTELOCKER_FLUTTER_PATH = (Get-Command flutter).Source
$env:BYTELOCKER_CLIENT_DIR = (Resolve-Path '../client').Path
go test -buildvcs=false ./internal/httpapi -run '^TestFlutterClientInterop$' -count=1 -v
Remove-Item Env:BYTELOCKER_FLUTTER_PATH
Remove-Item Env:BYTELOCKER_CLIENT_DIR
```

La suite ordinaria salta questa prova senza le due variabili. I test specifici del canale Windows sono saltati sugli altri sistemi.

## Compatibilità e limiti attuali

- Categorie, preferiti e loghi manuali usano schema cifrato 4: tutti i client dello stesso account devono essere almeno 0.3.0.
- Il blocco dopo molte riaperture/sessioni richiede anche server 0.2.3: il solo client non corregge il controllo del vecchio server.
- Il vault richiede rete. Sono ancora da implementare cache cifrata, sincronizzazione offline e rinnovo client degli access token; dopo la scadenza può essere richiesto un nuovo accesso.
- Le bozze e le scritture non confermate restano in memoria. Non chiudere l'app durante un tentativo pendente che vuoi riprendere.
- Windows Hello, provider passkey Windows, scansione QR TOTP e vault web non sono inclusi.
- Il provider passkey Android verifica il chiamante e il relying party; il profilo iniziale non supporta ogni estensione WebAuthn. La compatibilità fisica va verificata sui siti/dispositivi usati.
- Gli appunti sono marcati sensibili e vengono puliti best effort; il sistema operativo può limitare la pulizia in background.

## Loghi e attribuzioni

Asset locali da [Simple Icons 16.0.0](https://github.com/simple-icons/simple-icons/tree/16.0.0) e [Dashboard Icons](https://github.com/homarr-labs/dashboard-icons), con revisioni, hash e licenze in third_party. Il generatore è `tool/build_brand_catalog.cjs`; le correzioni di nomi/domìni sono in `tool/brand-overrides.json`. Nessuna richiesta a servizi esterni di favicon rivela i siti salvati.

I loghi sono decorativi: non certificano l'autenticità del sito o l'affiliazione di ByteLocker ai titolari dei marchi.
