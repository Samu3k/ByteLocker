# Contribuire a ByteLocker

La repository è inizialmente privata. Prima della pubblicazione aperta saranno definite licenza e modalità di contribuzione; l'accesso al codice non implica automaticamente un'autorizzazione al suo riutilizzo.

## Ambiente

Go 1.27.1, Flutter 3.47.7 stable/Dart 3.13.5, Node per gli strumenti. Per Windows serve Visual Studio con sviluppo desktop C++; per Android servono JDK e Android SDK compatibili. Mantieni go.sum e pubspec.lock.

```sh
git config core.hooksPath .githooks
node --test scripts/check-publication.test.cjs
node scripts/check-publication.cjs --staged
```

Lavora in un branch, descrivi il problema e verifica il comportamento finale. Non modificare migrazioni SQLite già distribuite: aggiungine una nuova quando necessario. Le estensioni dei payload cifrati devono specificare compatibilità e aggiornamento di tutti i client.

## Verifica

Da backend:

```sh
go test -buildvcs=false ./...
node maintenance-tests/backup-wrapper.cjs
```

Da client:

```sh
flutter pub get
flutter analyze
flutter test --concurrency=1
```

Per il test Flutter/Go opzionale vedi client/README.md. Test e screenshot devono usare dati sintetici. Non far dipendere la suite dal server dell'operatore, da Gmail reale o da file del proprio PC.

## Pull request

Spiega cosa cambia per l'utente, come è stato verificato e quali limiti restano. Per modifiche a crittografia, autenticazione, persistenza o provider passkey includi casi di errore, isolamento e compatibilità. Per modifiche all'interfaccia verifica sia una finestra ampia sia un telefono con caratteri grandi.

Non aggiungere .env, data, secrets, keystore, backup, pacchetti compilati, credenziali CI o indirizzi privati. Il controllo di pubblicazione è aggiuntivo: rivedi comunque ogni file prima del commit. Le vulnerabilità seguono SECURITY.md.
