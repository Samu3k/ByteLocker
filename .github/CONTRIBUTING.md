# Contributing

The repository is private while distribution is prepared. A code license has not yet been selected; access alone does not grant reuse rights.

## Set up

Use Go 1.27.1, Flutter 3.47.7 / Dart 3.13.5 and Node. Android needs a compatible JDK and SDK; Windows needs Visual Studio desktop C++ tools. Keep the dependency lockfiles.

```sh
git config core.hooksPath .github/hooks
node --test scripts/check-publication.test.cjs
node scripts/check-publication.cjs --staged
```

## Verify changes

From backend:

```sh
go test -buildvcs=false ./...
node maintenance-tests/backup-wrapper.cjs
```

From client:

```sh
flutter pub get
flutter analyze
flutter test --concurrency=1
```

Use synthetic fixtures, never the operator's live server or email. See the [client guide](../client/README.md) for builds and optional Flutter/Go interoperability tests.

## Submit

Work on a branch. Explain the user-visible change, validation and remaining limitations. Keep deployed SQLite migrations immutable; document compatibility when changing encrypted payloads. Cover failures and isolation for authentication or cryptography changes, and check both desktop and phone layouts for UI changes.

Do not commit .env, data, secrets, signing keys, backups, build packages or private URLs. Review staged files even when the publication guard passes. Report vulnerabilities through [Security](SECURITY.md).
