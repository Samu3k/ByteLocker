# ByteLocker clients

**0.3.1+7** · Flutter **3.47.7** · Dart **3.13.5**

[Overview](../README.md) · [User guide](../docs/getting-started.md) · [Contributing](../.github/CONTRIBUTING.md)

Android and Windows share an encrypted online vault, categories, favorites, tags, local brand icons and TOTP copying. Android adds themes, optional biometrics and a passkey provider on compatible devices.

No server or account is preconfigured. The remembered connection stores only the HTTPS origin, account/server/vault identity and email in the local user profile. Unlocked passwords, keys and sessions stay in memory, except for the optional Android biometric container protected by Keystore.

## Develop

From this directory, with Flutter on PATH:

```sh
flutter pub get
flutter analyze
flutter test --concurrency=1
flutter run -d windows
```

Windows requires Visual Studio desktop C++ tools and the Windows SDK. Android requires a compatible JDK and Android SDK. Check `flutter doctor -v`; keep generated platform files and local.properties out of Git.

## Build

```sh
flutter build windows --release
flutter build apk --release --target-platform android-arm64
```

**Windows:** distribute the entire build/windows/x64/runner/Release directory, including assets, DLLs and required Visual C++ runtime dependencies.

**Android:** release builds do not automatically use a debug signing key. Configure signing separately and verify the certificate. Updates must keep the application ID and certificate, with an increasing versionCode. The private-preview APK was explicitly signed with the previous test key to allow upgrades; that key is excluded from Git. Public / Play Store distribution needs dedicated production signing.

Build distribution packages in a clean environment. Never embed private server settings, tokens or signing keys in assets or dart-define values.

## Local development server

HTTP is available only through a debug opt-in:

```sh
flutter run -d windows --dart-define=PM_ALLOW_LOCAL_HTTP=true
```

Use http://127.0.0.1:8080 on the desktop or http://10.0.2.2:8080 in the Android emulator. Profile and release builds ignore this flag and require HTTPS.

## Optional Flutter / Go test

This test uses temporary SQLite data and simulated email, without contacting a real instance. From backend in PowerShell:

```powershell
$env:BYTELOCKER_FLUTTER_PATH = (Get-Command flutter).Source
$env:BYTELOCKER_CLIENT_DIR = (Resolve-Path '../client').Path
go test -buildvcs=false ./internal/httpapi -run '^TestFlutterClientInterop$' -count=1 -v
Remove-Item Env:BYTELOCKER_FLUTTER_PATH
Remove-Item Env:BYTELOCKER_CLIENT_DIR
```

Without these variables, the ordinary suite skips the optional test. Windows-specific channel tests are skipped on other platforms.

## Compatibility

- Encrypted schema 4 requires clients 0.3.0 or newer on every device. The repeated-login session-limit fix also requires server 0.2.3.
- Network access is required. Offline cache/sync and client token renewal are not implemented; expired sessions may require signing in again.
- Pending drafts remain in memory. Avoid closing the app during an unconfirmed write.
- Windows Hello, Windows passkey provider, TOTP QR scanning and a web vault are not included.
- Android passkey support needs testing on real sites/devices. Clipboard clearing is best effort and may be limited by the OS.

## Brand assets

Local icons come from Simple Icons and Dashboard Icons. Revisions, hashes and licenses are in third_party. The generator is tool/build_brand_catalog.cjs; manual matching overrides are in tool/brand-overrides.json. No external favicon service receives saved website names. Logos are decorative and do not certify a website or imply affiliation.
