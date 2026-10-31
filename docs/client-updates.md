# Maintaining signed client updates

The app pins an Ed25519 public key. The corresponding private key belongs outside the repository and release assets. HTTPS alone, GitHub checksums alone, and a public server address are not update authorization.

## Release process

1. Increment pubspec.yaml and the compiled version/build constants in client/lib/updates/update_manifest.dart.
2. Run Flutter tests and the updater Go tests. Build Android and Windows releases. Compile the Windows helper from client/windows/updater with Go and include ByteLockerUpdater.exe beside ByteLocker.exe.
3. Add .bytelocker-install.json to the dedicated Windows package folder. It contains schema 1, app ByteLocker, and a files array listing every packaged relative file path, including the inventory itself. Do not add profiles, exports or user data to the package.
4. Create the ZIP / signed APK and run privacy, signature, version and startup checks. Preserve third-party licenses. Verify Android certificate continuity.
5. Set BYTELOCKER_UPDATE_SIGNING_KEY to the private PEM path and BYTELOCKER_PYTHON to Python 3 if needed. From the repository root, with Node and Python installed:

```sh
node scripts/sign-update.cjs /private/builds/ByteLocker-Windows-VERSION.zip VERSION BUILD windows-x64 updates/windows-x64.json
node scripts/sign-update.cjs /private/builds/ByteLocker-VERSION-android-arm64.apk VERSION BUILD android-arm64 updates/android-arm64.json
```

Replace VERSION and BUILD with the actual version and increasing build number. The signer verifies that the private key matches the pinned public key. It computes the archive hash, each Windows file hash, the package size and an expiry (180 days), then signs the exact metadata bytes. Keep a protected backup of the private key; losing it requires a manually installed trust-key migration.

6. Prepare a draft GitHub release with the matching version tag and unchanged artifact names. Upload and verify the exact artifacts that were signed. Push the reviewed source and signed metadata, let CI pass, and publish the release. Do not announce metadata for a package that is still unavailable longer than the release preparation requires; incomplete downloads fail closed and can be retried after publication.

Never replace a published package with different bytes under the same version. Issue a higher build/version and new signed metadata. If no release is made before metadata expires, regenerate the signed metadata with the existing reviewed artifacts. No private signing keys are configured in GitHub Actions.

## Windows installation boundaries

The helper verifies the signature again, rejects old builds and expired metadata, checks the ZIP and per-file hashes, rejects path traversal, duplicate paths, symlinks/reparse points, reserved Windows names, unexpected files and excessive sizes. It audits the current folder against its inventory, prepares a sibling directory, validates and waits for the exact parent application process, then swaps folders and restarts the app. An immediate launch failure triggers rollback. The old application folder is retained; user profiles, registry data and server vaults are not replaced.

Updates require an ordinary writable, dedicated app directory. The helper does not elevate privileges or kill unrelated app instances. Installation can fail when another instance or security software holds files open; the manual package remains available. No mechanism can guarantee recovery from arbitrary hardware failure or every later application crash.

## Android boundaries

The APK is checked against signed metadata before requesting installation. Native code also checks app ID, increasing versionCode and the installed signing certificate. The system performs final package verification and asks for permission/confirmation. This sideload updater is for the GitHub APK; a future Play Store distribution needs a separate update/signing policy.

These checks are tested engineering controls, not an independent updater or cryptographic security audit.
