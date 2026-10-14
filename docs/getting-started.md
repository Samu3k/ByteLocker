# Get started

[Italiano](it/getting-started.md) · [Downloads](https://github.com/Samu3k/ByteLocker/releases/tag/v0.3.1)

## Join a friend's server

1. Install the Android ARM64 APK or extract the entire Windows ZIP.
2. Ask the server owner privately for its HTTPS address and your invitation.
3. Enter the server origin, such as `https://vault.example.com`, without /admin or /api/v1/config.
4. Create an account using the invited email, invitation code and your own Master Password.
5. Confirm the eight-digit email code. Later unlocks use your Master Password or enabled Android biometrics.
6. Save a test entry, reopen the app and check that your remembered account unlocks correctly.

Never share your Master Password. Password recovery is not available yet. Each person has a separate vault; the admin-panel key is not a user invitation.

## Everyday use

- Open an entry to view it; use the pencil to edit.
- Copy usernames, emails, passwords, URLs or current 2FA codes. Use the eye to reveal a password.
- Organize entries with categories, favorites and tags: sidebar on Windows, navigation menu on Android.
- Choose a logo manually if the automatic match is unsuitable.
- For 2FA, enter the service's Base32 secret or otpauth URL, not its six-digit code. Supported TOTP: SHA-1, six digits, 30 seconds. Keep your clock automatic.

On Android, enable biometrics in Settings after signing in. Website passkeys belong to individual credentials: enable ByteLocker as an Android provider and start creation from a compatible site/app. Compatibility is still being tested; see the [Android notes](android-security.md) (Italian).

## If the server address changes

Use Change server or account and enter the new address supplied by the owner. Sign in to your existing account rather than creating another. The client checks server/account identity; biometrics may need enabling again for the new origin.

Quick Tunnel addresses can change after recreation. An online server is required; there is no offline vault cache yet.

## For server owners

Use server 0.2.3 and clients 0.3.1. Create a separate email-bound user invitation for each friend in the admin panel. Share the invitation privately: invitation delivery is manual, while registration verification is sent by email.

Start with synthetic credentials and verify account isolation, reopening, copying and biometrics. Test a backup and restore before relying on the server. Friends can receive the client packages directly without GitHub access. [Host your own server →](self-hosting.md)
