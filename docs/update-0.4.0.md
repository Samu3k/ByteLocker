# ByteLocker 0.4.0 — File menu and updates

Client 0.4.0+9. **CasaOS server 0.2.3 is unchanged; no server update is required.**

## First installation of the updater

Install 0.4.0 manually once: version 0.3.2 does not contain an update checker. Close Windows before extracting the whole new ZIP into its own writable folder. On Android, install the APK over the existing app without uninstalling it.

From 0.4.0 onward, the app checks signed update metadata at startup. You can also use **Settings → Check for updates**. An available update appears at the top right:

- **Windows:** download, signature/hash verification, lock, installation and restart after your click. Unsaved edits, open vault dialogs, imports and pending encrypted writes block restart. The updater checks the current process and app folder and keeps the previous application folder for recovery. The remembered account/settings remain in the user's profile; vault data stays on the server.
- **Android:** download and verification, then the system installation screen. Android may ask you to allow updates from ByteLocker. Confirm the installation and reopen the app; silent installation/restart is not promised. The package must have the same app ID and signing certificate and a higher build number.

Keep the Windows app in a dedicated directory. Extra personal files, filesystem links or a non-writable installation can prevent automatic installation; use the manual ZIP in that case. Do not store CSV password exports inside the application directory.

## Import from Bitwarden CSV

1. Unlock your vault and finish any pending save.
2. Open **File → Import from Bitwarden** and choose the UTF-8 CSV export.
3. Review counts of importable, duplicate, invalid and unsupported rows.
4. Confirm the import. Confirmed entries remain saved if a later row fails; resolve any pending encrypted write and reread the CSV to skip exact duplicates.

The file is read locally; credentials are encrypted before upload to your own server. Existing entries are never overwritten. Folders become categories; favorites, usernames, passwords, URLs, notes and supported TOTP secrets are preserved. Custom fields are appended to notes. Per-item Bitwarden password re-prompts are not enforced. Unsupported TOTP profiles or over-limit entries are reported rather than silently stripped.

Limits: 10 MB, 5,000 input records, and the server's existing vault limits. CSV does not transfer passkeys or attachments. Use synthetic data for an initial test and compare the counts with your source. See [Bitwarden's CSV format](https://bitwarden.com/help/condition-bitwarden-import/).

## Export

**File → Export CSV** is available only while unlocked. The confirmation explains that the output contains **plaintext passwords and TOTP secrets**. Choose a private destination. Do not upload it, send it in chat or open it in a spreadsheet; values are preserved literally, including formula-like prefixes. This is a migration file, not a full backup: passkey private keys and attachments are excluded. Keep using verified server backups.

If the vault locks while a file picker is open, import/export does not proceed. Transfer buffers and import plans are released when the operation closes; no promise of forensic memory erasure is made for managed-language strings.

## Italiano

Installa questa versione manualmente una volta: la 0.3.2 non poteva cercare aggiornamenti. Da questa versione trovi **Impostazioni → Controlla aggiornamenti** e l'avviso in alto a destra. Su Windows il clic avvia aggiornamento e riavvio; su Android serve la conferma del sistema e poi si riapre l'app. Il profilo e i dati restano separati dalla cartella del programma.

Con il vault sbloccato usa **File → Importa da Bitwarden**, scegli il CSV e controlla il riepilogo prima di confermare. Le voci esistenti non vengono sostituite e i duplicati esatti vengono saltati. Se un import si interrompe, le voci già confermate restano salvate: risolvi le eventuali scritture in attesa e rileggi lo stesso CSV.

**File → Esporta CSV** crea un file con password e segreti 2FA in chiaro, soltanto dopo conferma. Conservalo privatamente; non è un backup completo e non contiene passkey. Non inviare qui il tuo CSV. Non serve aggiornare il server CasaOS.
