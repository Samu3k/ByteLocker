# Client 0.3.2 · Language settings

Android and Windows now offer **Italiano**, **English** and **Device language** in Settings, beside Theme. Changes apply immediately and are remembered locally. Unsupported device languages fall back to Italian. Existing installations keep Italian until a different preference is chosen.

Interface labels, validation, connection messages, credential details, categories, passkeys and 2FA controls are translated. Credential titles, usernames, passwords, notes and user-created category/tag names are never translated. The Android biometric prompt follows the selected language.

Windows now remembers the theme as well as the language in the current user's settings. Android uses its private preferences. No vault schema or server API changes are required; server 0.2.3 remains current.

## Update

- **Android ARM64:** install the 0.3.2 APK over your existing app, without uninstalling. The beta keeps the previous test certificate for upgrades; production signing remains separate.
- **Windows x64:** close ByteLocker, extract the entire new ZIP and start ByteLocker.exe. Keep all DLLs and assets together. Your remembered account remains in your user profile.
- **CasaOS:** no server update is required for languages. Each friend still needs the server origin and a separate invitation.

Checks: 70 Flutter tests passed, including language switching, preference reload and narrow-screen layout; static analysis passed. Android and Windows release builds are verified separately. The automated tests do not replace checks on a physical Android device or a security audit.

---

## Italiano

In **Impostazioni → Lingua**, accanto al tema, scegli Italiano, English oppure Lingua del dispositivo. La scelta è immediata e viene ricordata. I dati delle credenziali e i nomi personali di categorie/tag restano invariati.

Installa l'APK sopra la versione precedente senza disinstallarla. Su Windows chiudi l'app ed estrai tutto lo ZIP nuovo. Il server CasaOS 0.2.3 non richiede aggiornamenti. Prima di coinvolgere gli amici, prova riapertura, lingua, salvataggio, copia 2FA e sblocco sul telefono reale.
