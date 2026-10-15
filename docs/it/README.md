<div align="center">
  <img src="../../client/assets/brand/bytelocker.png" alt="Logo ByteLocker" width="200" />
  <h1>ByteLocker</h1>
  <p><strong>Le tue password. Il tuo server.</strong></p>
  <p>Vault cifrato per Android e Windows, sul tuo server CasaOS / Docker.</p>
  <p><a href="https://github.com/Samu3k/ByteLocker/releases/tag/v0.3.2">Scarica</a> · <a href="getting-started.md">Primo utilizzo</a> · <a href="self-hosting.md">Installa il server</a> · <a href="../../README.md">English</a></p>
  <p><sub>Client 0.3.2 · Server 0.2.3 · Beta pubblica</sub></p>
</div>

![ByteLocker su Windows con dati di prova](../images/031-vault-desktop.png)

## Tutto a portata di mano

- Categorie, preferiti, tag e oltre 3.300 loghi inclusi.
- Copia rapida di email, username, password e codici 2FA.
- Master Password, biometria opzionale e provider passkey su Android compatibile.
- Server personale con inviti, vault separati, pannello amministratore e backup verificabili.

## Inizia qui

Scarica il client dalle [Releases](https://github.com/Samu3k/ByteLocker/releases/tag/v0.3.2). Su Windows estrai tutto lo ZIP; su Android installa l'APK sopra la versione precedente.

**Hai un invito?** Inserisci l'indirizzo HTTPS ricevuto privatamente e crea il tuo account. [Guida →](getting-started.md)

**Vuoi un server tuo?** Segui la [guida CasaOS](self-hosting.md). Ogni installazione ha utenti e chiavi indipendenti.

Il client non contiene un server personale o credenziali preimpostate. I download sono pubblici; per registrarsi su un server serve comunque un invito del gestore.

## Sicurezza e limiti

Il vault viene cifrato sul dispositivo con Argon2id e AES-256-GCM. Master Password e chiave del vault non vengono inviate al server.

**È un'anteprima in sviluppo, senza revisione di sicurezza indipendente:** inizia con dati di prova. Mancano sincronizzazione offline, recupero password, Windows Hello e vault web. Restano da completare prove passkey, firma pubblica e indirizzo HTTPS stabile. La beta Android mantiene la firma di prova e non è una release Play Store.

Codice ByteLocker sotto [GPL-3.0-only](../../LICENSE), copyright © 2026 Samu3k. Le dipendenze e i loghi mantengono le proprie licenze.

[Documentazione](../README.md) · [Sicurezza](../../.github/SECURITY.md) · [Contribuire](../../.github/CONTRIBUTING.md)
