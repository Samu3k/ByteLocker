import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

/// Only interface messages are translated; vault contents are never looked up.
String tr(BuildContext context, String message) =>
    Localizations.of<AppStrings>(context, AppStrings)?.text(message) ?? message;

class AppStrings {
  const AppStrings(this.locale);
  final Locale locale;
  static const supportedLocales = [Locale('it'), Locale('en')];
  static const delegate = _StringsDelegate();
  String text(String message) =>
      locale.languageCode == 'en' ? _english[message] ?? message : message;
  String copied(String label) => locale.languageCode == 'en'
      ? '$label: copied to clipboard'
      : '$label: copiato negli appunti';
  String nextCode(int seconds) => locale.languageCode == 'en'
      ? 'New code in $seconds seconds'
      : 'Nuovo codice tra $seconds secondi';
  static AppStrings of(BuildContext context) =>
      Localizations.of<AppStrings>(context, AppStrings) ??
      const AppStrings(Locale('it'));
  String copy(String label) =>
      locale.languageCode == 'en' ? 'Copy $label' : 'Copia $label';
  String renameCategory(String name) => locale.languageCode == 'en'
      ? 'Rename category $name'
      : 'Rinomina categoria $name';
  String credentials(int count) =>
      locale.languageCode == 'en' ? '$count credentials' : '$count credenziali';
}

class _StringsDelegate extends LocalizationsDelegate<AppStrings> {
  const _StringsDelegate();
  @override
  bool isSupported(Locale locale) => ['it', 'en'].contains(locale.languageCode);
  @override
  Future<AppStrings> load(Locale locale) =>
      SynchronousFuture(AppStrings(locale));
  @override
  bool shouldReload(_StringsDelegate old) => false;
}

const _english = <String, String>{
  'Abilita ByteLocker come gestore nelle impostazioni Android. Le passkey vengono create dal sito o dall’app e salvate nel vault.': 'Enable ByteLocker as a provider in Android settings. Passkeys are created by the website or app and saved in your vault.',
  'Accedi al vault per attivarlo su questo dispositivo.':
      'Unlock your vault to enable this on this device.',
  'Accedi con una passkey': 'Sign in with a passkey',
  'Accedi e sblocca': 'Sign in and unlock',
  'Account creato. Accedi con la tua Master Password.':
      'Account created. Sign in with your Master Password.',
  'Account passkey': 'Passkey account',
  'Aggiorna vault': 'Refresh vault',
  'Aggiungi ai preferiti': 'Add to favorites',
  'Aggiungi tag quando modifichi un login.': 'Add tags when editing a login.',
  'Android non ha completato la protezione della chiave. Riprova ad attivare l’impronta.': 'Android could not finish protecting the key. Try enabling fingerprint unlock again.',
  'Annulla': 'Cancel',
  'Annulla richiesta': 'Cancel request',
  'Annulla richiesta passkey': 'Cancel passkey request',
  'Bentornato': 'Welcome back',
  'Blocca ed esci': 'Lock and sign out',
  'Blocco automatico dopo 5 minuti in background.':
      'Automatically locks after 5 minutes in the background.',
  'Cambia server o account': 'Change server or account',
  'Campo obbligatorio': 'Required field',
  'Categoria': 'Category',
  'Categorie': 'Categories',
  'Categorie e preferiti': 'Categories and favorites',
  'Cerca per titolo, account, sito o tag':
      'Search by title, account, website or tag',
  'Chiaro': 'Light',
  'Chiave di configurazione o link otpauth://. Lascia vuoto per rimuovere il 2FA salvato.':
      'Setup key or otpauth:// link. Leave empty to remove saved 2FA.',
  'Chiudi senza salvare': 'Close without saving',
  'Codice d’invito': 'Invitation code',
  'Codice email': 'Email code',
  'Collega il tuo server': 'Connect your server',
  'Comincia dall’indirizzo del server che ospiterà il tuo account.':
      'Start with the address of the server that will host your account.',
  'Conferma Master Password': 'Confirm Master Password',
  'Conferma dell’impronta annullata. Puoi riprovare.':
      'Fingerprint confirmation cancelled. You can try again.',
  'Conferma e salva passkey': 'Confirm and save passkey',
  'Conferma eliminazione': 'Confirm deletion',
  'Conferma la tua email': 'Verify your email',
  'Conferma rimozione dal vault': 'Confirm removal from vault',
  'Connessione HTTPS verificata.': 'HTTPS connection verified.',
  'Connessione locale di sviluppo, senza HTTPS.':
      'Local development connection, without HTTPS.',
  'Connessione non riuscita. Controlla il server e riprova.':
      'Connection failed. Check the server and try again.',
  'Continua': 'Continue',
  'Controlla di nuovo': 'Check again',
  'Controlla i dati inseriti o il codice ricevuto.':
      'Check the details you entered or the code you received.',
  'Controlla server': 'Check server',
  'Controllo della connessione in corso…': 'Checking connection…',
  'Copia password': 'Copy password',
  'Crea account': 'Create account',
  'Crea categorie come Personale o Lavoro.':
      'Create categories such as Personal or Work.',
  'Crea il tuo account': 'Create your account',
  'Crea la passkey dalle impostazioni di sicurezza del sito o dell’app e scegli ByteLocker come gestore.': 'Create the passkey in the website or app security settings and choose ByteLocker as the provider.',
  'Dettagli credenziale': 'Credential details',
  'Elimina credenziale': 'Delete credential',
  'Email o Master Password non valide.': 'Invalid email or Master Password.',
  'Esiste già una categoria con questo nome.':
      'A category with this name already exists.',
  'Gestore passkey Android': 'Android passkey provider',
  'Hai già un account? Accedi': 'Already have an account? Sign in',
  'I contenuti sono cifrati sul dispositivo prima dell’invio.':
      'Contents are encrypted on your device before being sent.',
  'IL TUO SPAZIO': 'YOUR SPACE',
  'IL TUO SPAZIO PRIVATO': 'YOUR PRIVATE SPACE',
  'Icona con iniziale': 'Initial icon',
  'Il certificato del server non è valido. Contatta chi gestisce il server.':
      'The server certificate is invalid. Contact the server owner.',
  'Il codice d’invito serve solo per creare un nuovo account.':
      'An invitation code is only needed to create a new account.',
  'Il controllo della connessione non invia password o codici d’invito.':
      'Checking the connection does not send passwords or invitation codes.',
  'Il provider di passkey richiede Android 14 o successivo.':
      'The passkey provider requires Android 14 or later.',
  'Il server consente la creazione di account con invito.':
      'This server supports invitation-only registration.',
  'Il server ha raggiunto il limite di sessioni aperte. Aggiorna il server CasaOS alla versione 0.2.3 o successiva, poi riprova: le credenziali rimangono salvate.': 'The server has reached its open-session limit. Update the CasaOS server to version 0.2.3 or later and try again. Your credentials remain saved.',
  'Il server impiega troppo tempo a rispondere. Riprova.':
      'The server is taking too long to respond. Try again.',
  'Il tuo vault': 'Your vault',
  'Il tuo vault.\nSul tuo server.': 'Your vault.\nYour server.',
  'Il vault è vuoto. Aggiungi la tua prima credenziale.':
      'Your vault is empty. Add your first credential.',
  'Impossibile completare il controllo. Riprova.':
      'Could not complete the check. Try again.',
  'Impossibile copiare negli appunti. Riprova.':
      'Could not copy to the clipboard. Try again.',
  'Impossibile verificare i dati in sicurezza. Controlla i dati e riprova.':
      'Could not verify the details securely. Check them and try again.',
  'Impostazioni': 'Settings',
  'Indirizzo del server': 'Server address',
  'Inserisci il codice di 8 cifre ricevuto via email.':
      'Enter the eight-digit code you received by email.',
  'Inserisci la Master Password': 'Enter your Master Password',
  'Inserisci le 8 cifre del codice': 'Enter the eight-digit code',
  'Inserisci prima la tua email.': 'Enter your email first.',
  'Inserisci un indirizzo HTTPS valido, senza percorsi o credenziali.':
      'Enter a valid HTTPS address without paths or credentials.',
  'Inserisci un nome breve, massimo 200 byte.':
      'Enter a short name, up to 200 bytes.',
  'Inserisci un titolo': 'Enter a title',
  'Inserisci un’email valida': 'Enter a valid email',
  'La Master Password resta sul dispositivo. Conservala con cura: l’email da sola non permette di recuperare il vault.': 'Your Master Password stays on your device. Keep it safe: email alone cannot recover your vault.',
  'La creazione di nuovi account non è disponibile su questo server.':
      'New account registration is unavailable on this server.',
  'La credenziale è stata modificata su un altro dispositivo. Aggiorna il vault e riapri la voce prima di salvarla.': 'This credential was changed on another device. Refresh the vault and reopen the entry before saving.',
  'La passkey sarà rimossa al salvataggio. Per revocarla sul sito, usa anche le impostazioni del sito.': 'The passkey will be removed when you save. To revoke it on the website, also use that website’s settings.',
  'La richiesta passkey del sito o dell’app non può essere verificata da questa versione.':
      'This version cannot verify the website or app passkey request.',
  'La risposta non corrisponde a un server compatibile.':
      'The response is not from a compatible server.',
  'La scrittura non è confermata. Ripeti la stessa operazione con il pulsante qui sotto.': 'The write is unconfirmed. Retry the same operation with the button below.',
  'La voce sarà rimossa dall’elenco. La cancellazione viene salvata cifrata sul server.': 'The entry will be removed from the list. The deletion is saved encrypted on the server.',
  'Le password non coincidono': 'Passwords do not match',
  'Logo automatico dal sito': 'Automatic website logo',
  'Modifica credenziale': 'Edit credential',
  'Mostra password': 'Show password',
  'Nascondi password': 'Hide password',
  'Nessuna credenziale trovata.': 'No credentials found.',
  'Nessuna passkey compatibile trovata in questo vault.':
      'No compatible passkey found in this vault.',
  'Nome': 'Name',
  'Non impostata': 'Not set',
  'Note': 'Notes',
  'Nuova categoria': 'New category',
  'Nuova credenziale': 'New credential',
  'Nuovo codice richiesto. Controlla la tua email.':
      'New code requested. Check your email.',
  'Operazione in conflitto. Riprova oppure contatta chi gestisce il server.':
      'Operation conflict. Try again or contact the server owner.',
  'Operazione non completata. Aggiorna il vault e riprova; le modifiche nel modulo sono ancora qui.': 'Operation incomplete. Refresh the vault and try again; your form changes are still here.',
  'Operazione non completata. Puoi riprovare. La passkey viene restituita al sito solo dopo il salvataggio confermato.': 'Operation incomplete. You can try again. The passkey is returned to the website only after saving is confirmed.',
  'Operazione non completata. Riprova o usa la Master Password.':
      'Operation incomplete. Try again or use your Master Password.',
  'Operazione non disponibile. Controlla l’invito e il server.':
      'Operation unavailable. Check the invitation and server.',
  'Passkey dei siti e delle app': 'Website and app passkeys',
  'Per esempio: Lavoro': 'For example: Work',
  'Preferiti': 'Favorites',
  'Preferito': 'Favorite',
  'Prima volta? Crea un account': 'First time? Create an account',
  'Questa versione del server non è compatibile con l’app.':
      'This server version is incompatible with the app.',
  'Questo indirizzo rimanda a un altro sito. Inserisci l’indirizzo diretto del server.': 'This address redirects to another site. Enter the server’s direct address.',
  'Richiede Android 11 o successivo, biometria sicura e una chiave protetta dall’hardware.': 'Requires Android 11 or later, strong biometrics and a hardware-protected key.',
  'Richiedi un nuovo codice': 'Request a new code',
  'Rimuovi dai preferiti': 'Remove from favorites',
  'Rimuovi passkey dalla credenziale': 'Remove passkey from credential',
  'Rinomina categoria': 'Rename category',
  'Ripeti operazione in attesa': 'Retry pending operation',
  'Riprendi salvataggio passkey': 'Resume saving passkey',
  'Salva categoria': 'Save category',
  'Salva credenziale': 'Save credential',
  'Salva nella credenziale': 'Save in credential',
  'Salva una passkey': 'Save a passkey',
  'Sblocca con biometria': 'Unlock with biometrics',
  'Sblocca il vault': 'Unlock vault',
  'Sblocco biometrico': 'Biometric unlock',
  'Sblocco biometrico non disponibile. Accedi con la Master Password e attivalo dalle impostazioni del vault.': 'Biometric unlock is unavailable. Sign in with your Master Password and enable it in vault settings.',
  'Scegli il logo': 'Choose logo',
  'Scuro ByteLocker': 'ByteLocker dark',
  'Segreto 2FA': '2FA secret',
  'Segui il sistema': 'Use system setting',
  'Senza categoria': 'Uncategorized',
  'Separa i tag con una virgola': 'Separate tags with a comma',
  'Server disponibile': 'Server available',
  'Server non raggiungibile. Controlla indirizzo e connessione.':
      'Server unreachable. Check the address and connection.',
  'Tema': 'Theme',
  'Titolo': 'Title',
  'Torna al vault': 'Back to vault',
  'Torna indietro': 'Back',
  'Troppi tentativi. Attendi prima di riprovare.':
      'Too many attempts. Wait before trying again.',
  'Tutti i login': 'All logins',
  'Un campo supera il limite consentito. Riduci il testo o i tag.':
      'A field exceeds the allowed limit. Shorten the text or tags.',
  'Una scrittura cifrata è in attesa di conferma. Non chiudere l’app se vuoi conservarne il tentativo.': 'An encrypted write is awaiting confirmation. Do not close the app if you want to keep this attempt.',
  'Usa almeno 12 caratteri': 'Use at least 12 characters',
  'Usa l’impronta o il riconoscimento del viso sicuro configurato su Android.':
      'Use the fingerprint or secure face recognition configured on Android.',
  'Usa l’indirizzo che hai configurato o ricevuto da chi ti ha invitato.':
      'Use the address you configured or received with your invitation.',
  'Usa una chiave Base32 o TOTP SHA-1, 6 cifre, 30 secondi.':
      'Use a Base32 key or TOTP SHA-1, six digits, 30 seconds.',
  'Vault bloccato sul dispositivo. La chiusura della sessione sul server non è stata confermata.': 'Vault locked on this device. Closing the server session was not confirmed.',
  'Vault bloccato.': 'Vault locked.',
  'Vault bloccato. Usa la Master Password o lo sblocco biometrico.':
      'Vault locked. Use your Master Password or biometric unlock.',
  'Verifica codice': 'Verify code',
  'Lingua': 'Language',
  'Italiano': 'Italian',
  'Inglese': 'English',
  'Lingua del dispositivo': 'Device language',
  'Cerca un servizio': 'Search for a service',
  'Automatico': 'Automatic',
  'Solo iniziale': 'Initial only',
  'Riprova': 'Try again',
  'Configurazione 2FA non valida. Usa TOTP SHA-1, 6 cifre e 30 secondi.':
      'Invalid 2FA setup. Use TOTP SHA-1, six digits and 30 seconds.',
  'Codice 2FA': '2FA code',
  'Copia codice 2FA': 'Copy 2FA code',
  'Codice 2FA copiato': '2FA code copied',
  'Impossibile copiare il codice 2FA. Riprova.':
      'Could not copy the 2FA code. Try again.',
  'Mantieni data e ora automatiche sul dispositivo.':
      'Keep automatic date and time enabled on your device.',
  'Non riesco a verificare il server salvato. Controlla la connessione oppure aggiorna l’indirizzo del server.': 'Could not verify the saved server. Check your connection or update the server address.',
  'Impossibile salvare la preferenza. Riprova.':
      'Could not save your preference. Try again.',
};
