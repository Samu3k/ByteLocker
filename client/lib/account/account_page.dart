import '../l10n/app_strings.dart';
import '../brand.dart';

import 'dart:async';

import 'package:flutter/services.dart';

import 'package:flutter/material.dart';

import '../account/account_client.dart';
import '../connection/server_address.dart';
import '../connection/server_config.dart';
import '../vault/vault_client.dart';
import '../vault/vault_page.dart';
import '../settings/client_settings.dart';
import '../crypto/pm1.dart';
import 'linked_account.dart';

class AccountPage extends StatefulWidget {
  const AccountPage({
    super.key,
    required this.address,
    required this.config,
    this.client,
    this.linked,
    this.linkedStore = const LinkedAccountStore(),
    this.onChangeConnection,
  });
  final ServerAddress address;
  final ServerConfig config;
  final AccountClient? client;
  final LinkedAccount? linked;
  final LinkedAccountStore linkedStore;
  final VoidCallback? onChangeConnection;
  @override
  State<AccountPage> createState() => _AccountPageState();
}

class _AccountPageState extends State<AccountPage> with WidgetsBindingObserver {
  final _form = GlobalKey<FormState>();
  final _email = TextEditingController();
  final _password = TextEditingController();
  final _confirm = TextEditingController();
  final _invite = TextEditingController();
  final _code = TextEditingController();
  late final AccountClient _client =
      widget.client ??
      AccountClient(AccountTransport(widget.address), widget.config);
  bool _register = false, _busy = false, _foreground = true;
  int _operation = 0;
  String? _message;
  PendingAccount? _pending;
  UnlockedAccount? _account;
  VaultClient? _vault;
  bool _biometricEnabled = false, _nativePrompt = false, _showSettings = false;
  LinkedAccount? _linked;
  static const _lockDelay = Duration(minutes: 5);
  Timer? _lockTimer;
  DateTime? _lockDeadline;
  final _backgroundClock = Stopwatch();
  NativeSecurity get _native =>
      SettingsScope.maybeOf(context)?.native ?? const NativeSecurity();
  String get _slot =>
      '${widget.address.origin}|${widget.config.serverId}|${normalizeEmail(_email.text)}';

  @override
  void initState() {
    super.initState();
    _linked = widget.linked;
    _email.text = _linked?.email ?? '';
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_linked != null) unawaited(_checkBiometrics());
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // A biometric prompt can briefly remove focus without leaving the app.
    if (_nativePrompt && state == AppLifecycleState.inactive) return;
    _foreground = state == AppLifecycleState.resumed;
    if (_foreground) {
      if ((_lockDeadline != null && !DateTime.now().isBefore(_lockDeadline!)) ||
          _backgroundClock.elapsed >= _lockDelay) {
        _lockAfterBackground();
      }
      _cancelLockTimer();
      if (_linked != null) unawaited(_checkBiometrics());
      return;
    }
    if (state == AppLifecycleState.detached) {
      _lockAfterBackground();
      return;
    }
    if (_lockDeadline == null) {
      _operation++;
      _password.clear();
      _confirm.clear();
      _invite.clear();
      _lockDeadline = DateTime.now().add(_lockDelay);
      _backgroundClock.start();
      _lockTimer = Timer(_lockDelay, _lockAfterBackground);
    }
  }

  void _cancelLockTimer() {
    _lockTimer?.cancel();
    _lockTimer = null;
    _lockDeadline = null;
    _backgroundClock
      ..stop()
      ..reset();
  }

  void _lockAfterBackground() {
    _cancelLockTimer();
    _vault?.dispose();
    _vault = null;
    _operation++;
    if (_account != null) _discard(_account!);
    if (mounted)
      setState(() {
        _account = null;
        _showSettings = false;
        _message = tr(
          context,
          'Vault bloccato. Usa la Master Password o lo sblocco biometrico.',
        );
      });
  }

  @override
  void dispose() {
    _cancelLockTimer();
    _vault?.dispose();
    WidgetsBinding.instance.removeObserver(this);
    _operation++;
    if (_account != null) _discard(_account!);
    _pending?.destroy();
    for (final controller in [_email, _password, _confirm, _invite, _code]) {
      controller.clear();
      controller.dispose();
    }
    super.dispose();
  }

  String _error(Object error) {
    if (error is AccountFailure) {
      if (error.status == 409 && error.code == 'session_limit') {
        return tr(
          context,
          'Il server ha raggiunto il limite di sessioni aperte. Aggiorna il server CasaOS alla versione 0.2.3 o successiva, poi riprova: le credenziali rimangono salvate.',
        );
      }
      return switch (error.status) {
        401 => tr(context, 'Email o Master Password non valide.'),
        400 => tr(context, 'Controlla i dati inseriti o il codice ricevuto.'),
        403 || 404 => tr(
          context,
          'Operazione non disponibile. Controlla l’invito e il server.',
        ),
        409 => tr(
          context,
          'Operazione in conflitto. Riprova oppure contatta chi gestisce il server.',
        ),
        429 => tr(context, 'Troppi tentativi. Attendi prima di riprovare.'),
        _ => tr(
          context,
          'Connessione non riuscita. Controlla il server e riprova.',
        ),
      };
    }
    return tr(
      context,
      'Impossibile verificare i dati in sicurezza. Controlla i dati e riprova.',
    );
  }

  void _discard(UnlockedAccount account) {
    unawaited(_client.logout(account).catchError((Object _) {}));
  }

  Future<void> _submit() async {
    if (_busy || !_form.currentState!.validate()) return;
    FocusScope.of(context).unfocus();
    final operation = ++_operation;
    final password = _password.text;
    final invitation = _invite.text.trim();
    _password.clear();
    _confirm.clear();
    _invite.clear();
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      if (_pending != null) {
        await _client.verify(_pending!, _code.text);
        if (!mounted) return;
        setState(() {
          _pending = null;
          _register = false;
          _code.clear();
          _message = tr(
            context,
            'Account creato. Accedi con la tua Master Password.',
          );
        });
      } else if (_register) {
        final pending = await _client.register(
          _email.text,
          password,
          invitation,
        );
        if (!mounted || operation != _operation) {
          pending.destroy();
          return;
        }
        setState(() {
          _pending = pending;
          _message = tr(
            context,
            'Inserisci il codice di 8 cifre ricevuto via email.',
          );
        });
      } else {
        final account = await _client.login(_email.text, password);
        if (!mounted || !_foreground || operation != _operation) {
          _discard(account);
          return;
        }
        try {
          await _remember(account);
        } catch (_) {
          _discard(account);
          rethrow;
        }
        if (!mounted ||
            !_foreground ||
            operation != _operation ||
            account.locked) {
          _discard(account);
          return;
        }
        setState(() {
          _account = account;
          _vault = VaultClient(_client, account);
        });
        await _checkBiometrics();
      }
    } catch (error) {
      if (mounted && operation == _operation)
        setState(() {
          _message = _error(error);
        });
    } finally {
      if (mounted)
        setState(() {
          _busy = false;
        });
    }
  }

  Future<void> _resend() async {
    if (_busy || _pending == null) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await _client.resend(_pending!);
      if (mounted)
        setState(() {
          _message = tr(
            context,
            'Nuovo codice richiesto. Controlla la tua email.',
          );
        });
    } catch (error) {
      if (mounted)
        setState(() {
          _message = _error(error);
        });
    } finally {
      if (mounted)
        setState(() {
          _busy = false;
        });
    }
  }

  Future<void> _checkBiometrics() async {
    try {
      final slot = _slot;
      final enabled = await _native.enrolled(slot);
      if (mounted && _slot == slot) setState(() => _biometricEnabled = enabled);
    } catch (_) {
      if (mounted) setState(() => _biometricEnabled = false);
    }
  }

  Future<void> _remember(UnlockedAccount account) async {
    final email = normalizeEmail(_email.text);
    if (_linked != null && !_linked!.matches(account))
      throw const CryptoFailure();
    final linked = LinkedAccount(
      address: widget.address,
      serverId: widget.config.serverId,
      email: email,
      accountId: account.identity.account.wire,
      vaultId: account.identity.vault.wire,
    );
    await widget.linkedStore.save(linked);
    if (mounted) _linked = linked;
  }

  Future<void> _setBiometrics(bool enabled) async {
    final account = _account;
    if (account == null || account.locked) throw const AccountFailure(401);
    final native = _native, slot = _slot;
    final payload = enabled ? _client.biometricPayload(account) : null;
    _nativePrompt = true;
    try {
      if (payload != null) {
        await native.enroll(slot, payload);
        if (!await native.enrolled(slot)) {
          throw PlatformException(code: 'NOT_SAVED');
        }
      } else {
        await native.remove(slot);
      }
      if (!mounted || account.locked) {
        if (enabled) await native.remove(slot);
        return;
      }
      setState(() => _biometricEnabled = enabled);
    } finally {
      _nativePrompt = false;
      payload?.fillRange(0, payload.length, 0);
    }
  }

  Future<void> _biometricLogin() async {
    if (_busy) return;
    final native = _native;
    late String slot;
    try {
      slot = _slot;
    } catch (_) {
      setState(() => _message = tr(context, 'Inserisci prima la tua email.'));
      return;
    }
    final operation = ++_operation;
    setState(() {
      _busy = true;
      _message = null;
    });
    _nativePrompt = true;
    try {
      final payload = await native.unlock(slot);
      if (payload == null) return;
      try {
        if (!mounted || !_foreground || operation != _operation) return;
        final account = await _client.biometricLogin(_email.text, payload);
        if (_linked != null && !_linked!.matches(account)) {
          _discard(account);
          throw const CryptoFailure();
        }
        if (!mounted || !_foreground || operation != _operation) {
          _discard(account);
          return;
        }
        setState(() {
          _account = account;
          _vault = VaultClient(_client, account);
          _biometricEnabled = true;
        });
      } finally {
        payload.fillRange(0, payload.length, 0);
      }
    } catch (error) {
      if (error is CryptoFailure ||
          error is AccountFailure && error.status == 401) {
        try {
          await native.remove(slot);
        } catch (_) {}
      }
      if (mounted && operation == _operation)
        setState(
          () => _message = tr(
            context,
            'Sblocco biometrico non disponibile. Accedi con la Master Password e attivalo dalle impostazioni del vault.',
          ),
        );
    } finally {
      _nativePrompt = false;
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _logout() async {
    _cancelLockTimer();
    final account = _account;
    if (account == null) return;
    _vault?.dispose();
    _vault = null;
    setState(() {
      _account = null;
      _busy = true;
      _message = tr(context, 'Vault bloccato.');
    });
    try {
      await _client.logout(account);
    } catch (_) {
      if (mounted)
        setState(() {
          _message = tr(
            context,
            'Vault bloccato sul dispositivo. La chiusura della sessione sul server non è stata confermata.',
          );
        });
    } finally {
      if (mounted)
        setState(() {
          _busy = false;
        });
    }
  }

  Widget _field(
    TextEditingController controller,
    String label, {
    bool secret = false,
    TextInputType? keyboard,
    String? Function(String?)? validator,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 16),
    child: TextFormField(
      controller: controller,
      enabled: !_busy,
      obscureText: secret,
      autocorrect: false,
      enableSuggestions: false,
      keyboardType: keyboard,
      decoration: InputDecoration(labelText: label),
      validator:
          validator ??
          (value) =>
              value == null || value.isEmpty ? 'Campo obbligatorio' : null,
      onFieldSubmitted: (_) => unawaited(_submit()),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final unlocked = _account != null && !_account!.locked;
    if (unlocked)
      return VaultPage(
        vault: _vault!,
        onLogout: _logout,
        onBiometrics: _setBiometrics,
        biometricEnabled: _biometricEnabled,
      );
    return Scaffold(
      appBar: AppBar(
        title: const ByteLockerTitle(),
        actions: [
          IconButton(
            tooltip: tr(context, 'Impostazioni'),
            onPressed: _busy
                ? null
                : () => setState(() => _showSettings = !_showSettings),
            icon: const Icon(Icons.settings_outlined),
          ),
        ],
      ),
      body: SafeArea(
        child: _showSettings
            ? SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: ClientSettingsPanel(
                  onClose: () => setState(() => _showSettings = false),
                  biometricEnabled: _biometricEnabled,
                ),
              )
            : SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 480),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        const SizedBox(height: 20),
                        const ByteLockerLogo(size: 72),
                        const SizedBox(height: 24),
                        Text(
                          _pending != null
                              ? tr(context, 'Conferma la tua email')
                              : _register
                              ? tr(context, 'Crea il tuo account')
                              : _linked != null
                              ? tr(context, 'Sblocca il vault')
                              : tr(context, 'Bentornato'),
                          style: Theme.of(context).textTheme.headlineMedium,
                        ),
                        const SizedBox(height: 12),
                        Text(
                          widget.address.origin.toString(),
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                        const SizedBox(height: 28),
                        if (_linked != null) ...[
                          Text(
                            _linked!.email,
                            key: const Key('remembered-email'),
                          ),
                          const SizedBox(height: 16),
                        ],
                        if (_pending == null &&
                            !_register &&
                            (_linked == null || _biometricEnabled) &&
                            SettingsScope.maybeOf(context)
                                    ?.biometricsAvailable ==
                                true) ...[
                          OutlinedButton.icon(
                            onPressed: _busy ? null : _biometricLogin,
                            icon: const Icon(Icons.fingerprint),
                            label: Text(tr(context, 'Sblocca con biometria')),
                          ),
                          const SizedBox(height: 16),
                        ],
                        Form(
                          key: _form,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              if (_pending != null) ...[
                                _field(
                                  _code,
                                  tr(context, 'Codice email'),
                                  keyboard: TextInputType.number,
                                  validator: (value) =>
                                      RegExp(r'^[0-9]{8}$')
                                          .hasMatch(value ?? '')
                                      ? null
                                      : tr(
                                          context,
                                          'Inserisci le 8 cifre del codice',
                                        ),
                                ),
                              ] else ...[
                                if (_linked == null || _register)
                                  _field(
                                    _email,
                                    'Email',
                                    keyboard: TextInputType.emailAddress,
                                    validator: (value) {
                                      try {
                                        normalizeEmail(value ?? '');
                                        return null;
                                      } on FormatException {
                                        return tr(
                                          context,
                                          'Inserisci un’email valida',
                                        );
                                      }
                                    },
                                  ),
                                _field(
                                  _password,
                                  'Master Password',
                                  secret: true,
                                  validator: (value) =>
                                      value == null || value.isEmpty
                                      ? tr(
                                          context,
                                          'Inserisci la Master Password',
                                        )
                                      : _register && value.runes.length < 12
                                      ? tr(context, 'Usa almeno 12 caratteri')
                                      : null,
                                ),
                                if (_register) ...[
                                  _field(
                                    _confirm,
                                    tr(context, 'Conferma Master Password'),
                                    secret: true,
                                    validator: (value) =>
                                        value == _password.text
                                        ? null
                                        : tr(
                                            context,
                                            'Le password non coincidono',
                                          ),
                                  ),
                                  _field(
                                    _invite,
                                    tr(context, 'Codice d’invito'),
                                    secret: true,
                                  ),
                                ],
                              ],
                              FilledButton(
                                onPressed: _busy ? null : _submit,
                                child: Padding(
                                  padding: const EdgeInsets.all(12),
                                  child: _busy
                                      ? const SizedBox(
                                          width: 22,
                                          height: 22,
                                          child: CircularProgressIndicator(
                                            strokeWidth: 2,
                                          ),
                                        )
                                      : Text(
                                          _pending != null
                                              ? tr(context, 'Verifica codice')
                                              : _register
                                              ? tr(context, 'Crea account')
                                              : tr(context, 'Accedi e sblocca'),
                                        ),
                                ),
                              ),
                              if (_pending != null)
                                TextButton(
                                  onPressed: _busy ? null : _resend,
                                  child: Text(
                                    tr(context, 'Richiedi un nuovo codice'),
                                  ),
                                )
                              else if (_linked == null &&
                                  widget.config.registrationAvailable)
                                TextButton(
                                  onPressed: _busy
                                      ? null
                                      : () => setState(() {
                                          _register = !_register;
                                          _password.clear();
                                          _confirm.clear();
                                          _invite.clear();
                                          _message = null;
                                          _form.currentState?.reset();
                                        }),
                                  child: Text(
                                    _register
                                        ? tr(
                                            context,
                                            'Hai già un account? Accedi',
                                          )
                                        : tr(
                                            context,
                                            'Prima volta? Crea un account',
                                          ),
                                  ),
                                ),
                            ],
                          ),
                        ),
                        if (_linked != null)
                          TextButton(
                            onPressed: _busy
                                ? null
                                : widget.onChangeConnection ??
                                      () => Navigator.of(context).pop(),
                            child: Text(tr(context, 'Cambia server o account')),
                          ),
                        if (_message != null)
                          Padding(
                            padding: const EdgeInsets.only(top: 20),
                            child: Semantics(
                              liveRegion: true,
                              child: Text(_message!),
                            ),
                          ),
                        const SizedBox(height: 24),
                        Text(
                          tr(
                            context,
                            'La Master Password resta sul dispositivo. Conservala con cura: l’email da sola non permette di recuperare il vault.',
                          ),
                          style: TextStyle(fontSize: 12, height: 1.5),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
      ),
    );
  }
}
