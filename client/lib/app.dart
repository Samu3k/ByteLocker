import 'l10n/app_strings.dart';
import 'brand.dart';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'dart:async';

import 'settings/client_settings.dart';

import 'account/account_page.dart';
import 'account/linked_account.dart';
import 'connection/connection_gate.dart';

import 'connection/discovery_client.dart';
import 'connection/server_address.dart';
import 'connection/server_config.dart';

class ByteLockerApp extends StatefulWidget {
  const ByteLockerApp({
    super.key,
    this.discovery,
    this.allowLocalHttp = false,
    this.settings,
    this.linkedStore = const LinkedAccountStore(),
  });
  final ServerDiscovery? discovery;
  final bool allowLocalHttp;
  final ClientSettings? settings;
  final LinkedAccountStore linkedStore;

  @override
  State<ByteLockerApp> createState() => _ByteLockerAppState();
}

class _ByteLockerAppState extends State<ByteLockerApp> {
  late final _settings = widget.settings ?? ClientSettings();
  @override
  void initState() {
    super.initState();
    _settings.addListener(_changed);
    unawaited(_settings.load());
  }

  void _changed() {
    if (mounted) setState(() {});
  }

  @override
  void dispose() {
    _settings.removeListener(_changed);
    if (widget.settings == null) _settings.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return SettingsScope(
      settings: _settings,
      child: MaterialApp(
        title: 'ByteLocker',
        debugShowCheckedModeBanner: false,
        themeMode: _settings.mode,
        locale: _settings.locale,
        supportedLocales: AppStrings.supportedLocales,
        localizationsDelegates: const [
          AppStrings.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        theme: ThemeData(
          useMaterial3: true,
          brightness: Brightness.light,
          colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff78e2c8)),
          inputDecorationTheme: InputDecorationTheme(
            filled: true,
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(14)),
            contentPadding: const EdgeInsets.all(18),
          ),
        ),
        darkTheme: ThemeData(
          useMaterial3: true,
          brightness: Brightness.dark,
          colorScheme: ColorScheme.fromSeed(
            seedColor: const Color(0xff78e2c8),
            brightness: Brightness.dark,
            surface: const Color(0xff172323),
          ),
          scaffoldBackgroundColor: const Color(0xff0c1516),
          inputDecorationTheme: InputDecorationTheme(
            filled: true,
            fillColor: const Color(0xff101b1d),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(14)),
            contentPadding: const EdgeInsets.all(18),
          ),
        ),
        home: ConnectionGate(
          discovery: widget.discovery ?? DiscoveryClient(),
          store: widget.linkedStore,
          allowLocalHttp: widget.allowLocalHttp,
        ),
      ),
    );
  }
}

class ServerConnectionPage extends StatefulWidget {
  const ServerConnectionPage({
    super.key,
    required this.discovery,
    this.allowLocalHttp = false,
    this.linkedStore = const LinkedAccountStore(),
    this.initialAddress,
  });
  final ServerDiscovery discovery;
  final bool allowLocalHttp;
  final LinkedAccountStore linkedStore;
  final String? initialAddress;

  @override
  State<ServerConnectionPage> createState() => _ServerConnectionPageState();
}

class _ServerConnectionPageState extends State<ServerConnectionPage> {
  final _form = GlobalKey<FormState>();
  final _address = TextEditingController();
  bool _busy = false;
  ServerConfig? _config;
  ServerAddress? _checkedAddress;
  String? _failure;
  bool _settings = false;

  @override
  void initState() {
    super.initState();
    _address.text = widget.initialAddress ?? '';
  }

  @override
  void dispose() {
    _address.dispose();
    super.dispose();
  }

  String? _validate(String? value) {
    try {
      ServerAddress.parse(value ?? '', allowLocalHttp: widget.allowLocalHttp);
      return null;
    } on FormatException {
      return tr(
        context,
        'Inserisci un indirizzo HTTPS valido, senza percorsi o credenziali.',
      );
    }
  }

  Future<void> _check() async {
    if (_busy || !_form.currentState!.validate()) return;
    FocusScope.of(context).unfocus();
    final address = ServerAddress.parse(
      _address.text,
      allowLocalHttp: widget.allowLocalHttp,
    );
    setState(() {
      _busy = true;
      _config = null;
      _failure = null;
    });
    try {
      final config = await widget.discovery.discover(address);
      if (!mounted) return;
      setState(() {
        _config = config;
        _checkedAddress = address;
      });
    } on DiscoveryException catch (error) {
      if (!mounted) return;
      setState(() {
        _failure = _failureText(error.failure);
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _failure = tr(context, 'Impossibile completare il controllo. Riprova.');
      });
    } finally {
      if (mounted)
        setState(() {
          _busy = false;
        });
    }
  }

  String _failureText(DiscoveryFailure failure) => switch (failure) {
    DiscoveryFailure.unreachable => tr(
      context,
      'Server non raggiungibile. Controlla indirizzo e connessione.',
    ),
    DiscoveryFailure.timeout => tr(
      context,
      'Il server impiega troppo tempo a rispondere. Riprova.',
    ),
    DiscoveryFailure.certificate => tr(
      context,
      'Il certificato del server non è valido. Contatta chi gestisce il server.',
    ),
    DiscoveryFailure.redirect => tr(
      context,
      'Questo indirizzo rimanda a un altro sito. Inserisci l’indirizzo diretto del server.',
    ),
    DiscoveryFailure.incompatible => tr(
      context,
      'Questa versione del server non è compatibile con l’app.',
    ),
    DiscoveryFailure.malformed || DiscoveryFailure.response => tr(
      context,
      'La risposta non corrisponde a un server compatibile.',
    ),
  };

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        actions: [
          IconButton(
            tooltip: tr(context, 'Impostazioni'),
            onPressed: () => setState(() => _settings = !_settings),
            icon: const Icon(Icons.settings_outlined),
          ),
        ],
      ),
      body: SafeArea(
        child: _settings
            ? SingleChildScrollView(
                padding: const EdgeInsets.all(24),
                child: ClientSettingsPanel(
                  onClose: () => setState(() => _settings = false),
                ),
              )
            : LayoutBuilder(
                builder: (context, constraints) {
                  final wide = constraints.maxWidth >= 900;
                  return SingleChildScrollView(
                    padding: EdgeInsets.symmetric(
                      horizontal: wide ? 48 : 24,
                      vertical: 32,
                    ),
                    child: Center(
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 1080),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.all(12),
                                  decoration: BoxDecoration(
                                    color: colors.primaryContainer,
                                    borderRadius: BorderRadius.circular(16),
                                  ),
                                  child: const ByteLockerLogo(size: 42),
                                ),
                                const SizedBox(width: 14),
                                const Expanded(
                                  child: Text(
                                    'ByteLocker',
                                    style: TextStyle(
                                      fontSize: 20,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                            SizedBox(height: wide ? 88 : 40),
                            if (wide)
                              Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Expanded(child: _intro(context)),
                                  const SizedBox(width: 64),
                                  Expanded(child: _connectionCard(context)),
                                ],
                              )
                            else ...[
                              _intro(context),
                              const SizedBox(height: 30),
                              _connectionCard(context),
                            ],
                            const SizedBox(height: 32),
                            Text(
                              tr(
                                context,
                                'Il codice d’invito serve solo per creare un nuovo account.',
                              ),
                              style: TextStyle(color: colors.onSurfaceVariant),
                            ),
                          ],
                        ),
                      ),
                    ),
                  );
                },
              ),
      ),
    );
  }

  Widget _intro(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          tr(context, 'IL TUO SPAZIO PRIVATO'),
          style: TextStyle(
            color: colors.primary,
            fontWeight: FontWeight.w700,
            letterSpacing: 2,
            fontSize: 12,
          ),
        ),
        const SizedBox(height: 16),
        Text(
          tr(context, 'Il tuo vault.\nSul tuo server.'),
          style: TextStyle(
            fontSize: 40,
            height: 1.15,
            fontWeight: FontWeight.w700,
          ),
        ),
        const SizedBox(height: 20),
        Text(
          tr(
            context,
            'Comincia dall’indirizzo del server che ospiterà il tuo account.',
          ),
          style: TextStyle(
            color: colors.onSurfaceVariant,
            fontSize: 17,
            height: 1.5,
          ),
        ),
        const SizedBox(height: 24),
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.shield_outlined, color: colors.primary, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                tr(
                  context,
                  'Il controllo della connessione non invia password o codici d’invito.',
                ),
                style: TextStyle(color: colors.onSurfaceVariant, height: 1.5),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _connectionCard(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: colors.surface,
        border: Border.all(color: colors.outlineVariant),
        borderRadius: BorderRadius.circular(24),
      ),
      child: Form(
        key: _form,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              tr(context, 'Collega il tuo server'),
              style: TextStyle(fontSize: 24, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 8),
            Text(
              tr(
                context,
                'Usa l’indirizzo che hai configurato o ricevuto da chi ti ha invitato.',
              ),
              style: TextStyle(color: colors.onSurfaceVariant, height: 1.5),
            ),
            const SizedBox(height: 24),
            TextFormField(
              key: const Key('server-address'),
              controller: _address,
              enabled: !_busy,
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.done,
              autocorrect: false,
              enableSuggestions: false,
              maxLength: 512,
              decoration: InputDecoration(
                labelText: tr(context, 'Indirizzo del server'),
                hintText: 'https://vault.example.com',
                prefixIcon: Icon(Icons.dns_outlined),
                counterText: '',
                errorMaxLines: 4,
              ),
              validator: _validate,
              onChanged: (_) => setState(() {
                _config = null;
                _failure = null;
              }),
              onFieldSubmitted: (_) => _check(),
            ),
            const SizedBox(height: 18),
            FilledButton(
              key: const Key('check-server'),
              onPressed: _busy ? null : _check,
              style: FilledButton.styleFrom(
                padding: const EdgeInsets.symmetric(
                  horizontal: 20,
                  vertical: 18,
                ),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
              child: _busy
                  ? const SizedBox(
                      height: 22,
                      width: 22,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text(
                      _config == null
                          ? tr(context, 'Controlla server')
                          : tr(context, 'Controlla di nuovo'),
                    ),
            ),
            if (_busy) ...[
              const SizedBox(height: 16),
              Semantics(
                liveRegion: true,
                child: Text(
                  tr(context, 'Controllo della connessione in corso…'),
                ),
              ),
            ],
            if (_failure != null) ...[
              const SizedBox(height: 20),
              Semantics(
                liveRegion: true,
                child: Text(
                  _failure!,
                  key: const Key('connection-error'),
                  style: TextStyle(color: colors.error, height: 1.5),
                ),
              ),
            ],
            if (_config != null) ...[
              const SizedBox(height: 24),
              const Divider(),
              const SizedBox(height: 16),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.check_circle_outline_rounded,
                    color: colors.primary,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      tr(context, 'Server disponibile'),
                      key: Key('connection-success'),
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Text(
                _checkedAddress!.isSecure
                    ? tr(context, 'Connessione HTTPS verificata.')
                    : tr(
                        context,
                        'Connessione locale di sviluppo, senza HTTPS.',
                      ),
                style: TextStyle(color: colors.onSurfaceVariant),
              ),
              const SizedBox(height: 8),
              Text(
                _config!.registrationAvailable
                    ? tr(
                        context,
                        'Il server consente la creazione di account con invito.',
                      )
                    : tr(
                        context,
                        'La creazione di nuovi account non è disponibile su questo server.',
                      ),
                style: TextStyle(color: colors.onSurfaceVariant, height: 1.5),
              ),
              const SizedBox(height: 20),
              FilledButton(
                onPressed: () => Navigator.of(context).push<void>(
                  MaterialPageRoute(
                    builder: (_) => AccountPage(
                      address: _checkedAddress!,
                      config: _config!,
                      linkedStore: widget.linkedStore,
                    ),
                  ),
                ),
                child: Text(tr(context, 'Continua')),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
