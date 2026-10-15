import '../l10n/app_strings.dart';

import 'package:flutter/material.dart';

import 'dart:io';

import 'package:flutter/services.dart';

class NativeSecurity {
  const NativeSecurity();
  static const channel = MethodChannel('bytelocker/security');
  Future<Map<Object?, Object?>> status() async =>
      (Platform.isAndroid || Platform.isWindows)
      ? await channel.invokeMapMethod<Object?, Object?>('status') ?? {}
      : {};
  Future<void> theme(String value) async {
    if (Platform.isAndroid || Platform.isWindows)
      await channel.invokeMethod('theme', value);
  }

  Future<void> language(String value) async {
    if (Platform.isAndroid || Platform.isWindows)
      await channel.invokeMethod('language', value);
  }

  Future<void> enroll(String slot, Uint8List payload) =>
      channel.invokeMethod('enroll', {'slot': slot, 'payload': payload});
  Future<Uint8List?> unlock(String slot) =>
      channel.invokeMethod<Uint8List>('unlock', slot);
  Future<bool> enrolled(String slot) async => Platform.isAndroid
      ? await channel.invokeMethod<bool>('enrolled', slot) ?? false
      : false;
  Future<void> remove(String slot) => channel.invokeMethod('remove', slot);
  Future<void> providerSettings() => channel.invokeMethod('providerSettings');
}

class ClientSettings extends ChangeNotifier {
  ClientSettings({this.native = const NativeSecurity()});
  final NativeSecurity native;
  bool _alive = true;
  ThemeMode mode = ThemeMode.dark;
  String language = 'it';
  Locale? get locale => language == 'system' ? null : Locale(language);
  bool biometricsAvailable = false, passkeysAvailable = false;
  Future<void> load() async {
    try {
      final status = await native.status();
      if (!_alive) return;
      mode = switch (status['theme']) {
        'light' => ThemeMode.light,
        'system' => ThemeMode.system,
        _ => ThemeMode.dark,
      };
      biometricsAvailable = status['biometrics'] == true;
      passkeysAvailable = status['passkeys'] == true;
      language = ['it', 'en', 'system'].contains(status['language'])
          ? status['language'] as String
          : 'it';
      notifyListeners();
    } on MissingPluginException {
      // Tests or unsupported platforms may not have a native settings store.
    } on PlatformException {
      // An unavailable native store never enables security capabilities.
    }
  }

  Future<void> changeTheme(ThemeMode value) async {
    try {
      await native.theme(value.name);
    } on MissingPluginException {
      // Preserve in-memory themes when a native store is unavailable in tests.
    }
    if (!_alive) return;
    mode = value;
    notifyListeners();
  }

  Future<void> changeLanguage(String value) async {
    if (!['it', 'en', 'system'].contains(value))
      throw ArgumentError.value(value);
    await native.language(value);
    if (!_alive) return;
    language = value;
    notifyListeners();
  }

  @override
  void dispose() {
    _alive = false;
    super.dispose();
  }
}

class SettingsScope extends InheritedNotifier<ClientSettings> {
  const SettingsScope({
    super.key,
    required ClientSettings settings,
    required super.child,
  }) : super(notifier: settings);
  static ClientSettings? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<SettingsScope>()?.notifier;
}

class ClientSettingsPanel extends StatefulWidget {
  const ClientSettingsPanel({
    super.key,
    required this.onClose,
    this.onBiometrics,
    this.biometricEnabled = false,
  });
  final VoidCallback onClose;
  final Future<void> Function(bool)? onBiometrics;
  final bool biometricEnabled;
  @override
  State<ClientSettingsPanel> createState() => _ClientSettingsPanelState();
}

class _ClientSettingsPanelState extends State<ClientSettingsPanel> {
  bool _busy = false;
  String? _message;
  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await action();
    } catch (error) {
      if (mounted)
        setState(
          () =>
              _message = error is PlatformException && error.code == 'CANCELLED'
              ? tr(context, 'Conferma dell’impronta annullata. Puoi riprovare.')
              : error is PlatformException && error.code == 'INVALIDATED'
              ? tr(
                  context,
                  'Android non ha completato la protezione della chiave. Riprova ad attivare l’impronta.',
                )
              : tr(
                  context,
                  'Operazione non completata. Riprova o usa la Master Password.',
                ),
        );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final settings = SettingsScope.maybeOf(context);
    return SingleChildScrollView(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(tr(context, 'Blocco automatico dopo 5 minuti in background.')),
          const SizedBox(height: 12),
          Text(
            tr(context, 'Impostazioni'),
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 24),
          DropdownButtonFormField<ThemeMode>(
            isExpanded: true,
            key: ValueKey(settings?.mode),
            initialValue: settings?.mode ?? ThemeMode.dark,
            decoration: InputDecoration(labelText: tr(context, 'Tema')),
            items: [
              DropdownMenuItem(
                value: ThemeMode.dark,
                child: Text(tr(context, 'Scuro ByteLocker')),
              ),
              DropdownMenuItem(
                value: ThemeMode.light,
                child: Text(tr(context, 'Chiaro')),
              ),
              DropdownMenuItem(
                value: ThemeMode.system,
                child: Text(tr(context, 'Segui il sistema')),
              ),
            ],
            onChanged: _busy || settings == null
                ? null
                : (value) {
                    if (value != null) _run(() => settings.changeTheme(value));
                  },
          ),
          const SizedBox(height: 24),
          DropdownButtonFormField<String>(
            isExpanded: true,
            key: ValueKey('language-${settings?.language}'),
            initialValue: settings?.language ?? 'it',
            decoration: InputDecoration(labelText: tr(context, 'Lingua')),
            items: [
              const DropdownMenuItem(value: 'it', child: Text('Italiano')),
              const DropdownMenuItem(value: 'en', child: Text('English')),
              DropdownMenuItem(
                value: 'system',
                child: Text(tr(context, 'Lingua del dispositivo')),
              ),
            ],
            onChanged: _busy || settings == null
                ? null
                : (value) {
                    if (value != null)
                      _run(() => settings.changeLanguage(value));
                  },
          ),
          const SizedBox(height: 24),
          SwitchListTile.adaptive(
            contentPadding: EdgeInsets.zero,
            title: Text(tr(context, 'Sblocco biometrico')),
            subtitle: Text(
              settings?.biometricsAvailable == true
                  ? widget.onBiometrics == null
                        ? tr(
                            context,
                            'Accedi al vault per attivarlo su questo dispositivo.',
                          )
                        : tr(
                            context,
                            'Usa l’impronta o il riconoscimento del viso sicuro configurato su Android.',
                          )
                  : tr(
                      context,
                      'Richiede Android 11 o successivo, biometria sicura e una chiave protetta dall’hardware.',
                    ),
            ),
            value: widget.biometricEnabled,
            onChanged:
                _busy ||
                    (settings?.biometricsAvailable != true &&
                        !widget.biometricEnabled) ||
                    widget.onBiometrics == null
                ? null
                : (value) => _run(() => widget.onBiometrics!(value)),
          ),
          const SizedBox(height: 16),
          Text(tr(context, 'Passkey dei siti e delle app')),
          const SizedBox(height: 8),
          Text(
            settings?.passkeysAvailable == true
                ? tr(
                    context,
                    'Abilita ByteLocker come gestore nelle impostazioni Android. Le passkey vengono create dal sito o dall’app e salvate nel vault.',
                  )
                : tr(
                    context,
                    'Il provider di passkey richiede Android 14 o successivo.',
                  ),
          ),
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: _busy || settings?.passkeysAvailable != true
                ? null
                : () => _run(settings!.native.providerSettings),
            icon: const Icon(Icons.key),
            label: Text(tr(context, 'Gestore passkey Android')),
          ),
          if (_message != null)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: Text(_message!),
            ),
          const SizedBox(height: 24),
          TextButton(
            onPressed: _busy ? null : widget.onClose,
            child: Text(tr(context, 'Torna indietro')),
          ),
        ],
      ),
    );
  }
}
