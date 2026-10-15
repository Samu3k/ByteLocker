import '../l10n/app_strings.dart';
import '../brand.dart';

import 'dart:async';

import 'package:flutter/material.dart';

import '../account/account_page.dart';
import '../account/linked_account.dart';
import '../app.dart' show ServerConnectionPage;
import 'discovery_client.dart';
import 'server_config.dart';

class ConnectionGate extends StatefulWidget {
  const ConnectionGate({
    super.key,
    required this.discovery,
    required this.store,
    this.allowLocalHttp = false,
  });
  final ServerDiscovery discovery;
  final LinkedAccountStore store;
  final bool allowLocalHttp;
  @override
  State<ConnectionGate> createState() => _ConnectionGateState();
}

class _ConnectionGateState extends State<ConnectionGate> {
  LinkedAccount? _linked;
  ServerConfig? _config;
  bool _loading = false, _manual = false;
  String? _error;
  @override
  void initState() {
    super.initState();
    if (widget.store.supported) {
      _loading = true;
      unawaited(_restore());
    }
  }

  Future<void> _restore() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final linked = await widget.store.load();
      if (!mounted) return;
      _linked = linked;
      if (linked != null) {
        final config = await widget.discovery.discover(linked.address);
        if (config.serverId != linked.serverId) {
          throw const FormatException('Server identity changed');
        }
        if (!mounted) return;
        _config = config;
      }
    } catch (_) {
      if (mounted)
        _error = tr(
          context,
          'Non riesco a verificare il server salvato. Controlla la connessione oppure aggiorna l’indirizzo del server.',
        );
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _change() => setState(() {
    _manual = true;
    _error = null;
  });
  @override
  Widget build(BuildContext context) {
    if (_loading)
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    if (_manual || (_linked == null && _error == null)) {
      return ServerConnectionPage(
        discovery: widget.discovery,
        allowLocalHttp: widget.allowLocalHttp,
        linkedStore: widget.store,
        initialAddress: _linked?.address.origin.toString(),
      );
    }
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(title: const ByteLockerTitle()),
        body: SafeArea(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(_error!),
                  const SizedBox(height: 24),
                  FilledButton(
                    onPressed: _restore,
                    child: Text(tr(context, 'Riprova')),
                  ),
                  TextButton(
                    onPressed: _change,
                    child: Text(tr(context, 'Cambia server o account')),
                  ),
                ],
              ),
            ),
          ),
        ),
      );
    }
    return AccountPage(
      address: _linked!.address,
      config: _config!,
      linked: _linked,
      linkedStore: widget.store,
      onChangeConnection: _change,
    );
  }
}
