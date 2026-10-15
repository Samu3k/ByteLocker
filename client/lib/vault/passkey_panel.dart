import '../l10n/app_strings.dart';

import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../connection/strict_json.dart';
import 'passkey.dart';
import 'vault_client.dart';
import 'vault_record.dart';

class PasskeyRequest {
  PasskeyRequest(Map<Object?, Object?> value)
    : id = value['request_id'] as String,
      create = value['operation'] == 'create',
      rpId = value['rp_id'] as String,
      userName = value['user_name'] as String,
      displayName = value['display_name'] as String,
      allowed = List<String>.from(value['allowed_ids'] as List);
  final String id, rpId, userName, displayName;
  final bool create;
  final List<String> allowed;
  @override
  String toString() => 'PasskeyRequest([REDACTED])';
}

class NativePasskeyClient {
  static const channel = MethodChannel('bytelocker/passkeys');
  Future<PasskeyRequest?> pending() async {
    if (!Platform.isAndroid) return null;
    try {
      final value = await channel.invokeMapMethod<Object?, Object?>('pending');
      return value == null ? null : PasskeyRequest(value);
    } on MissingPluginException {
      return null;
    }
  }

  Future<void> verified(PasskeyRequest request) =>
      channel.invokeMethod('verified', {'request_id': request.id});
  Future<VaultPasskey> create(
    PasskeyRequest request,
    List<String> existing,
  ) async {
    final raw = await channel.invokeMethod<String>('create', {
      'request_id': request.id,
      'existing_ids': existing,
    });
    if (raw == null) throw const FormatException('Missing passkey');
    return VaultPasskey.decode(
      decodeStrictJson(utf8.encode(raw), maxBytes: 4096),
    );
  }

  Future<void> sign(PasskeyRequest request, VaultPasskey key) =>
      channel.invokeMethod('sign', {
        'request_id': request.id,
        'material': jsonEncode(key.encode()),
      });
  Future<void> complete(PasskeyRequest request) =>
      channel.invokeMethod('complete', {'request_id': request.id});
  Future<void> cancel() => channel.invokeMethod('cancel');
}

class PasskeyPanel extends StatefulWidget {
  const PasskeyPanel({
    super.key,
    required this.request,
    required this.vault,
    required this.onComplete,
    this.native,
  });
  final PasskeyRequest request;
  final VaultClient vault;
  final VoidCallback onComplete;
  final NativePasskeyClient? native;
  @override
  State<PasskeyPanel> createState() => _PasskeyPanelState();
}

class _PasskeyPanelState extends State<PasskeyPanel> {
  String _selected = '';
  bool _busy = false;
  String? _message;
  VaultRecord? _generated;
  VaultEntry? _replacing;
  NativePasskeyClient get _native => widget.native ?? NativePasskeyClient();
  List<VaultEntry> get _matching => widget.vault.entries.where((entry) {
    final key = entry.record.passkey;
    return key != null &&
        key.rpId == widget.request.rpId &&
        (widget.request.allowed.isEmpty ||
            widget.request.allowed.contains(key.credentialId));
  }).toList();

  Future<void> _run(Future<void> Function() action) async {
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await action();
    } catch (_) {
      if (mounted)
        setState(
          () => _message = tr(
            context,
            'Operazione non completata. Puoi riprovare. La passkey viene restituita al sito solo dopo il salvataggio confermato.',
          ),
        );
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _create() async {
    if (_generated == null) {
      final key = await _native.create(
        widget.request,
        widget.vault.entries
            .map((entry) => entry.record.passkey?.credentialId)
            .whereType<String>()
            .toList(),
      );
      if (!mounted || widget.vault.account.locked) return;
      if (_selected.isNotEmpty)
        _replacing = widget.vault.entries.firstWhere(
          (entry) => entry.id.wire == _selected,
        );
      final base =
          _replacing?.record ??
          VaultRecord(
            title: String.fromCharCodes(
              '${widget.request.rpId} (${widget.request.userName})'.runes.take(
                200,
              ),
            ),
            username: widget.request.userName,
            url: 'https://${widget.request.rpId}',
          );
      _generated = base.withPasskey(key);
    }
    if (widget.vault.hasPendingWrite) await widget.vault.retryPending();
    if (!widget.vault.ready) await widget.vault.reload();
    final saved = widget.vault.entries.any(
      (entry) =>
          entry.record.passkey?.credentialId ==
          _generated!.passkey!.credentialId,
    );
    if (!saved) await widget.vault.save(_generated!, replacing: _replacing);
    if (!mounted || widget.vault.account.locked) return;
    if (!widget.vault.entries.any(
      (entry) =>
          entry.record.passkey?.credentialId ==
          _generated!.passkey!.credentialId,
    ))
      throw StateError('Unconfirmed passkey');
    await _native.complete(widget.request);
    if (mounted) widget.onComplete();
  }

  Future<void> _sign(VaultEntry entry) async {
    await _native.sign(widget.request, entry.record.passkey!);
    if (!mounted || widget.vault.account.locked) return;
    await _native.complete(widget.request);
    if (mounted) widget.onComplete();
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      const Icon(Icons.key, size: 44),
      const SizedBox(height: 16),
      Text(
        widget.request.create
            ? tr(context, 'Salva una passkey')
            : tr(context, 'Accedi con una passkey'),
        style: Theme.of(context).textTheme.headlineSmall,
      ),
      const SizedBox(height: 12),
      Text(widget.request.rpId, style: Theme.of(context).textTheme.titleLarge),
      const SizedBox(height: 8),
      if (widget.request.create) ...[
        Text(widget.request.userName),
        const SizedBox(height: 24),
        DropdownButtonFormField<String>(
          initialValue: '',
          isExpanded: true,
          decoration: InputDecoration(
            labelText: tr(context, 'Salva nella credenziale'),
          ),
          items: [
            DropdownMenuItem(
              value: '',
              child: Text(tr(context, 'Nuova credenziale')),
            ),
            for (final entry in widget.vault.entries.where(
              (entry) => entry.record.passkey == null,
            ))
              DropdownMenuItem(
                value: entry.id.wire,
                child: Text(
                  entry.record.title,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: _busy || _generated != null
              ? null
              : (value) => setState(() => _selected = value ?? ''),
        ),
        const SizedBox(height: 20),
        FilledButton(
          onPressed: _busy ? null : () => _run(_create),
          child: Text(
            _generated == null
                ? tr(context, 'Conferma e salva passkey')
                : tr(context, 'Riprendi salvataggio passkey'),
          ),
        ),
      ] else ...[
        const SizedBox(height: 24),
        if (_matching.isEmpty)
          Text(
            tr(context, 'Nessuna passkey compatibile trovata in questo vault.'),
          ),
        for (final entry in _matching)
          Card(
            child: ListTile(
              title: Text(entry.record.title),
              subtitle: Text(entry.record.passkey!.userName),
              trailing: const Icon(Icons.key),
              onTap: _busy ? null : () => _run(() => _sign(entry)),
            ),
          ),
      ],
      if (_message != null)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Text(_message!),
        ),
      TextButton(
        onPressed: _busy
            ? null
            : () => _run(() async {
                await _native.cancel();
                if (mounted) widget.onComplete();
              }),
        child: Text(tr(context, 'Annulla richiesta')),
      ),
    ],
  );
}
