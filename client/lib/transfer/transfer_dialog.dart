import 'dart:typed_data';

import 'package:flutter/material.dart';

import '../l10n/app_strings.dart';
import '../account/account_client.dart';
import '../vault/vault_client.dart';
import '../vault/vault_record.dart';
import 'bitwarden_csv.dart';
import 'transfer_files.dart';

class TransferDialog extends StatefulWidget {
  const TransferDialog({
    super.key,
    required this.vault,
    required this.exporting,
    this.files = const TransferFiles(),
    this.onSessionExpired,
  });
  final VaultClient vault;
  final bool exporting;
  final TransferFiles files;
  final VoidCallback? onSessionExpired;
  @override
  State<TransferDialog> createState() => _TransferDialogState();
}

class _TransferDialogState extends State<TransferDialog> {
  ImportPlan? _plan;
  bool _busy = false, _finished = false;
  int _saved = 0;
  String? _message;
  bool get _active => mounted && widget.vault.active;
  @override
  void dispose() {
    _plan?.clear();
    _plan = null;
    super.dispose();
  }

  Future<void> _read() async {
    if (_busy || !widget.vault.ready) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    Uint8List? bytes;
    try {
      bytes = await widget.files.readCsv(
        isAllowed: () => _active && widget.vault.ready,
      );
      if (!_active || bytes == null) return;
      await widget.vault.reload();
      if (!_active) return;
      final plan = await planBitwardenCsv(
        bytes,
        widget.vault.entries,
        widget.vault.categories,
      );
      if (!_active) {
        plan.clear();
        return;
      }
      _plan?.clear();
      setState(() => _plan = plan);
    } catch (error) {
      if (error is AccountFailure && error.status == 401) {
        widget.onSessionExpired?.call();
        return;
      }
      if (_active)
        setState(
          () => _message = tr(
            context,
            error is TransferFailure
                ? 'File CSV non valido o troppo grande. Usa un export Bitwarden CSV UTF-8 (massimo 10 MB / 5000 voci).'
                : 'Connessione non riuscita. Controlla il server e riprova.',
          ),
        );
    } finally {
      bytes?.fillRange(0, bytes.length, 0);
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _import() async {
    final plan = _plan;
    if (_busy || plan == null || !widget.vault.ready || !_active) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      if (widget.vault.entries.length +
              widget.vault.categories.length +
              plan.items.length +
              plan.items
                  .map((e) => e.folder)
                  .where((f) => f.isNotEmpty)
                  .toSet()
                  .length >
          10000)
        throw const TransferFailure();
      final folders = {
        for (final e in widget.vault.categories)
          e.record.title.trim().toLowerCase(): e.id.wire,
      };
      for (final item in plan.items) {
        if (!_active) break;
        String? folder;
        if (item.folder.isNotEmpty) {
          final key = item.folder.trim().toLowerCase();
          folder = folders[key];
          if (folder == null) {
            await widget.vault.saveImported(
              VaultRecord(title: item.folder, isCategory: true),
            );
            if (!_active) return;
            folder = widget.vault.categories.last.id.wire;
            folders[key] = folder;
          }
        }
        await widget.vault.saveImported(
          item.record.withOrganization(categoryId: folder),
        );
        if (!_active) return;
        setState(() => _saved++);
      }
      if (!_active) return;
      await widget.vault.reload();
      if (_active) {
        plan.clear();
        setState(() => _finished = true);
      }
    } catch (error) {
      if (error is AccountFailure && error.status == 401) {
        widget.onSessionExpired?.call();
        return;
      }
      // Confirmed rows remain saved. Resolve an uncertain encrypted write before
      // re-reading the CSV; duplicate checks then make re-import safe.
      if (_active)
        setState(
          () => _message = tr(
            context,
            'Importazione interrotta. Le voci già confermate restano salvate. Chiudi, risolvi eventuali scritture in attesa e rileggi il CSV per saltare i duplicati.',
          ),
        );
      _plan?.clear();
      _plan = null;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _export() async {
    if (_busy || !widget.vault.ready || !_active) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    Uint8List? bytes;
    try {
      final destination = await widget.files.chooseExport();
      if (!_active || destination == null) return;
      bytes = exportBitwardenCsv(widget.vault.entries, widget.vault.categories);
      if (!_active) return;
      await widget.files.write(destination, bytes);
      if (_active) setState(() => _finished = true);
    } catch (_) {
      if (_active)
        setState(
          () => _message = tr(
            context,
            'Esportazione non completata. Controlla la destinazione e riprova.',
          ),
        );
    } finally {
      bytes?.fillRange(0, bytes.length, 0);
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final p = _plan;
    return PopScope(
      canPop: !_busy,
      child: AlertDialog(
        title: Text(
          tr(
            context,
            widget.exporting ? 'Esporta CSV' : 'Importa da Bitwarden',
          ),
        ),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  tr(
                    context,
                    widget.exporting
                        ? 'Il CSV contiene password e segreti 2FA in chiaro. Salvalo in un luogo privato. Non include passkey o allegati e non sostituisce il backup del server.'
                        : 'Il file viene letto sul dispositivo. Le nuove voci saranno cifrate prima di inviarle al tuo server. I duplicati esatti vengono saltati; nessuna voce esistente viene sostituita.',
                  ),
                ),
                const SizedBox(height: 12),
                if (p != null) ...[
                  Text('${tr(context, 'Da importare')}: ${p.items.length}'),
                  Text('${tr(context, 'Duplicati')}: ${p.duplicates}'),
                  Text('${tr(context, 'Non valide')}: ${p.invalid}'),
                  Text('${tr(context, 'Non supportate')}: ${p.unsupported}'),
                  if (p.customFields > 0)
                    Text(
                      tr(
                        context,
                        'I campi personalizzati vengono conservati nelle note.',
                      ),
                    ),
                  if (p.reprompt > 0)
                    Text(
                      tr(
                        context,
                        'Il blocco aggiuntivo per singola voce di Bitwarden non è supportato.',
                      ),
                    ),
                ],
                if (_saved > 0) Text('${tr(context, 'Voci salvate')}: $_saved'),
                if (_busy)
                  const Padding(
                    padding: EdgeInsets.only(top: 12),
                    child: LinearProgressIndicator(),
                  ),
                if (_message != null) Text(_message!),
                if (_finished) Text(tr(context, 'Operazione completata.')),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: _busy ? null : () => Navigator.of(context).pop('done'),
            child: Text(tr(context, 'Chiudi')),
          ),
          if (!_finished && !widget.exporting && p == null)
            FilledButton(
              onPressed: _busy ? null : _read,
              child: Text(tr(context, 'Scegli CSV')),
            ),
          if (!_finished && !widget.exporting && p != null)
            FilledButton(
              onPressed: _busy || p.items.isEmpty ? null : _import,
              child: Text(tr(context, 'Conferma importazione')),
            ),
          if (!_finished && widget.exporting)
            FilledButton(
              onPressed: _busy ? null : _export,
              child: Text(tr(context, 'Conferma esportazione')),
            ),
        ],
      ),
    );
  }
}
