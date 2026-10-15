import '../l10n/app_strings.dart';

import 'dart:async';

import 'package:flutter/material.dart';

import 'totp.dart';
import 'sensitive_clipboard.dart';

class TotpCode extends StatefulWidget {
  const TotpCode({super.key, required this.input, this.now = DateTime.now});
  final String input;
  final DateTime Function() now;
  @override
  State<TotpCode> createState() => _TotpCodeState();
}

class _TotpCodeState extends State<TotpCode> {
  Timer? _timer;
  String? _code;
  int? _counter;
  int _remaining = 30, _revision = 0;
  bool _invalid = false;

  Future<void> _copy() async {
    // Recompute at the tap so a just-expired displayed code is never copied.
    final revision = _revision;
    try {
      final time = widget.now();
      final code = await Totp.parse(widget.input).codeAt(time);
      if (!mounted || revision != _revision) return;
      if (widget.now().millisecondsSinceEpoch ~/ 30000 !=
          time.millisecondsSinceEpoch ~/ 30000) {
        await _tick();
        return;
      }
      await SensitiveClipboard.copy(code);
      if (!mounted || revision != _revision) return;
      ScaffoldMessenger.of(context).hideCurrentSnackBar();
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(tr(context, 'Codice 2FA copiato')),
          duration: Duration(seconds: 2),
        ),
      );
    } catch (_) {
      if (mounted)
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              tr(context, 'Impossibile copiare il codice 2FA. Riprova.'),
            ),
          ),
        );
    }
  }

  @override
  void initState() {
    super.initState();
    _tick();
    _schedule();
  }

  void _schedule() {
    _timer?.cancel();
    if (widget.input.trim().isNotEmpty) {
      _timer = Timer.periodic(const Duration(seconds: 1), (_) => _tick());
    }
  }

  @override
  void didUpdateWidget(TotpCode oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.input != widget.input) {
      _revision++;
      _counter = null;
      _code = null;
      _schedule();
      _tick();
    }
  }

  Future<void> _tick() async {
    final time = widget.now();
    final seconds = time.millisecondsSinceEpoch ~/ 1000;
    final counter = seconds ~/ 30;
    if (_counter == counter) {
      if (mounted) setState(() => _remaining = 30 - seconds % 30);
      return;
    }
    final revision = ++_revision;
    setState(() {
      _counter = counter;
      _code = null;
      _invalid = false;
      _remaining = 30 - seconds % 30;
    });
    if (widget.input.trim().isEmpty) return;
    try {
      final code = await Totp.parse(widget.input).codeAt(time);
      if (!mounted || revision != _revision) return;
      // Never publish a result computed for a time step that has expired.
      if (widget.now().millisecondsSinceEpoch ~/ 30000 != counter) {
        _counter = null;
        unawaited(_tick());
        return;
      }
      setState(() => _code = code);
    } catch (_) {
      if (mounted && revision == _revision) setState(() => _invalid = true);
    }
  }

  @override
  void dispose() {
    _revision++;
    _timer?.cancel();
    _code = null;
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.input.trim().isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 24),
      child: _invalid
          ? Text(
              tr(
                context,
                'Configurazione 2FA non valida. Usa TOTP SHA-1, 6 cifre e 30 secondi.',
              ),
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(tr(context, 'Codice 2FA')),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        _code ?? '······',
                        style: Theme.of(context).textTheme.headlineMedium,
                      ),
                    ),
                    IconButton(
                      tooltip: tr(context, 'Copia codice 2FA'),
                      onPressed: _code == null ? null : _copy,
                      icon: const Icon(Icons.copy_rounded),
                    ),
                  ],
                ),
                Text(AppStrings.of(context).nextCode(_remaining)),
                Text(
                  tr(
                    context,
                    'Mantieni data e ora automatiche sul dispositivo.',
                  ),
                ),
              ],
            ),
    );
  }
}
