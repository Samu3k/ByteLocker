import 'package:flutter/material.dart';

import '../l10n/app_strings.dart';
import 'update_controller.dart';

class UpdateOverlay extends StatelessWidget {
  const UpdateOverlay({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) {
    final updates = UpdateScope.maybeOf(context);
    final available = updates?.available;
    return Stack(
      children: [
        ExcludeFocus(
          excluding: updates?.installing == true,
          child: AbsorbPointer(
            absorbing: updates?.installing == true,
            child: child,
          ),
        ),
        if (updates?.installing == true)
          const ModalBarrier(dismissible: false, color: Colors.black38),
        if (updates != null && (available != null || updates.message != null))
          Positioned(
            top: 12,
            right: 12,
            child: SafeArea(
              child: SizedBox(
                width: MediaQuery.sizeOf(context).width < 440
                    ? MediaQuery.sizeOf(context).width - 24
                    : 400,
                child: Material(
                  elevation: 8,
                  borderRadius: BorderRadius.circular(16),
                  color: Theme.of(context).colorScheme.surfaceContainerHigh,
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (available != null)
                          Text(
                            '${tr(context, 'Aggiornamento disponibile')}: ${available.version}',
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                        if (updates.message != null)
                          Text(tr(context, updates.message!)),
                        if (updates.installing) const LinearProgressIndicator(),
                        Wrap(
                          alignment: WrapAlignment.end,
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            TextButton(
                              onPressed: updates.installing
                                  ? null
                                  : updates.dismiss,
                              child: Text(tr(context, 'Più tardi')),
                            ),
                            if (available != null)
                              FilledButton(
                                onPressed: updates.installing
                                    ? null
                                    : updates.install,
                                child: Text(
                                  tr(
                                    context,
                                    updates.automaticRestart
                                        ? 'Aggiorna e riavvia'
                                        : 'Installa aggiornamento',
                                  ),
                                ),
                              ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}
