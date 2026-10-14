import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_page.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';
import 'passkey_test.dart' show syntheticPasskey;

void main() {
  for (final width in [360.0, 1280.0]) {
    testWidgets('credential details are read-only and fit at width $width', (
      tester,
    ) async {
      final api = MemoryVaultApi();
      late VaultClient vault;
      await tester.runAsync(() async {
        final account = await api.login(
          'test@example.test',
          'Test-only master password 2026!',
        );
        vault = VaultClient(api, account);
        await vault.reload();
        await vault.save(
          VaultRecord(
            title: 'Read-only account',
            username: 'alice',
            email: 'alice@example.test',
            password: 'never-show-automatically',
            url: 'https://example.test',
            notes: 'Personal notes',
            tags: ['friends'],
          ),
        );
      });
      addTearDown(() {
        vault.dispose();
        vault.account.lock();
      });
      await tester.binding.setSurfaceSize(Size(width, 900));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(width == 360 ? 2 : 1)),
            child: child!,
          ),
          home: VaultPage(vault: vault, onLogout: () async {}),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Read-only account'));
      await tester.tap(find.text('Read-only account'));
      await tester.pumpAndSettle();
      expect(find.byType(TextFormField), findsNothing);
      expect(find.text('never-show-automatically'), findsNothing);
      expect(find.text('alice@example.test'), findsOneWidget);
      expect(find.text('Personal notes'), findsOneWidget);
      expect(find.text('Salva credenziale'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(find.byTooltip('Modifica credenziale'));
      await tester.tap(find.byTooltip('Modifica credenziale'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('record-Titolo')), findsOneWidget);
      expect(vault.entries.single.record.title, 'Read-only account');
      await tester.pumpWidget(const SizedBox());
    });
  }
  testWidgets(
    'search, edit, save, reveal password and delete require deliberate actions',
    (tester) async {
      final api = MemoryVaultApi();
      late VaultClient vault;
      await tester.runAsync(() async {
        final account = await api.login(
          'test@example.test',
          'Test-only master password 2026!',
        );
        vault = VaultClient(api, account);
        await vault.reload();
        await vault.save(
          VaultRecord(
            title: 'My mail',
            username: 'alice',
            password: 'hidden-value',
            passkey: syntheticPasskey(),
          ),
        );
      });
      addTearDown(() {
        vault.dispose();
        vault.account.lock();
      });
      await tester.binding.setSurfaceSize(const Size(390, 844));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: VaultPage(
            vault: vault,
            onLogout: () async {
              vault.account.lock();
            },
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('My mail'), findsOneWidget);
      expect(find.text('hidden-value'), findsNothing);
      await tester.enterText(find.byType(TextField).first, 'missing');
      await tester.pumpAndSettle();
      expect(find.text('Nessuna credenziale trovata.'), findsOneWidget);
      await tester.enterText(find.byType(TextField).first, '');
      await tester.pumpAndSettle();
      await tester.tap(find.text('My mail'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('credential-details')), findsOneWidget);
      expect(find.byType(TextFormField), findsNothing);
      expect(find.text('Salva credenziale'), findsNothing);
      final detailPassword = find.byKey(const ValueKey('detail-password'));
      expect(tester.widget<SelectableText>(detailPassword).data, '••••••••');
      await tester.ensureVisible(find.byTooltip('Mostra password'));
      await tester.tap(find.byTooltip('Mostra password'));
      await tester.pump();
      expect(
        tester.widget<SelectableText>(detailPassword).data,
        'hidden-value',
      );
      expect(vault.entries.single.record.title, 'My mail');
      await tester.ensureVisible(find.text('Torna al vault'));
      await tester.tap(find.text('Torna al vault'));
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Modifica credenziale'));
      await tester.pumpAndSettle();
      final password = find.byKey(const ValueKey('record-Password'));
      final passwordField = find.descendant(
        of: password,
        matching: find.byType(TextField),
      );
      expect(tester.widget<TextField>(passwordField).obscureText, isTrue);
      await tester.ensureVisible(find.byTooltip('Mostra password'));
      await tester.tap(find.byTooltip('Mostra password'));
      await tester.pump();
      expect(tester.widget<TextField>(passwordField).obscureText, isFalse);
      await tester.enterText(
        find.byKey(const ValueKey('record-Titolo')),
        'New title',
      );
      final totpField = find.byKey(const ValueKey('record-Segreto 2FA'));
      await tester.ensureVisible(totpField);
      await tester.enterText(totpField, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
      await tester.pumpAndSettle();
      expect(find.text('Codice 2FA'), findsOneWidget);
      expect(
        tester
            .widget<TextField>(
              find.descendant(of: totpField, matching: find.byType(TextField)),
            )
            .obscureText,
        isTrue,
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Salva credenziale'));
      await tester.tap(find.text('Salva credenziale'));
      await tester.pumpAndSettle();
      expect(find.text('New title'), findsOneWidget);
      expect(vault.entries.single.record.title, 'New title');
      expect(
        vault.entries.single.record.passkey!.credentialId,
        syntheticPasskey().credentialId,
      );
      expect(
        vault.entries.single.record.totp!.secret,
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      );
      await tester.tap(find.text('New title'));
      await tester.pumpAndSettle();
      expect(find.text('Codice 2FA'), findsOneWidget);
      expect(find.byType(TextFormField), findsNothing);
      await tester.ensureVisible(find.byTooltip('Modifica credenziale'));
      await tester.tap(find.byTooltip('Modifica credenziale'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Elimina credenziale'));
      await tester.tap(find.text('Elimina credenziale'));
      await tester.pumpAndSettle();
      expect(vault.entries.length, 1);
      await tester.ensureVisible(find.text('Conferma eliminazione'));
      await tester.tap(find.text('Conferma eliminazione'));
      await tester.pumpAndSettle();
      expect(vault.entries, isEmpty);
      expect(
        find.text('Il vault è vuoto. Aggiungi la tua prima credenziale.'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'editor fits large text on a narrow screen and blocks empty titles',
    (tester) async {
      final api = MemoryVaultApi();
      late VaultClient vault;
      await tester.runAsync(() async {
        final account = await api.login(
          'test@example.test',
          'Test-only master password 2026!',
        );
        vault = VaultClient(api, account);
      });
      addTearDown(() {
        vault.dispose();
        vault.account.lock();
      });
      await tester.binding.setSurfaceSize(const Size(360, 780));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: const TextScaler.linear(2)),
            child: child!,
          ),
          home: VaultPage(vault: vault, onLogout: () async {}),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Nuova credenziale'));
      await tester.tap(find.text('Nuova credenziale'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Salva credenziale'));
      await tester.tap(find.text('Salva credenziale'));
      await tester.pumpAndSettle();
      expect(find.text('Inserisci un titolo'), findsOneWidget);
      expect(api.objects, isEmpty);
      expect(tester.takeException(), isNull);
    },
  );
}
