import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_page.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

void main() {
  for (final width in [390.0, 1280.0]) {
    testWidgets('categories, favorites and masked copy work at $width', (
      tester,
    ) async {
      final calls = <MethodCall>[];
      const channel = MethodChannel('bytelocker/clipboard');
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (
        call,
      ) async {
        calls.add(call);
        return null;
      });
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          channel,
          null,
        ),
      );
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
            title: 'GitHub personale',
            email: 'alice@example.test',
            password: 'copy-this-secret',
            url: 'https://github.com',
            tags: ['sviluppo'],
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
          home: VaultPage(vault: vault, onLogout: () async {}),
        ),
      );
      await tester.pumpAndSettle();
      Future<void> menu() async {
        if (width < 1050) {
          await tester.tap(find.byTooltip('Categorie e preferiti'));
          await tester.pumpAndSettle();
        }
      }

      await menu();
      await tester.tap(find.byTooltip('Nuova categoria'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const ValueKey('category-name')),
        'Lavoro',
      );
      await tester.tap(find.text('Salva categoria'));
      await tester.pumpAndSettle();
      expect(vault.categories.single.record.title, 'Lavoro');
      expect(find.text('GitHub personale'), findsNothing);
      await menu();
      await tester.tap(find.text('Tutti i login'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('GitHub personale'));
      await tester.pumpAndSettle();
      for (final field in ['email', 'password']) {
        await tester.ensureVisible(find.byTooltip('Copia $field'));
        await tester.tap(find.byTooltip('Copia $field'));
        await tester.pumpAndSettle();
      }
      expect(calls.where((c) => c.method == 'copy').map((c) => c.arguments), [
        'alice@example.test',
        'copy-this-secret',
      ]);
      expect(find.text('copy-this-secret'), findsNothing);
      await tester.ensureVisible(find.byTooltip('Aggiungi ai preferiti'));
      await tester.tap(find.byTooltip('Aggiungi ai preferiti'));
      await tester.pumpAndSettle();
      expect(vault.entries.single.record.favorite, isTrue);
      await tester.tap(find.byTooltip('Modifica credenziale'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byTooltip('Scegli il logo'));
      await tester.tap(find.byTooltip('Scegli il logo'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.widgetWithText(TextField, 'Cerca un servizio'),
        'Airbnb',
      );
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(ListTile, 'Airbnb'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byType(DropdownButtonFormField<String>));
      await tester.tap(find.byType(DropdownButtonFormField<String>));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Lavoro').last);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Salva credenziale'));
      await tester.tap(find.text('Salva credenziale'));
      await tester.pumpAndSettle();
      expect(
        vault.entries.single.record.categoryId,
        vault.categories.single.id.wire,
      );
      expect(vault.entries.single.record.favorite, isTrue);
      expect(vault.entries.single.record.logo, 'airbnb');
      await menu();
      await tester.tap(find.text('Preferiti').first);
      await tester.pumpAndSettle();
      expect(find.text('GitHub personale'), findsOneWidget);
      await menu();
      await tester.tap(find.byTooltip('Nuova categoria'));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const ValueKey('category-name')),
        'Unsaved private category',
      );
      vault.dispose();
      vault.account.lock();
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
      expect(calls.any((c) => c.method == 'clear'), isTrue);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    });
  }
}
