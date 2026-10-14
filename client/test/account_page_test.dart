import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';
import 'package:password_manager/vault/totp.dart';

import 'vault_fixtures.dart';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_page.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';

import 'fixtures.dart';

void main() {
  testWidgets(
    'account forms validate locally and fit narrow screens with large text',
    (tester) async {
      await tester.binding.setSurfaceSize(const Size(360, 780));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: const TextScaler.linear(2)),
            child: child!,
          ),
          home: AccountPage(
            linkedStore: const DisabledLinks(),
            address: ServerAddress.parse('https://vault.example.com'),
            config: ServerConfig.decode(configBytes()),
          ),
        ),
      );
      await tester.ensureVisible(find.text('Accedi e sblocca'));
      await tester.tap(find.text('Accedi e sblocca'));
      await tester.pumpAndSettle();
      expect(find.text('Inserisci un’email valida'), findsOneWidget);
      expect(find.text('Inserisci la Master Password'), findsOneWidget);
      await tester.ensureVisible(find.text('Prima volta? Crea un account'));
      await tester.tap(find.text('Prima volta? Crea un account'));
      await tester.pumpAndSettle();
      expect(find.text('Crea il tuo account'), findsOneWidget);
      expect(find.text('Conferma Master Password'), findsOneWidget);
      expect(find.text('Codice d’invito'), findsOneWidget);
      await tester.ensureVisible(find.text('Crea account'));
      await tester.tap(find.text('Crea account'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('server without registration exposes only login', (tester) async {
    final fixture = configFixture()..['registration_available'] = false;
    await tester.pumpWidget(
      MaterialApp(
        home: AccountPage(
          linkedStore: const DisabledLinks(),
          address: ServerAddress.parse('https://vault.example.com'),
          config: ServerConfig.decode(configBytes(fixture)),
        ),
      ),
    );
    expect(find.text('Accedi e sblocca'), findsOneWidget);
    expect(find.text('Prima volta? Crea un account'), findsNothing);
    for (final field in tester.widgetList<TextField>(find.byType(TextField))) {
      if (field.decoration?.labelText == 'Master Password') {
        expect(field.obscureText, isTrue);
        expect(field.enableSuggestions, isFalse);
        expect(field.autocorrect, isFalse);
      }
    }
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(find.textContaining('Vault bloccato.'), findsNothing);
    await tester.pump(const Duration(minutes: 5));
    expect(find.textContaining('Vault bloccato.'), findsOneWidget);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
  });
  testWidgets(
    'short focus changes preserve the editor; five minutes background clears secrets',
    (tester) async {
      final api = ReadyAccountApi();
      await tester.runAsync(() async {
        api.account = await api.originalLogin();
        final seed = VaultClient(api, api.account!);
        await seed.reload();
        await seed.save(
          VaultRecord(
            title: 'PRIVATE TITLE',
            password: 'PRIVATE PASSWORD',
            totp: Totp.parse('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
          ),
        );
        seed.dispose();
      });
      addTearDown(() => api.account?.lock());
      await tester.binding.setSurfaceSize(const Size(390, 844));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: AccountPage(
            linkedStore: const DisabledLinks(),
            address: ServerAddress.parse('https://vault.example.com'),
            config: vaultConfig(),
            client: api,
          ),
        ),
      );
      await tester.enterText(
        find.byType(TextFormField).at(0),
        'test@example.test',
      );
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'synthetic-password',
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Accedi e sblocca'));
      await tester.tap(find.text('Accedi e sblocca'));
      await tester.pumpAndSettle();
      expect(find.text('PRIVATE TITLE'), findsOneWidget);
      await tester.tap(find.text('PRIVATE TITLE'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('credential-details')), findsOneWidget);
      await tester.ensureVisible(find.byTooltip('Modifica credenziale'));
      await tester.tap(find.byTooltip('Modifica credenziale'));
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('record-Password')), findsOneWidget);
      expect(find.text('Codice 2FA'), findsOneWidget);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await tester.pumpAndSettle();
      expect(api.account!.locked, isFalse);
      await tester.pump(const Duration(minutes: 4));
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      expect(find.byKey(const ValueKey('record-Password')), findsOneWidget);
      expect(api.account!.locked, isFalse);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await tester.pump(const Duration(minutes: 4, seconds: 59));
      expect(api.account!.locked, isFalse);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      await tester.pump(const Duration(seconds: 1));
      expect(api.account!.locked, isTrue);
      // A hidden application does not render frames; the text is erased even
      // then, and the locked screen is rendered on the next visible frame.
      expect(
        tester
            .widget<TextFormField>(
              find.byKey(const ValueKey('record-Password')),
            )
            .controller!
            .text,
        isEmpty,
      );
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('record-Password')), findsNothing);
      expect(find.text('Codice 2FA'), findsNothing);
      expect(find.byKey(const ValueKey('record-Segreto 2FA')), findsNothing);
      expect(find.text('PRIVATE TITLE'), findsNothing);
      expect(find.text('Sblocca il vault'), findsOneWidget);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    },
  );
}

class ReadyAccountApi extends MemoryVaultApi {
  UnlockedAccount? account;
  Future<UnlockedAccount> originalLogin() =>
      super.login('test@example.test', 'Test-only master password 2026!');
  @override
  Future<UnlockedAccount> login(String email, String password) async =>
      account!;
}
