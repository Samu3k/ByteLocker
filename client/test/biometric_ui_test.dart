import 'fixtures.dart';

import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/account/account_page.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/settings/client_settings.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_page.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'settings_test.dart' show FakeSecurity;
import 'vault_fixtures.dart';

class PreparedApi extends MemoryVaultApi {
  UnlockedAccount? prepared;
  int biometricCalls = 0;
  Future<UnlockedAccount> originalLogin() =>
      super.login('test@example.test', 'Test-only master password 2026!');
  @override
  Future<UnlockedAccount> login(String email, String password) async =>
      prepared!;
  @override
  Future<UnlockedAccount> biometricLogin(String email, Uint8List payload) {
    biometricCalls++;
    return super.biometricLogin(email, payload);
  }
}

class DelayedSecurity extends FakeSecurity {
  final pendingUnlock = Completer<Uint8List?>();
  @override
  Future<Uint8List?> unlock(String slot) => pendingUnlock.future;
}

Widget accountPage(PreparedApi api, ClientSettings settings) => SettingsScope(
  settings: settings,
  child: MaterialApp(
    home: AccountPage(
      linkedStore: const DisabledLinks(),
      address: ServerAddress.parse('https://vault.example.com'),
      config: vaultConfig(),
      client: api,
    ),
  ),
);

void main() {
  testWidgets(
    'enroll from settings, lock on background and restore with protected payload',
    (tester) async {
      final api = PreparedApi();
      final native = FakeSecurity();
      final settings = ClientSettings(native: native);
      await settings.load();
      await tester.runAsync(() async {
        api.prepared = await api.originalLogin();
        final vault = VaultClient(api, api.prepared!);
        await vault.reload();
        await vault.save(VaultRecord(title: 'Private credential'));
        vault.dispose();
      });
      addTearDown(() {
        settings.dispose();
        api.prepared?.lock();
      });
      await tester.binding.setSurfaceSize(const Size(390, 844));
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(accountPage(api, settings));
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
      await tester.tap(find.byTooltip('Impostazioni'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byType(SwitchListTile));
      await tester.tap(find.byType(SwitchListTile));
      await tester.pumpAndSettle();
      expect(native.enrolledValue, isTrue);
      expect(
        tester.widget<SwitchListTile>(find.byType(SwitchListTile)).value,
        isTrue,
      );
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      await tester.pumpAndSettle();
      expect(api.prepared!.locked, isFalse);
      await tester.pump(const Duration(minutes: 5));
      expect(api.prepared!.locked, isTrue);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      expect(find.byType(VaultPage), findsNothing);
      await tester.ensureVisible(find.text('Sblocca con biometria'));
      await tester.tap(find.text('Sblocca con biometria'));
      await tester.pumpAndSettle();
      expect(api.biometricCalls, 1);
      expect(find.text('Private credential'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      await native.remove('synthetic');
    },
  );

  testWidgets(
    'late biometric completion after background cannot unlock the vault',
    (tester) async {
      final api = PreparedApi();
      final native = DelayedSecurity();
      final settings = ClientSettings(native: native);
      await settings.load();
      late Uint8List payload;
      await tester.runAsync(() async {
        final account = await api.originalLogin();
        payload = api.biometricPayload(account);
        account.lock();
      });
      addTearDown(settings.dispose);
      await tester.pumpWidget(accountPage(api, settings));
      await tester.enterText(
        find.byType(TextFormField).at(0),
        'test@example.test',
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Sblocca con biometria'));
      await tester.tap(find.text('Sblocca con biometria'));
      await tester.pump();
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
      await tester.pump();
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump();
      native.pendingUnlock.complete(payload);
      await tester.pumpAndSettle();
      expect(api.biometricCalls, 0);
      expect(find.byType(VaultPage), findsNothing);
      expect(payload.every((byte) => byte == 0), isTrue);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
