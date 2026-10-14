import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_page.dart';
import 'package:password_manager/account/linked_account.dart';
import 'package:password_manager/app.dart';
import 'package:password_manager/connection/discovery_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';
import 'package:password_manager/settings/client_settings.dart';
import 'package:password_manager/vault/vault_page.dart';

import 'biometric_ui_test.dart' show PreparedApi;
import 'crypto_test.dart' show identity;
import 'fixtures.dart';
import 'settings_test.dart' show FakeSecurity;
import 'vault_fixtures.dart';

class MemoryLinks extends LinkedAccountStore {
  Map<Object?, Object?>? data;
  int writes = 0;
  @override
  bool get supported => true;
  @override
  Future<LinkedAccount?> load() async =>
      data == null ? null : LinkedAccount.decode(data!);
  @override
  Future<void> save(LinkedAccount value) async {
    data = value.encode();
    writes++;
  }
}

class LinkedDiscovery implements ServerDiscovery {
  ServerConfig config = vaultConfig();
  bool offline = false;
  int calls = 0;
  @override
  Future<ServerConfig> discover(ServerAddress address) async {
    calls++;
    if (offline) throw const DiscoveryException(DiscoveryFailure.unreachable);
    return config;
  }
}

LinkedAccount savedAccount() => LinkedAccount(
  address: ServerAddress.parse('https://vault.example.com'),
  serverId: identity().server.wire,
  accountId: identity().account.wire,
  vaultId: identity().vault.wire,
  email: 'test@example.test',
);

void main() {
  test('linked metadata contains only connection identity and rejects unexpected fields', () {
    final linked = savedAccount();
    expect(
      LinkedAccount.decode(linked.encode()).biometricSlot,
      linked.biometricSlot,
    );
    expect(linked.encode().keys.toSet(), {
      'schema',
      'origin',
      'server_id',
      'email',
      'account_id',
      'vault_id',
    });
    expect(
      () => LinkedAccount.decode({...linked.encode(), 'password': 'forbidden'}),
      throwsFormatException,
    );
    expect(
      () => LinkedAccount.decode({
        ...linked.encode(),
        'origin': 'http://evil.example',
      }),
      throwsFormatException,
    );
    expect(
      () => LinkedAccount.decode({...linked.encode(), 'server_id': 'invalid'}),
      throwsA(anything),
    );
    expect(
      () => LinkedAccount.decode({
        ...linked.encode(),
        'email': 'TEST@EXAMPLE.TEST',
      }),
      throwsFormatException,
    );
    expect(linked.toString(), 'LinkedAccount([REDACTED])');
  });

  testWidgets(
    'restart opens password-only unlock and detects saved biometric enrollment',
    (tester) async {
      final links = MemoryLinks();
      await links.save(savedAccount());
      final native = FakeSecurity()..enrolledValue = true;
      final settings = ClientSettings(native: native);
      final discovery = LinkedDiscovery();
      addTearDown(settings.dispose);
      await tester.pumpWidget(
        ByteLockerApp(
          settings: settings,
          discovery: discovery,
          linkedStore: links,
        ),
      );
      await tester.pumpAndSettle();
      expect(discovery.calls, 1);
      expect(find.text('Sblocca il vault'), findsOneWidget);
      expect(find.text('test@example.test'), findsOneWidget);
      expect(find.byType(TextFormField), findsOneWidget);
      expect(find.text('Sblocca con biometria'), findsOneWidget);
      expect(find.byKey(const Key('server-address')), findsNothing);
      expect(find.text('Prima volta? Crea un account'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets(
    'changed server identity is refused; reconnect keeps the saved address available',
    (tester) async {
      final links = MemoryLinks();
      await links.save(savedAccount());
      final discovery = LinkedDiscovery()
        ..config = ServerConfig.decode(configBytes());
      await tester.pumpWidget(
        ByteLockerApp(discovery: discovery, linkedStore: links),
      );
      await tester.pumpAndSettle();
      expect(find.byType(AccountPage), findsNothing);
      expect(find.textContaining('Non riesco a verificare'), findsOneWidget);
      expect(links.writes, 1);
      await tester.tap(find.text('Cambia server o account'));
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<TextFormField>(find.byKey(const Key('server-address')))
            .controller!
            .text,
        'https://vault.example.com',
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('offline startup preserves profile and retries successfully', (
    tester,
  ) async {
    final links = MemoryLinks();
    await links.save(savedAccount());
    final discovery = LinkedDiscovery()..offline = true;
    await tester.pumpWidget(
      ByteLockerApp(discovery: discovery, linkedStore: links),
    );
    await tester.pumpAndSettle();
    expect(find.byType(AccountPage), findsNothing);
    expect(links.data, isNotNull);
    discovery.offline = false;
    await tester.tap(find.text('Riprova'));
    await tester.pumpAndSettle();
    expect(find.text('Sblocca il vault'), findsOneWidget);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets(
    'successful login persists no secrets and biometric unlock works after recreating account page',
    (tester) async {
      final api = PreparedApi();
      await tester.runAsync(() async {
        api.prepared = await api.originalLogin();
      });
      final links = MemoryLinks();
      final native = FakeSecurity();
      final settings = ClientSettings(native: native);
      await settings.load();
      addTearDown(settings.dispose);
      await tester.pumpWidget(
        SettingsScope(
          settings: settings,
          child: MaterialApp(
            home: AccountPage(
              address: savedAccount().address,
              config: vaultConfig(),
              client: api,
              linkedStore: links,
            ),
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
      await tester.ensureVisible(find.text('Accedi e sblocca'));
      await tester.tap(find.text('Accedi e sblocca'));
      await tester.pumpAndSettle();
      expect(find.byType(VaultPage), findsOneWidget);
      expect(links.writes, 1);
      expect(jsonEncode(links.data), isNot(contains('synthetic-password')));
      expect((await links.load())!.matches(api.prepared!), isTrue);
      await tester.tap(find.byTooltip('Impostazioni'));
      await tester.pumpAndSettle();
      await tester.tap(find.byType(SwitchListTile));
      await tester.pumpAndSettle();
      expect(native.enrolledValue, isTrue);
      await tester.pumpWidget(const SizedBox());
      expect(api.prepared!.locked, isTrue);
      final restored = await links.load();
      await tester.pumpWidget(
        SettingsScope(
          settings: settings,
          child: MaterialApp(
            home: AccountPage(
              address: restored!.address,
              config: vaultConfig(),
              linked: restored,
              client: api,
              linkedStore: links,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byType(TextFormField), findsOneWidget);
      await tester.tap(find.text('Sblocca con biometria'));
      await tester.pumpAndSettle();
      expect(api.biometricCalls, 1);
      expect(find.byType(VaultPage), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
      await native.remove('synthetic');
    },
  );
}
