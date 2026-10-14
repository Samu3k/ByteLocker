import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/crypto/pm1.dart';
import 'package:password_manager/vault/passkey.dart';
import 'package:password_manager/vault/passkey_panel.dart';
import 'package:password_manager/vault/totp.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

VaultPasskey syntheticPasskey() => VaultPasskey.decode(
  jsonDecode(File('test/fixtures/passkey.json').readAsStringSync()),
);
PasskeyRequest request({bool create = true, List<String> allowed = const []}) =>
    PasskeyRequest({
      'request_id': 'synthetic-request',
      'operation': create ? 'create' : 'get',
      'rp_id': 'example.com',
      'user_name': 'alice',
      'display_name': 'Alice',
      'allowed_ids': allowed,
    });

class FakePasskeys extends NativePasskeyClient {
  int creations = 0, completions = 0, signatures = 0;
  @override
  Future<VaultPasskey> create(
    PasskeyRequest request,
    List<String> existing,
  ) async {
    creations++;
    return syntheticPasskey();
  }

  @override
  Future<void> complete(PasskeyRequest request) async {
    completions++;
  }

  @override
  Future<void> sign(PasskeyRequest request, VaultPasskey key) async {
    expect(key.rpId, request.rpId);
    signatures++;
  }
}

void main() {
  test('schema 3 preserves existing fields, TOTP and a redacted passkey', () {
    final key = syntheticPasskey();
    final record = VaultRecord(
      title: 'Example',
      password: 'kept-password',
      notes: 'kept-notes',
      tags: ['kept-tag'],
      totp: Totp.parse('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
    ).withPasskey(key);
    final restored = VaultRecord.decode(record.encode())!;
    expect(restored.passkey!.credentialId, key.credentialId);
    expect(restored.passkey!.privateKey, key.privateKey);
    expect(restored.password, 'kept-password');
    expect(restored.totp!.secret, record.totp!.secret);
    expect(
      VaultRecord.decode(record.withPasskey(null).encode())!.passkey,
      isNull,
    );
    expect(record.matches(key.privateKey), isFalse);
    expect(record.toString(), isNot(contains(key.privateKey)));
    expect(key.toString(), isNot(contains(key.privateKey)));
    final corrupted = key.encode()..['algorithm'] = -8;
    expect(() => VaultPasskey.decode(corrupted), throwsA(isA<CryptoFailure>()));
    expect(
      VaultRecord.decode(VaultRecord(title: 'No TOTP', passkey: key).encode())!
          .totp,
      isNull,
    );
  });

  testWidgets(
    'lost response retries same ciphertext and returns passkey only after confirmed commit',
    (tester) async {
      final api = MemoryVaultApi();
      late VaultClient vault;
      await tester.runAsync(() async {
        vault = VaultClient(
          api,
          await api.login(
            'test@example.test',
            'Test-only master password 2026!',
          ),
        );
        await vault.reload();
      });
      addTearDown(() {
        vault.dispose();
        vault.account.lock();
      });
      final native = FakePasskeys();
      api.loseResponse = true;
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: PasskeyPanel(
                request: request(),
                vault: vault,
                native: native,
                onComplete: () {},
              ),
            ),
          ),
        ),
      );
      await tester.tap(find.text('Conferma e salva passkey'));
      await tester.pumpAndSettle();
      expect(native.creations, 1);
      expect(native.completions, 0);
      expect(vault.hasPendingWrite, isTrue);
      await tester.tap(find.text('Riprendi salvataggio passkey'));
      await tester.pumpAndSettle();
      expect(native.creations, 1);
      expect(native.completions, 1);
      expect(
        vault.entries.single.record.passkey!.credentialId,
        syntheticPasskey().credentialId,
      );
      expect(api.serializedWrites[0], api.serializedWrites[1]);
      expect(
        api.serializedWrites.join(),
        isNot(contains(syntheticPasskey().privateKey)),
      );
      await tester.pumpWidget(const SizedBox());
    },
  );

  testWidgets('assertion selector filters by RP and allowed credential ID', (
    tester,
  ) async {
    final api = MemoryVaultApi();
    late VaultClient vault;
    await tester.runAsync(() async {
      vault = VaultClient(
        api,
        await api.login('test@example.test', 'Test-only master password 2026!'),
      );
      await vault.reload();
      await vault.save(
        VaultRecord(title: 'Alice passkey', passkey: syntheticPasskey()),
      );
      final another = syntheticPasskey().encode()
        ..['rp_id'] = 'another.example';
      await vault.save(
        VaultRecord(
          title: 'Other service',
          passkey: VaultPasskey.decode(another),
        ),
      );
    });
    addTearDown(() {
      vault.dispose();
      vault.account.lock();
    });
    final native = FakePasskeys();
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: PasskeyPanel(
            request: request(
              create: false,
              allowed: [syntheticPasskey().credentialId],
            ),
            vault: vault,
            native: native,
            onComplete: () {},
          ),
        ),
      ),
    );
    expect(find.text('Alice passkey'), findsOneWidget);
    expect(find.text('Other service'), findsNothing);
    await tester.tap(find.text('Alice passkey'));
    await tester.pumpAndSettle();
    expect(native.signatures, 1);
    expect(native.completions, 1);
    await tester.pumpWidget(const SizedBox());
  });
}
