import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/crypto/pm1.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

void main() {
  test(
    'record schema, size limits, tombstones and redacted representation',
    () {
      final record = VaultRecord(
        title: 'My mail',
        username: 'alice',
        email: 'private@example.test',
        password: '  Keep spaces!  ',
        notes: 'not searchable',
        tags: ['personal'],
      );
      final decoded = VaultRecord.decode(record.encode())!;
      expect(decoded.password, '  Keep spaces!  ');
      expect(decoded.matches('PERSONAL'), isTrue);
      expect(decoded.matches('Keep spaces'), isFalse);
      expect(decoded.matches('not searchable'), isFalse);
      expect(decoded.toString(), 'VaultRecord([REDACTED])');
      expect(VaultRecord.decode(VaultRecord.tombstone()), isNull);
      for (final invalid in [
        '{"schema":2,"deleted":true}',
        '{"schema":1,"deleted":true,"password":"must not survive"}',
        '{"schema":1,"deleted":false}',
        '{"schema":1.0,"deleted":true}',
      ]) {
        expect(
          () => VaultRecord.decode(Uint8List.fromList(utf8.encode(invalid))),
          throwsA(isA<RecordFailure>()),
        );
      }
      expect(() => VaultRecord(title: ' '), throwsA(isA<RecordFailure>()));
      expect(
        () => VaultRecord(title: 'invalid\ud800'),
        throwsA(isA<RecordFailure>()),
      );
      expect(
        () => VaultRecord(title: 'é' * 101),
        throwsA(isA<RecordFailure>()),
      );
      expect(
        () => VaultRecord(title: 'valid', tags: ['same', 'same']),
        throwsA(isA<RecordFailure>()),
      );
      expect(() => vaultCounter('01'), throwsA(isA<CryptoFailure>()));
      expect(vaultCounter('18446744073709551615'), EnvelopeContext.maxU64);
    },
  );

  test(
    'lost write response retries the exact ciphertext and idempotency key',
    () async {
      final api = MemoryVaultApi();
      final account = await api.login(
        'test@example.test',
        'Test-only master password 2026!',
      );
      final vault = VaultClient(api, account);
      addTearDown(() {
        vault.dispose();
        account.lock();
      });
      await vault.reload();
      api.loseResponse = true;
      await expectLater(
        vault.save(
          VaultRecord(
            title: 'Never sent in plaintext',
            password: 'super-private',
          ),
        ),
        throwsA(isA<AccountFailure>()),
      );
      expect(vault.hasPendingWrite, isTrue);
      expect(vault.ready, isFalse);
      await expectLater(
        vault.save(VaultRecord(title: 'blocked')),
        throwsStateError,
      );
      await vault.retryPending();
      expect(api.serializedWrites[0], api.serializedWrites[1]);
      expect(api.serializedWrites[0].contains('super-private'), isFalse);
      expect(
        api.serializedWrites[0].contains('Never sent in plaintext'),
        isFalse,
      );
      expect(vault.entries.single.record.password, 'super-private');
      expect(api.objects.length, 1);
      expect(vault.hasPendingWrite, isFalse);
      expect(vault.ready, isTrue);
    },
  );

  test('snapshot pages publish atomically; corruption and changed snapshots keep the old list', () async {
    final api = MemoryVaultApi();
    final account = await api.login(
      'test@example.test',
      'Test-only master password 2026!',
    );
    final vault = VaultClient(api, account);
    addTearDown(() {
      vault.dispose();
      account.lock();
    });
    await vault.reload();
    await vault.save(VaultRecord(title: 'First'));
    await vault.save(VaultRecord(title: 'Second'));
    final previous = vault.entries;
    api.corruptLast = true;
    await expectLater(vault.reload(), throwsA(isA<CryptoFailure>()));
    expect(identical(vault.entries, previous), isTrue);
    expect(vault.ready, isFalse);
    api.corruptLast = false;
    api.failSecondPage = true;
    await expectLater(vault.reload(), throwsA(isA<AccountFailure>()));
    expect(identical(vault.entries, previous), isTrue);
    api.failSecondPage = false;
    await vault.reload();
    expect(vault.entries.length, 2);
    await vault.remove(vault.entries.first);
    expect(vault.entries.single.record.title, 'Second');
    expect(api.objects.length, 2);
    account.lock();
    expect(vault.entries, isEmpty);
    await expectLater(vault.reload(), throwsA(isA<AccountFailure>()));
  });
}
