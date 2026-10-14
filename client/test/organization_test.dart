import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/crypto/pm1.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';
import 'passkey_test.dart' show syntheticPasskey;

void main() {
  test('schema 4 preserves organization, secrets and legacy records', () {
    final category = PmId.random().wire;
    final record = VaultRecord(
      title: 'Work login',
      password: 'secret',
      tags: ['work'],
      categoryId: category,
      favorite: true,
      logo: 'microsoft-outlook',
      passkey: syntheticPasskey(),
    );
    final decoded = VaultRecord.decode(record.encode())!;
    expect(decoded.categoryId, category);
    expect(decoded.favorite, isTrue);
    expect(decoded.logo, 'microsoft-outlook');
    expect(decoded.passkey!.privateKey, record.passkey!.privateKey);
    final removed = decoded.withPasskey(null).withOrganization(favorite: false);
    expect(removed.categoryId, category);
    expect(removed.logo, 'microsoft-outlook');
    expect(removed.password, 'secret');
    expect(
      VaultRecord.decode(VaultRecord(title: 'Old record').encode())!.favorite,
      isFalse,
    );
    expect(
      VaultRecord.decode(VaultRecord(title: 'Work', isCategory: true).encode())!
          .isCategory,
      isTrue,
    );
    expect(
      () => VaultRecord(title: 'Broken', categoryId: 'bad'),
      throwsA(isA<RecordFailure>()),
    );
    expect(
      () => VaultRecord(title: 'Broken', logo: '../evil'),
      throwsA(isA<RecordFailure>()),
    );
    expect(
      () => VaultRecord(title: 'Broken', isCategory: true, password: 'private'),
      throwsA(isA<RecordFailure>()),
    );
    final wire =
        jsonDecode(utf8.decode(removed.encode())) as Map<String, dynamic>;
    for (final change in <Map<String, dynamic>>[
      {...wire, 'favorite': 1},
      {...wire, 'category_id': 'bad'},
      {...wire, 'logo': '../evil'},
      {...wire, 'unknown': true},
    ])
      expect(
        () => VaultRecord.decode(
          Uint8List.fromList(utf8.encode(jsonEncode(change))),
        ),
        throwsA(isA<RecordFailure>()),
      );
    wire.remove('favorite');
    expect(
      () =>
          VaultRecord.decode(Uint8List.fromList(utf8.encode(jsonEncode(wire)))),
      throwsA(isA<RecordFailure>()),
    );
  });

  test('categories and favorites synchronize encrypted between clients and remain separate from credentials', () async {
    final api = MemoryVaultApi();
    final account = await api.login(
      'test@example.test',
      'Test-only master password 2026!',
    );
    final first = VaultClient(api, account), second = VaultClient(api, account);
    addTearDown(() {
      first.dispose();
      second.dispose();
      account.lock();
    });
    await first.reload();
    await first.save(VaultRecord(title: 'Private work', isCategory: true));
    final folder = first.categories.single;
    expect(first.entries, isEmpty);
    await first.save(
      VaultRecord(
        title: 'GitHub login',
        password: 'not-on-server',
        categoryId: folder.id.wire,
        favorite: true,
        logo: 'github',
      ),
    );
    await second.reload();
    expect(second.categories.single.record.title, 'Private work');
    expect(second.entries.single.record.favorite, isTrue);
    expect(second.entries.single.record.categoryId, folder.id.wire);
    for (final serialized in api.serializedWrites) {
      expect(serialized, isNot(contains('Private work')));
      expect(serialized, isNot(contains('not-on-server')));
    }
    await expectLater(
      first.remove(first.categories.single),
      throwsA(isA<RecordFailure>()),
    );
    await expectLater(
      first.save(VaultRecord(title: 'private work', isCategory: true)),
      throwsA(isA<RecordFailure>()),
    );
    await first.save(
      VaultRecord(title: 'Team', isCategory: true),
      replacing: first.categories.single,
    );
    await second.reload();
    expect(second.categories.single.record.title, 'Team');
    expect(second.entries.single.record.categoryId, folder.id.wire);
    await second.save(
      second.entries.single.record.withOrganization(favorite: false),
      replacing: second.entries.single,
    );
    await first.reload();
    expect(first.entries.single.record.favorite, isFalse);
    expect(first.entries.single.record.password, 'not-on-server');
    first.dispose();
    expect(first.categories, isEmpty);
  });
}
