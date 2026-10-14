import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/crypto/pm1.dart';

import 'vault_fixtures.dart';

void main() {
  test('native sealed payload logs in without master password and binds server, origin, generation and epoch', () async {
    final api = MemoryVaultApi();
    final account = await api.login(
      'test@example.test',
      'Test-only master password 2026!',
    );
    final payload = api.biometricPayload(account);
    try {
      expect(
        utf8.decode(payload),
        isNot(contains('Test-only master password')),
      );
      final restored = await api.biometricLogin('test@example.test', payload);
      final original = account.vaultKey.copyBytes(),
          recovered = restored.vaultKey.copyBytes();
      expect(recovered, orderedEquals(original));
      original.fillRange(0, original.length, 0);
      recovered.fillRange(0, recovered.length, 0);
      await api.logout(restored);
      for (final patch in [
        {'origin': 'https://other.example.com'},
        {'server_id': PmId.random().wire},
        {'account_id': PmId.random().wire},
        {'epoch_id': PmId.random().wire},
        {'credential_generation': '2'},
        {'schema': 1.0},
      ]) {
        final changed =
            (jsonDecode(utf8.decode(payload)) as Map<String, dynamic>)
              ..addAll(patch);
        final bytes = Uint8List.fromList(utf8.encode(jsonEncode(changed)));
        try {
          await expectLater(
            api.biometricLogin('test@example.test', bytes),
            throwsA(isA<CryptoFailure>()),
          );
        } finally {
          bytes.fillRange(0, bytes.length, 0);
        }
      }
      account.lock();
      expect(() => api.biometricPayload(account), throwsException);
    } finally {
      account.lock();
      payload.fillRange(0, payload.length, 0);
    }
  });
}
