import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/connection/discovery_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';
import 'package:password_manager/vault/totp.dart';
import 'package:password_manager/vault/passkey.dart';

void main() {
  final url = Platform.environment['BYTELOCKER_TEST_SERVER'];
  final invite = Platform.environment['BYTELOCKER_TEST_INVITE'];
  test(
    'real Go backend interoperability with temporary SQLite and fake email delivery',
    () async {
      final address = ServerAddress.parse(url!, allowLocalHttp: true);
      final config = await DiscoveryClient().discover(address);
      final api = AccountClient(AccountTransport(address), config);
      const password = 'Only synthetic interop password 2026!';
      final pending = await api.register(
        'interop@example.test',
        password,
        invite!,
      );
      final emailClient = HttpClient();
      late String code;
      try {
        final response = await (await emailClient.getUrl(
          Uri.parse('$url/__test__/email-code'),
        )).close();
        expect(response.statusCode, 200);
        final decoded = jsonDecode(
          await utf8.decoder.bind(response).join(),
        ) as Map<String, dynamic>;
        code = decoded['code'] as String;
      } finally {
        emailClient.close(force: true);
      }
      await api.verify(pending, code);
      final first = await api.login('interop@example.test', password);
      final sealedPayload = api.biometricPayload(first);
      final second = await api.biometricLogin(
        'interop@example.test',
        sealedPayload,
      );
      sealedPayload.fillRange(0, sealedPayload.length, 0);
      final vault = VaultClient(api, first);
      final other = VaultClient(api, second);
      addTearDown(() {
        vault.dispose();
        other.dispose();
        first.lock();
        second.lock();
      });
      await vault.reload();
      expect(vault.entries, isEmpty);
      await vault.save(
        VaultRecord(
          title: 'Mail account',
          username: 'private-user',
          email: 'private@example.test',
          password: 'private-vault-password',
          notes: 'Only encrypted',
          tags: ['personal'],
          totp: Totp.parse('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'),
          passkey: VaultPasskey.decode(
            jsonDecode(File('test/fixtures/passkey.json').readAsStringSync()),
          ),
        ),
      );
      expect(vault.entries.single.record.password, 'private-vault-password');
      await other.reload();
      expect(
        other.entries.single.record.totp!.secret,
        'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
      );
      final stale = other.entries.single;
      expect(stale.record.passkey!.userName, 'alice');
      await vault.save(
        VaultRecord(
          title: 'Updated on first device',
          password: 'changed-secret',
        ),
        replacing: vault.entries.single,
      );
      await expectLater(
        other.save(VaultRecord(title: 'Must not overwrite'), replacing: stale),
        throwsA(
          isA<AccountFailure>().having((error) => error.status, 'status', 412),
        ),
      );
      expect(other.hasPendingWrite, isFalse);
      await other.reload();
      expect(other.entries.single.record.title, 'Updated on first device');
      await other.remove(other.entries.single);
      expect(other.entries, isEmpty);
      await vault.reload();
      expect(vault.entries, isEmpty);
      await api.logout(first);
      await api.logout(second);
      final third = await api.login('interop@example.test', password);
      final restored = VaultClient(api, third);
      await restored.reload();
      expect(restored.entries, isEmpty);
      await restored.save(
        VaultRecord(
          title: 'A fresh encrypted record',
          password: 'another-secret',
        ),
      );
      expect(restored.entries.single.record.title, 'A fresh encrypted record');
      restored.dispose();
      await api.logout(third);
    },
    skip: url == null || invite == null
        ? 'Run through the opt-in Go interoperability harness'
        : false,
    timeout: const Timeout(Duration(minutes: 2)),
  );
}
