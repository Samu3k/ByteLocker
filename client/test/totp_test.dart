import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/vault/totp.dart';
import 'package:password_manager/vault/totp_code.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

void main() {
  testWidgets(
    'copy uses the current TOTP at the time of tap, never the secret or an expired display',
    (tester) async {
      var now = DateTime.fromMillisecondsSinceEpoch(29000);
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
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TotpCode(input: secret, now: () => now),
          ),
        ),
      );
      await tester.pump();
      expect(find.text('755224'), findsOneWidget);
      now = DateTime.fromMillisecondsSinceEpoch(30000);
      // No timer pump: the screen still contains the previous period's code.
      await tester.tap(find.byTooltip('Copia codice 2FA'));
      await tester.pump();
      expect(calls.single.method, 'copy');
      expect(calls.single.arguments, '287082');
      expect(calls.single.arguments, isNot(secret));
      await tester.pumpWidget(const SizedBox());
    },
  );
  test('RFC 6238 SHA-1 vectors, six-digit truncation and boundaries', () async {
    final totp = Totp.parse(secret);
    const vectors = {
      59: '287082',
      1111111109: '081804',
      1111111111: '050471',
      1234567890: '005924',
      2000000000: '279037',
      20000000000: '353130',
    };
    for (final vector in vectors.entries) {
      expect(
        await totp.codeAt(
          DateTime.fromMillisecondsSinceEpoch(vector.key * 1000, isUtc: true),
        ),
        vector.value,
      );
    }
    expect(await totp.codeAt(DateTime.fromMillisecondsSinceEpoch(0)), '755224');
    expect(
      await totp.codeAt(DateTime.fromMillisecondsSinceEpoch(29999)),
      '755224',
    );
    expect(
      await totp.codeAt(DateTime.fromMillisecondsSinceEpoch(30000)),
      '287082',
    );
    await expectLater(
      totp.codeAt(DateTime.fromMillisecondsSinceEpoch(-1)),
      throwsA(isA<TotpFailure>()),
    );
    expect(totp.toString(), isNot(contains(secret)));
  });

  test('Base32 and provisioning links reject unsupported parameters', () {
    expect(
      Totp.parse(' gezd gnbv gy3t qojq gezd gnbv gy3t qojq ').secret,
      secret,
    );
    expect(
      Totp.parse(
        'otpauth://totp/Test:alice?secret=$secret&issuer=Test&algorithm=SHA1&digits=6&period=30',
      ).secret,
      secret,
    );
    expect(Totp.parse('${secret}GE======').secret, '${secret}GE');
    for (final input in [
      '',
      'ABC',
      'AAAAAAAAAAAAAAA',
      'AAAAAAAAAAAAAAAAAB',
      '${secret}=',
      'JBSWY3DPEHPK3PXP0',
      'otpauth://hotp/Test?secret=$secret',
      'otpauth://totp/Test?secret=$secret&digits=8',
      'otpauth://totp/Test?secret=$secret&period=60',
      'otpauth://totp/Test?secret=$secret&algorithm=SHA256',
      'otpauth://totp/Test?secret=$secret&secret=$secret',
      'otpauth://totp/Test?secret=$secret&counter=1',
      'otpauth://totp/Test?secret=$secret#fragment',
      'otpauth://totp/Test?secret=%XX',
      'A' * 4097,
    ]) {
      expect(() => Totp.parse(input), throwsA(isA<TotpFailure>()));
    }
  });

  test(
    'schema 1 remains readable; schema 2 encrypts and synchronizes TOTP',
    () async {
      final legacy = VaultRecord(title: 'Legacy');
      expect(jsonDecode(utf8.decode(legacy.encode()))['schema'], 1);
      expect(VaultRecord.decode(legacy.encode())!.totp, isNull);
      final record = VaultRecord(title: 'Account', totp: Totp.parse(secret));
      final decoded = VaultRecord.decode(record.encode())!;
      expect(decoded.totp!.secret, secret);
      expect(record.matches(secret), isFalse);
      final invalid =
          jsonDecode(utf8.decode(record.encode())) as Map<String, dynamic>;
      invalid['totp'] = 'invalid';
      expect(
        () => VaultRecord.decode(
          Uint8List.fromList(utf8.encode(jsonEncode(invalid))),
        ),
        throwsA(isA<RecordFailure>()),
      );
      final api = MemoryVaultApi();
      final account = await api.login(
        'test@example.test',
        'Test-only master password 2026!',
      );
      final vault = VaultClient(api, account);
      try {
        await vault.reload();
        await vault.save(record);
        expect(vault.entries.single.record.totp!.secret, secret);
        expect(api.objects.toString(), isNot(contains(secret)));
        await vault.reload();
        expect(vault.entries.single.record.totp!.secret, secret);
        await vault.save(
          VaultRecord(title: 'Account'),
          replacing: vault.entries.single,
        );
        expect(vault.entries.single.record.totp, isNull);
      } finally {
        vault.dispose();
        account.lock();
      }
    },
  );

  testWidgets(
    'code rolls over, clears on input change and cancels timer on close',
    (tester) async {
      var now = DateTime.fromMillisecondsSinceEpoch(29000);
      Widget page(String input) => MaterialApp(
        home: Scaffold(
          body: TotpCode(input: input, now: () => now),
        ),
      );
      await tester.pumpWidget(page(secret));
      await tester.pump();
      expect(find.text('755224'), findsOneWidget);
      expect(find.text('Nuovo codice tra 1 secondi'), findsOneWidget);
      now = DateTime.fromMillisecondsSinceEpoch(30000);
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(find.text('755224'), findsNothing);
      expect(find.text('287082'), findsOneWidget);
      await tester.pumpWidget(page('invalid'));
      await tester.pump();
      expect(find.text('287082'), findsNothing);
      expect(
        find.textContaining('Configurazione 2FA non valida'),
        findsOneWidget,
      );
      await tester.pumpWidget(page(''));
      expect(find.text('Codice 2FA'), findsNothing);
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 35));
      expect(tester.takeException(), isNull);
    },
  );
}
