import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/connection/server_config.dart';
import 'package:password_manager/crypto/pm1.dart';

Uint8List hex(String text) => Uint8List.fromList([
  for (var i = 0; i < text.length; i += 2)
    int.parse(text.substring(i, i + 2), radix: 16),
]);
String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
Uint8List sequence(int start, int count) =>
    Uint8List.fromList(List.generate(count, (i) => start + i));
Identity identity() => Identity(
  PmId(sequence(0, 16)),
  PmId(sequence(16, 16)),
  PmId(sequence(32, 16)),
);
PasswordDescriptor descriptor() =>
    PasswordDescriptor(const KdfProfile(65536, 3, 4, 19), sequence(0, 16));
EnvelopeContext context({int kind = 1, BigInt? generation, Identity? ids}) =>
    EnvelopeContext(
      kind: kind,
      identity: ids ?? identity(),
      epoch: PmId(sequence(48, 16)),
      object: kind >= 3 ? PmId(sequence(64, 16)) : null,
      generation: generation ?? BigInt.one,
      metadata: kind == 1
          ? descriptor().bytes
          : kind == 2
          ? sequence(224, 16)
          : [],
    );
const vector =
    '504d453101000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000000000000000000000000000000000000100000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab0000001e0113000100000000000300000004000102030405060708090a0b0c0d0e0fa5656aa25fd4d401ceeeb391808aae8f6801f2c8f5cc96f70ede1533b146a56fbbf822bc077e3e9bc4c603dcf01f2af7';

void main() {
  test('one MiB JSON boundary and encryption input snapshot', () async {
    final root = Secret.random();
    final crypto = EnvelopeCrypto();
    final expected = context(kind: 3);
    final maximum = Uint8List.fromList(
      utf8.encode('{"n":"${'x' * (1048576 - 8)}"}'),
    );
    expect(maximum.length, 1048576);
    final original = Uint8List.fromList(maximum);
    final future = crypto.encrypt(root, expected, maximum);
    maximum.fillRange(0, maximum.length, 0);
    final encrypted = await future;
    expect(await crypto.decrypt(root, expected, encrypted), original);
    await expectLater(
      crypto.encrypt(root, expected, Uint8List(1048577)),
      throwsA(isA<CryptoFailure>()),
    );
    root.destroy();
  });
  test(
    'PM1 Argon2id and separated HKDF keys match independent fixture',
    () async {
      final engine = PasswordEngine();
      final future = engine.derive(
        'Test-only master password 2026!',
        identity(),
        descriptor(),
        creating: true,
      );
      expect(engine.busy, isTrue);
      await expectLater(
        engine.derive('another password!', identity(), descriptor()),
        throwsStateError,
      );
      final keys = await future;
      expect(engine.busy, isFalse);
      expect(
        toHex(keys.wrapping.copyBytes()),
        '70c6a4425a9c6cf54720100f08098e64f8ffa14e54a0e2cec8ff8df44e167c16',
      );
      expect(
        toHex(keys.authentication.copyBytes()),
        'fca131d785fbe0fa95ae0c305e383793fe1b6902b8c1f9ad722bb6460eec19c4',
      );
      expect(
        await EnvelopeCrypto().decrypt(keys.wrapping, context(), hex(vector)),
        sequence(96, 32),
      );
      keys.destroy();
      expect(keys.wrapping.copyBytes, throwsStateError);
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );

  test('descriptor and canonical wire values reject ambiguous encodings', () {
    expect(
      toHex(descriptor().bytes),
      '0113000100000000000300000004000102030405060708090a0b0c0d0e0f',
    );
    expect(
      PasswordDescriptor.decode(descriptor().bytes).bytes,
      descriptor().bytes,
    );
    for (final value in ['AA==', 'A', ' A', 'AB', '_', '']) {
      expect(() => decodeWire(value), throwsA(isA<CryptoFailure>()));
    }
    expect(() => PmId(Uint8List(16)), throwsA(isA<CryptoFailure>()));
    final invalid = descriptor().bytes..[5] = 1;
    expect(
      () => PasswordDescriptor.decode(invalid),
      throwsA(isA<CryptoFailure>()),
    );
    expect(
      () => EnvelopeContext(
        kind: 1,
        identity: identity(),
        epoch: PmId(sequence(48, 16)),
        generation: BigInt.zero,
        metadata: descriptor().bytes,
      ),
      throwsA(isA<CryptoFailure>()),
    );
  });

  test(
    'password preserves spaces, combining marks and Unicode scalar counts',
    () {
      expect(passwordBytes('  e\u0301  '), utf8.encode('  e\u0301  '));
      expect(passwordBytes('😀' * 12, creating: true).length, 48);
      for (final value in ['', '\ud800', '\udc00', '\ud800a', 'x' * 1025]) {
        expect(() => passwordBytes(value), throwsA(isA<CryptoFailure>()));
      }
      expect(
        () => passwordBytes('short', creating: true),
        throwsA(isA<CryptoFailure>()),
      );
      expect(passwordBytes('short').length, 5);
    },
  );

  test(
    'known password fixture authenticates all header, ciphertext and tag bytes',
    () async {
      final root = Secret(
        hex('70c6a4425a9c6cf54720100f08098e64f8ffa14e54a0e2cec8ff8df44e167c16'),
      );
      final crypto = EnvelopeCrypto();
      for (var offset = 0; offset < 226; offset++) {
        final changed = hex(vector)..[offset] ^= 1;
        await expectLater(
          crypto.decrypt(root, context(), changed),
          throwsA(isA<CryptoFailure>()),
        );
      }
      await expectLater(
        crypto.decrypt(Secret.random(), context(), hex(vector)),
        throwsA(isA<CryptoFailure>()),
      );
      await expectLater(
        crypto.decrypt(root, context(generation: BigInt.two), hex(vector)),
        throwsA(isA<CryptoFailure>()),
      );
      await expectLater(
        crypto.decrypt(
          root,
          context(
            ids: Identity(PmId.random(), identity().account, identity().vault),
          ),
          hex(vector),
        ),
        throwsA(isA<CryptoFailure>()),
      );
      await expectLater(
        crypto.decrypt(
          root,
          context(),
          Uint8List.fromList([...hex(vector), 0]),
        ),
        throwsA(isA<CryptoFailure>()),
      );
      root.destroy();
    },
  );

  test(
    'all envelope kinds round trip with fresh salt and nonce and full uint64',
    () async {
      final crypto = EnvelopeCrypto();
      final root = Secret.random();
      for (final kind in [1, 2, 3, 4]) {
        final expected = context(
          kind: kind,
          generation: EnvelopeContext.maxU64,
        );
        final plain = kind <= 2
            ? sequence(96, 32)
            : Uint8List.fromList(utf8.encode('{"schema":1,"deleted":true}'));
        final a = await crypto.encrypt(root, expected, plain);
        final b = await crypto.encrypt(root, expected, plain);
        expect(a, isNot(b));
        expect(a.sublist(100, 132), isNot(b.sublist(100, 132)));
        expect(a.sublist(132, 144), isNot(b.sublist(132, 144)));
        expect(a.sublist(88, 96), List.filled(8, 255));
        expect(await crypto.decrypt(root, expected, a), plain);
      }
      root.destroy();
    },
  );

  test('JSON content must be a strict object before encryption', () async {
    final root = Secret.random();
    for (final text in ['[]', '{"a":1,"a":2}', '\ufeff{}', '{', '{"a":NaN}']) {
      await expectLater(
        EnvelopeCrypto().encrypt(
          root,
          context(kind: 3),
          Uint8List.fromList(utf8.encode(text)),
        ),
        throwsA(isA<CryptoFailure>()),
      );
    }
    root.destroy();
    expect(root.toString(), 'Secret([REDACTED])');
  });
}
