import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:flutter_test/flutter_test.dart';

import 'crypto_test.dart' show hex, sequence, toHex;

void main() {
  test('Argon2id RFC 9106 section 5.3', () async {
    final key =
        await const DartArgon2id(
          memory: 32,
          iterations: 3,
          parallelism: 4,
          hashLength: 32,
          maxIsolates: 1,
        ).deriveKey(
          secretKey: SecretKey(List.filled(32, 1)),
          nonce: List.filled(16, 2),
          optionalSecret: List.filled(8, 3),
          associatedData: List.filled(12, 4),
        );
    expect(
      toHex(await key.extractBytes()),
      '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
    );
    key.destroy();
  });

  test('HKDF-SHA256 RFC 5869 appendix A.1', () async {
    final key = await Hkdf(hmac: Hmac.sha256(), outputLength: 42).deriveKey(
      secretKey: SecretKey(List.filled(22, 11)),
      nonce: sequence(0, 13),
      info: sequence(240, 10),
    );
    expect(
      toHex(key.bytes),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
    key.destroy();
  });

  test('AES-256-GCM zero-input known answer', () async {
    final box = await AesGcm.with256bits().encrypt(
      List.filled(16, 0),
      secretKey: SecretKey(List.filled(32, 0)),
      nonce: List.filled(12, 0),
    );
    expect(box.cipherText, hex('cea7403d4d606b6e074ec5d3baf39d18'));
    expect(box.mac.bytes, hex('d0d1c8a799996bf0265b98b5d48ab919'));
  });
}
