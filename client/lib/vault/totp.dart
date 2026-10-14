import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Initial profile: SHA-1, six digits, 30 seconds, Unix epoch.
final class Totp {
  Totp._(this.secret);
  final String secret;

  factory Totp.parse(String input) {
    try {
      return Totp._parse(input);
    } on FormatException {
      throw const TotpFailure();
    }
  }

  static Totp _parse(String input) {
    if (input.length > 4096) throw const TotpFailure();
    var value = input.trim();
    if (value.toLowerCase().startsWith('otpauth:')) {
      final uri = Uri.tryParse(value);
      if (uri == null ||
          uri.scheme != 'otpauth' ||
          uri.host != 'totp' ||
          uri.userInfo.isNotEmpty ||
          uri.hasPort ||
          uri.fragment.isNotEmpty ||
          uri.path.length < 2)
        throw const TotpFailure();
      final query = uri.queryParametersAll;
      if (query.values.any((values) => values.length != 1) ||
          !query.keys.every(
            const {
              'secret',
              'issuer',
              'algorithm',
              'digits',
              'period',
            }.contains,
          ) ||
          (query['algorithm']?.single.toUpperCase() ?? 'SHA1') != 'SHA1' ||
          (query['digits']?.single ?? '6') != '6' ||
          (query['period']?.single ?? '30') != '30')
        throw const TotpFailure();
      value = query['secret']?.single ?? '';
    }
    value = value.replaceAll(RegExp(r'\s'), '').toUpperCase();
    // Canonical, unpadded Base32. Ignore only valid trailing padding.
    final match = RegExp(r'^([A-Z2-7]+)(=*)$').firstMatch(value);
    if (match == null) throw const TotpFailure();
    final raw = match.group(1)!;
    final padding = match.group(2)!.length;
    const expectedPadding = {0: 0, 2: 6, 4: 4, 5: 3, 7: 1};
    final expected = expectedPadding[raw.length % 8];
    if (expected == null || (padding != 0 && padding != expected))
      throw const TotpFailure();
    final result = Totp._(raw);
    final bytes = result._decode();
    try {
      if (bytes.length < 10 || bytes.length > 128) throw const TotpFailure();
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
    return result;
  }

  Uint8List _decode() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    final bytes = <int>[];
    var buffer = 0, bits = 0;
    for (final character in secret.codeUnits) {
      buffer = (buffer << 5) | alphabet.indexOf(String.fromCharCode(character));
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        bytes.add((buffer >> bits) & 255);
        buffer &= (1 << bits) - 1;
      }
    }
    if (buffer != 0) throw const TotpFailure();
    return Uint8List.fromList(bytes);
  }

  Future<String> codeAt(DateTime time) async {
    final seconds = time.millisecondsSinceEpoch ~/ 1000;
    if (time.millisecondsSinceEpoch < 0) throw const TotpFailure();
    final counter = ByteData(8)..setUint64(0, seconds ~/ 30, Endian.big);
    final bytes = _decode();
    final key = SecretKey(bytes);
    try {
      final mac = await Hmac.sha1().calculateMac(
        counter.buffer.asUint8List(),
        secretKey: key,
      );
      final offset = mac.bytes.last & 15;
      final binary =
          ((mac.bytes[offset] & 127) << 24) |
          (mac.bytes[offset + 1] << 16) |
          (mac.bytes[offset + 2] << 8) |
          mac.bytes[offset + 3];
      return (binary % 1000000).toString().padLeft(6, '0');
    } finally {
      key.destroy();
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  @override
  String toString() => 'Totp([REDACTED])';
}

final class TotpFailure implements Exception {
  const TotpFailure();
  @override
  String toString() => 'TotpFailure: invalid or unsupported TOTP configuration';
}
