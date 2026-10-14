import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import '../connection/server_config.dart';
import '../connection/strict_json.dart';

/// Protocol errors deliberately contain no passwords, keys or plaintext.
final class CryptoFailure implements Exception {
  const CryptoFailure();
  @override
  String toString() => 'CryptoFailure: invalid or unauthenticated PM1 data';
}

String encodeWire(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List decodeWire(String value, {int? length, int maximum = 1048770}) {
  if (value.isEmpty ||
      value.length > ((maximum + 2) ~/ 3) * 4 ||
      !RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value)) {
    throw const CryptoFailure();
  }
  try {
    final bytes = Uint8List.fromList(
      base64Url.decode(base64Url.normalize(value)),
    );
    if (bytes.length > maximum ||
        (length != null && bytes.length != length) ||
        encodeWire(bytes) != value) {
      throw const CryptoFailure();
    }
    return bytes;
  } on FormatException {
    throw const CryptoFailure();
  }
}

Uint8List secureBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => random.nextInt(256)),
  );
}

bool sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

final class PmId {
  PmId(List<int> bytes) : _bytes = Uint8List.fromList(bytes) {
    if (_bytes.length != 16 || _bytes.every((b) => b == 0)) {
      throw const CryptoFailure();
    }
  }
  factory PmId.parse(String value) => PmId(decodeWire(value, length: 16));
  factory PmId.random() => PmId(secureBytes(16));
  final Uint8List _bytes;
  Uint8List get bytes => Uint8List.fromList(_bytes);
  String get wire => encodeWire(_bytes);
  bool matches(PmId other) => sameBytes(_bytes, other._bytes);
}

final class Identity {
  const Identity(this.server, this.account, this.vault);
  final PmId server, account, vault;
  Uint8List get bytes => Uint8List.fromList([
    ...server._bytes,
    ...account._bytes,
    ...vault._bytes,
  ]);
}

final class PasswordDescriptor {
  PasswordDescriptor(KdfProfile profile, List<int> salt)
    : profile = KdfProfile.parse({
        'memory_kib': profile.memoryKiB,
        'iterations': profile.iterations,
        'parallelism': profile.parallelism,
        'argon_version': profile.version,
      }),
      _salt = Uint8List.fromList(salt) {
    if (_salt.length != 16) throw const CryptoFailure();
  }
  factory PasswordDescriptor.random(KdfProfile profile) =>
      PasswordDescriptor(profile, secureBytes(16));
  final KdfProfile profile;
  final Uint8List _salt;
  Uint8List get bytes {
    final result = Uint8List(30);
    result[0] = 1;
    result[1] = profile.version;
    final view = ByteData.sublistView(result);
    view.setUint32(2, profile.memoryKiB);
    view.setUint32(6, profile.iterations);
    view.setUint32(10, profile.parallelism);
    result.setRange(14, 30, _salt);
    return result;
  }

  factory PasswordDescriptor.decode(List<int> bytes) {
    if (bytes.length != 30 || bytes[0] != 1 || bytes[1] != 19) {
      throw const CryptoFailure();
    }
    final view = ByteData.sublistView(Uint8List.fromList(bytes));
    try {
      return PasswordDescriptor(
        KdfProfile(
          view.getUint32(2),
          view.getUint32(6),
          view.getUint32(10),
          bytes[1],
        ),
        bytes.sublist(14),
      );
    } on ConfigurationException {
      throw const CryptoFailure();
    } on FormatException {
      throw const CryptoFailure();
    }
  }
}

/// Memory-only secret. Wiping is best effort in a garbage-collected runtime.
final class Secret {
  Secret(List<int> bytes) : _bytes = Uint8List.fromList(bytes) {
    if (_bytes.length != 32) throw const CryptoFailure();
  }
  factory Secret.random() => Secret(secureBytes(32));
  final Uint8List _bytes;
  bool _destroyed = false;
  Uint8List copyBytes() {
    if (_destroyed) throw StateError('Secret destroyed');
    return Uint8List.fromList(_bytes);
  }

  String get wire {
    if (_destroyed) throw StateError('Secret destroyed');
    return encodeWire(_bytes);
  }

  void destroy() {
    _bytes.fillRange(0, _bytes.length, 0);
    _destroyed = true;
  }

  @override
  String toString() => 'Secret([REDACTED])';
}

final class PasswordKeys {
  const PasswordKeys(this.wrapping, this.authentication);
  final Secret wrapping, authentication;
  void destroy() {
    wrapping.destroy();
    authentication.destroy();
  }
}

Uint8List passwordBytes(String password, {bool creating = false}) {
  // Dart's UTF-8 encoder replaces invalid surrogate sequences: reject first.
  final units = password.codeUnits;
  for (var i = 0; i < units.length; i++) {
    final unit = units[i];
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (++i >= units.length || units[i] < 0xdc00 || units[i] > 0xdfff) {
        throw const CryptoFailure();
      }
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw const CryptoFailure();
    }
  }
  final bytes = Uint8List.fromList(utf8.encode(password));
  if (bytes.isEmpty ||
      bytes.length > 1024 ||
      (creating && password.runes.length < 12)) {
    bytes.fillRange(0, bytes.length, 0);
    throw const CryptoFailure();
  }
  return bytes;
}

Future<Uint8List> _hkdf(List<int> input, List<int> salt, List<int> info) async {
  final key = SecretKeyData(
    Uint8List.fromList(input),
    overwriteWhenDestroyed: true,
  );
  SecretKeyData? output;
  try {
    output = await Hkdf(
      hmac: Hmac.sha256(),
      outputLength: 32,
    ).deriveKey(secretKey: key, nonce: salt, info: info);
    return Uint8List.fromList(output.bytes);
  } finally {
    key.destroy();
    output?.destroy();
  }
}

/// One expensive password derivation at a time, outside the UI isolate.
/// Use one engine per application; additional requests are refused, not queued.
final class PasswordEngine {
  static bool _busy = false;
  bool get busy => _busy;
  Future<PasswordKeys> derive(
    String password,
    Identity identity,
    PasswordDescriptor descriptor, {
    bool creating = false,
  }) async {
    if (_busy) throw StateError('Password derivation already running');
    final input = passwordBytes(password, creating: creating);
    final context = identity.bytes;
    final descriptorBytes = descriptor.bytes;
    _busy = true;
    try {
      final output = await Isolate.run(
        () => _derivePassword(input, context, descriptorBytes),
      );
      try {
        return PasswordKeys(
          Secret(output.sublist(0, 32)),
          Secret(output.sublist(32)),
        );
      } finally {
        output.fillRange(0, output.length, 0);
      }
    } finally {
      input.fillRange(0, input.length, 0);
      _busy = false;
    }
  }
}

Future<Uint8List> _derivePassword(
  Uint8List input,
  Uint8List context,
  Uint8List descriptorBytes,
) async {
  final descriptor = PasswordDescriptor.decode(descriptorBytes);
  final passwordKey = SecretKeyData(input, overwriteWhenDestroyed: true);
  SecretKey? intermediate;
  Uint8List? master;
  Uint8List? wrap;
  Uint8List? authentication;
  try {
    // Explicitly use the portable Dart backend in the worker isolate.
    intermediate = await DartArgon2id(
      memory: descriptor.profile.memoryKiB,
      iterations: descriptor.profile.iterations,
      parallelism: descriptor.profile.parallelism,
      hashLength: 32,
      maxIsolates: 1,
    ).deriveKey(secretKey: passwordKey, nonce: descriptor._salt);
    master = Uint8List.fromList(await intermediate.extractBytes());
    final identitySalt = (await Sha256().hash([
      ...ascii.encode('PM1/identity'),
      ...context,
    ])).bytes;
    wrap = await _hkdf(master, identitySalt, ascii.encode('PM1/password-wrap'));
    authentication = await _hkdf(
      master,
      identitySalt,
      ascii.encode('PM1/authentication'),
    );
    return Uint8List.fromList([...wrap, ...authentication]);
  } finally {
    input.fillRange(0, input.length, 0);
    passwordKey.destroy();
    intermediate?.destroy();
    master?.fillRange(0, master.length, 0);
    wrap?.fillRange(0, wrap.length, 0);
    authentication?.fillRange(0, authentication.length, 0);
  }
}

final class EnvelopeContext {
  EnvelopeContext({
    required this.kind,
    required this.identity,
    required this.epoch,
    required this.generation,
    this.object,
    List<int> metadata = const [],
  }) : _metadata = Uint8List.fromList(metadata) {
    if (kind < 1 ||
        kind > 4 ||
        generation <= BigInt.zero ||
        generation > maxU64 ||
        ((kind <= 2) != (object == null))) {
      throw const CryptoFailure();
    }
    if (kind == 1) {
      PasswordDescriptor.decode(_metadata);
    } else if ((kind == 2 && _metadata.length != 16) ||
        (kind >= 3 && _metadata.isNotEmpty)) {
      throw const CryptoFailure();
    }
    if (kind == 2 && _metadata.every((b) => b == 0))
      throw const CryptoFailure();
  }
  static final maxU64 = (BigInt.one << 64) - BigInt.one;
  final int kind;
  final Identity identity;
  final PmId epoch;
  final PmId? object;
  final BigInt generation;
  final Uint8List _metadata;
}

Uint8List _header(
  EnvelopeContext context,
  int length,
  List<int> salt,
  List<int> nonce,
) {
  final bytes = Uint8List(148 + context._metadata.length);
  bytes.setRange(0, 4, ascii.encode('PME1'));
  bytes[4] = context.kind;
  final view = ByteData.sublistView(bytes);
  view.setUint16(6, 1);
  bytes.setRange(8, 56, context.identity.bytes);
  bytes.setRange(56, 72, context.epoch._bytes);
  if (context.object != null) bytes.setRange(72, 88, context.object!._bytes);
  var counter = context.generation;
  for (var i = 95; i >= 88; i--) {
    bytes[i] = (counter & BigInt.from(255)).toInt();
    counter >>= 8;
  }
  view.setUint32(96, length);
  bytes.setRange(100, 132, salt);
  bytes.setRange(132, 144, nonce);
  view.setUint32(144, context._metadata.length);
  bytes.setRange(148, bytes.length, context._metadata);
  return bytes;
}

/// Validates all structure and trusted context before key use.
Uint8List _validate(Uint8List blob, EnvelopeContext context) {
  if (blob.length < 164 || blob.length > 1048740) throw const CryptoFailure();
  final view = ByteData.sublistView(blob);
  final length = view.getUint32(96);
  final metadataLength = view.getUint32(144);
  if (metadataLength != context._metadata.length ||
      blob.length != 148 + metadataLength + length + 16 ||
      (context.kind <= 2 ? length != 32 : length < 1 || length > 1048576)) {
    throw const CryptoFailure();
  }
  final expected = _header(
    context,
    length,
    blob.sublist(100, 132),
    blob.sublist(132, 144),
  );
  if (!sameBytes(expected, blob.sublist(0, expected.length))) {
    throw const CryptoFailure();
  }
  return expected;
}

Future<Uint8List> _envelopeKey(Secret root, Uint8List header) async {
  final rootBytes = root.copyBytes();
  try {
    return await _hkdf(rootBytes, header.sublist(100, 132), [
      ...ascii.encode('PM1/envelope-key'),
      ...(await Sha256().hash(header)).bytes,
    ]);
  } finally {
    rootBytes.fillRange(0, rootBytes.length, 0);
  }
}

final class EnvelopeCrypto {
  Future<Uint8List> encrypt(
    Secret root,
    EnvelopeContext context,
    Uint8List plaintext,
  ) async {
    if (context.kind <= 2
        ? plaintext.length != 32
        : plaintext.isEmpty || plaintext.length > 1048576) {
      throw const CryptoFailure();
    }
    if (context.kind >= 3) {
      try {
        _validateJson(plaintext);
      } on FormatException {
        throw const CryptoFailure();
      }
    }
    final snapshot = Uint8List.fromList(plaintext);
    final header = _header(
      context,
      plaintext.length,
      secureBytes(32),
      secureBytes(12),
    );
    final keyBytes = await _envelopeKey(root, header);
    final key = SecretKeyData(keyBytes, overwriteWhenDestroyed: true);
    try {
      final box = await AesGcm.with256bits().encrypt(
        snapshot,
        secretKey: key,
        nonce: header.sublist(132, 144),
        aad: header,
      );
      return Uint8List.fromList([
        ...header,
        ...box.cipherText,
        ...box.mac.bytes,
      ]);
    } finally {
      snapshot.fillRange(0, snapshot.length, 0);
      keyBytes.fillRange(0, keyBytes.length, 0);
      key.destroy();
    }
  }

  Future<Uint8List> decrypt(
    Secret root,
    EnvelopeContext context,
    Uint8List encrypted,
  ) async {
    // Snapshot input before the first await: no caller mutation during verification.
    if (encrypted.length < 164 || encrypted.length > 1048740)
      throw const CryptoFailure();
    final blob = Uint8List.fromList(encrypted);
    final header = _validate(blob, context);
    final keyBytes = await _envelopeKey(root, header);
    final key = SecretKeyData(keyBytes, overwriteWhenDestroyed: true);
    Uint8List? plaintext;
    try {
      final box = SecretBox(
        blob.sublist(header.length, blob.length - 16),
        nonce: header.sublist(132, 144),
        mac: Mac(blob.sublist(blob.length - 16)),
      );
      plaintext = Uint8List.fromList(
        await AesGcm.with256bits().decrypt(box, secretKey: key, aad: header),
      );
      if (context.kind >= 3) _validateJson(plaintext);
      return plaintext;
    } on SecretBoxAuthenticationError {
      throw const CryptoFailure();
    } on FormatException {
      plaintext?.fillRange(0, plaintext.length, 0);
      throw const CryptoFailure();
    } finally {
      keyBytes.fillRange(0, keyBytes.length, 0);
      key.destroy();
    }
  }

  void _validateJson(Uint8List bytes) {
    // Objects only; record-specific schema is validated by the vault layer.
    final value = decodeStrictJson(bytes, maxBytes: 1048576);
    if (value is! Map<String, dynamic>)
      throw const FormatException('Vault JSON object');
  }
}
