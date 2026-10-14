import '../crypto/pm1.dart';

import 'dart:convert';

bool _validText(String text) {
  final units = text.codeUnits;
  for (var i = 0; i < units.length; i++) {
    if (units[i] >= 0xd800 && units[i] <= 0xdbff) {
      if (++i >= units.length || units[i] < 0xdc00 || units[i] > 0xdfff)
        return false;
    } else if (units[i] >= 0xdc00 && units[i] <= 0xdfff) {
      return false;
    }
  }
  return utf8.encode(text).length <= 256 && text.isNotEmpty;
}

/// Private key material belongs only inside an authenticated encrypted record.
final class VaultPasskey {
  VaultPasskey({
    required this.rpId,
    required this.userId,
    required this.userName,
    required this.displayName,
    required this.credentialId,
    required this.privateKey,
    required this.publicKey,
  }) {
    if (rpId.length > 253 ||
        !rpId
            .split('.')
            .every(
              (label) =>
                  label.length <= 63 &&
                  RegExp(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$').hasMatch(label),
            ) ||
        !rpId.contains('.') ||
        rpId.contains('..') ||
        RegExp(r'^[0-9.]+$').hasMatch(rpId) ||
        !_validText(userName) ||
        !_validText(displayName))
      throw const CryptoFailure();
    decodeWire(userId, maximum: 64);
    decodeWire(credentialId, length: 32);
    decodeWire(privateKey, maximum: 512);
    decodeWire(publicKey, maximum: 256);
  }
  final String rpId,
      userId,
      userName,
      displayName,
      credentialId,
      privateKey,
      publicKey;
  Map<String, dynamic> encode() => {
    'algorithm': -7,
    'rp_id': rpId,
    'user_id': userId,
    'user_name': userName,
    'display_name': displayName,
    'credential_id': credentialId,
    'private_key': privateKey,
    'public_key': publicKey,
  };
  factory VaultPasskey.decode(Object? value) {
    if (value is! Map ||
        value.length != 8 ||
        value['algorithm'] != -7 ||
        value['algorithm'] is! int)
      throw const CryptoFailure();
    String field(String name) {
      final text = value[name];
      if (text is! String) throw const CryptoFailure();
      return text;
    }

    return VaultPasskey(
      rpId: field('rp_id'),
      userId: field('user_id'),
      userName: field('user_name'),
      displayName: field('display_name'),
      credentialId: field('credential_id'),
      privateKey: field('private_key'),
      publicKey: field('public_key'),
    );
  }
  @override
  String toString() => 'VaultPasskey([REDACTED])';
}
