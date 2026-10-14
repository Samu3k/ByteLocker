import 'dart:io';
import 'dart:convert';

import 'package:flutter/services.dart';

import '../connection/server_address.dart';
import '../crypto/pm1.dart';
import 'account_client.dart';

/// Connection metadata only. No password, vault key or session token.
final class LinkedAccount {
  LinkedAccount({
    required this.address,
    required this.serverId,
    required this.email,
    required this.accountId,
    required this.vaultId,
  }) {
    decodeWire(serverId, length: 16);
    decodeWire(accountId, length: 16);
    decodeWire(vaultId, length: 16);
    if (email != normalizeEmail(email)) throw const FormatException();
  }
  final ServerAddress address;
  final String serverId, email, accountId, vaultId;
  String get biometricSlot => '${address.origin}|$serverId|$email';
  Map<String, Object> encode() => {
    'schema': 1,
    'origin': address.origin.toString(),
    'server_id': serverId,
    'email': email,
    'account_id': accountId,
    'vault_id': vaultId,
  };
  factory LinkedAccount.decode(Map<Object?, Object?> value) {
    if (value.length != 6 || value['schema'] != 1 || value['schema'] is! int) {
      throw const FormatException();
    }
    String field(String name) {
      final text = value[name];
      if (text is! String || text.length > 512) throw const FormatException();
      return text;
    }

    return LinkedAccount(
      address: ServerAddress.parse(field('origin')),
      serverId: field('server_id'),
      email: field('email'),
      accountId: field('account_id'),
      vaultId: field('vault_id'),
    );
  }
  bool matches(UnlockedAccount account) =>
      account.identity.server.wire == serverId &&
      account.identity.account.wire == accountId &&
      account.identity.vault.wire == vaultId;
  @override
  String toString() => 'LinkedAccount([REDACTED])';
}

class LinkedAccountStore {
  const LinkedAccountStore();
  static const _channel = MethodChannel('bytelocker/security');
  bool get supported => Platform.isAndroid || Platform.isWindows;
  Future<LinkedAccount?> load() async {
    if (!supported) return null;
    if (Platform.isWindows) {
      final text = await _channel.invokeMethod<String>('linkedAccount');
      if (text == null) return null;
      if (text.length > 4096) throw const FormatException();
      final value = jsonDecode(text);
      if (value is! Map<String, dynamic>) throw const FormatException();
      return LinkedAccount.decode(value);
    }
    final value = await _channel.invokeMapMethod<Object?, Object?>(
      'linkedAccount',
    );
    return value == null ? null : LinkedAccount.decode(value);
  }

  Future<void> save(LinkedAccount value) async {
    if (supported)
      await _channel.invokeMethod(
        'saveLinkedAccount',
        Platform.isWindows ? jsonEncode(value.encode()) : value.encode(),
      );
  }
}
