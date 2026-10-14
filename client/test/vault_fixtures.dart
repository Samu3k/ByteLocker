import 'dart:convert';
import 'dart:typed_data';

import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';
import 'package:password_manager/crypto/pm1.dart';

import 'crypto_test.dart' show identity, descriptor, vector;
import 'fixtures.dart';

ServerConfig vaultConfig() {
  final fixture = configFixture()..['server_id'] = identity().server.wire;
  return ServerConfig.decode(configBytes(fixture));
}

class FixtureTransport extends AccountTransport {
  FixtureTransport() : super(ServerAddress.parse('https://vault.example.com'));
  @override
  Future<Map<String, dynamic>> request(
    String method,
    String path, {
    Map<String, dynamic>? body,
    String? authorization,
    int expected = 200,
    Map<String, String>? query,
    Map<String, String> headers = const {},
    int maxBytes = 65536,
  }) async {
    final ids = identity();
    if (path == '/auth/prelogin' || path == '/account/material')
      return {
        'server_id': ids.server.wire,
        'account_id': ids.account.wire,
        'vault_id': ids.vault.wire,
        'credential_generation': '1',
        'password_descriptor': encodeWire(descriptor().bytes),
        if (path.endsWith('/material')) ...{
          'epoch_id': PmId(Uint8List.fromList(List.generate(16, (i) => 48 + i)))
              .wire,
          'password_envelope': encodeWire(
            Uint8List.fromList([
              for (var i = 0; i < vector.length; i += 2)
                int.parse(vector.substring(i, i + 2), radix: 16),
            ]),
          ),
        },
      };
    if (path == '/auth/login')
      return {
        'account_id': ids.account.wire,
        'vault_id': ids.vault.wire,
        'access_token': Secret.random().wire,
        'refresh_token': Secret.random().wire,
      };
    if (path == '/auth/logout') return {};
    throw const AccountFailure(404);
  }
}

class MemoryVaultApi extends AccountClient {
  MemoryVaultApi() : super(FixtureTransport(), vaultConfig());
  final objects = <String, Map<String, dynamic>>{};
  final confirmations = <String, Map<String, dynamic>>{};
  final serializedWrites = <String>[];
  BigInt sequence = BigInt.zero;
  bool loseResponse = false, corruptLast = false, failSecondPage = false;
  @override
  Future<Map<String, dynamic>> vaultRequest(
    UnlockedAccount account,
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? query,
    Map<String, String> headers = const {},
    int expected = 200,
  }) async {
    if (account.locked) throw const AccountFailure(401);
    if (path == '/vault/state')
      return {
        'server_id': account.identity.server.wire,
        'account_id': account.identity.account.wire,
        'vault_id': account.identity.vault.wire,
        'epoch_id': account.epoch.wire,
        'credential_generation': '1',
        'collection_revision': sequence.toString(),
        'object_count': objects.length,
      };
    if (path == '/vault/sync') {
      final after = BigInt.parse(query!['after_sequence']!);
      if (failSecondPage && after > BigInt.zero)
        throw const AccountFailure(409);
      final remaining =
          objects.values
              .where(
                (value) => BigInt.parse(value['sequence'] as String) > after,
              )
              .toList()
            ..sort(
              (a, b) =>
                  BigInt.parse(a['sequence'] as String)
                      .compareTo(BigInt.parse(b['sequence'] as String)),
            );
      final items = remaining
          .take(1)
          .map((value) => Map<String, dynamic>.from(value))
          .toList();
      if (corruptLast && remaining.length == 1 && items.isNotEmpty) {
        final blob = decodeWire(items[0]['envelope'] as String);
        blob[blob.length - 1] ^= 1;
        items[0]['envelope'] = encodeWire(blob);
      }
      return {
        'epoch_id': account.epoch.wire,
        'snapshot_revision': sequence.toString(),
        'items': items,
        'next_after_sequence': remaining.length > 1
            ? items.last['sequence']
            : null,
      };
    }
    serializedWrites.add(
      jsonEncode({
        'method': method,
        'path': path,
        'body': body,
        'headers': headers,
      }),
    );
    final key = headers['Idempotency-Key']!;
    if (confirmations.containsKey(key)) return confirmations[key]!;
    final id = method == 'POST'
        ? body!['object_id'] as String
        : path.split('/').last;
    final current = objects[id];
    final revision = current == null
        ? BigInt.one
        : BigInt.parse(current['revision'] as String) + BigInt.one;
    if (method == 'PUT' &&
        headers['If-Match'] !=
            '"o:${account.epoch.wire}:${current!['revision']}"')
      throw const AccountFailure(412);
    sequence += BigInt.one;
    objects[id] = {
      'object_id': id,
      'revision': revision.toString(),
      'sequence': sequence.toString(),
      'envelope': body!['envelope'],
    };
    final confirmation = {
      'epoch_id': account.epoch.wire,
      'object_id': id,
      'revision': revision.toString(),
      'sequence': sequence.toString(),
      'collection_revision': sequence.toString(),
    };
    confirmations[key] = confirmation;
    if (loseResponse) {
      loseResponse = false;
      throw const AccountFailure(0);
    }
    return confirmation;
  }
}
