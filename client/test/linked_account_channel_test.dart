import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/linked_account.dart';
import 'package:password_manager/connection/server_address.dart';

import 'crypto_test.dart' show identity;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('bytelocker/security');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test(
    'Windows channel saves only identity and restores it in a new store',
    () async {
      String? persisted;
      messenger.setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'saveLinkedAccount') {
          persisted = call.arguments as String;
          return null;
        }
        if (call.method == 'linkedAccount') return persisted;
        throw MissingPluginException();
      });
      expect(await const LinkedAccountStore().load(), isNull);
      final linked = LinkedAccount(
        address: ServerAddress.parse('https://vault.example.com'),
        serverId: identity().server.wire,
        accountId: identity().account.wire,
        vaultId: identity().vault.wire,
        email: 'test@example.test',
      );
      await const LinkedAccountStore().save(linked);
      expect(jsonDecode(persisted!), linked.encode());
      final restored = await const LinkedAccountStore().load();
      expect(restored!.encode(), linked.encode());
    },
    skip: !Platform.isWindows,
  );

  test(
    'Windows channel fails closed for corrupt or expanded profiles',
    () async {
      for (final value in ['not JSON', '[]', '{"schema":1}', 'x' * 4097]) {
        messenger.setMockMethodCallHandler(channel, (_) async => value);
        await expectLater(
          const LinkedAccountStore().load(),
          throwsFormatException,
        );
      }
    },
    skip: !Platform.isWindows,
  );

  test(
    'Windows storage errors propagate instead of claiming a saved account',
    () async {
      messenger.setMockMethodCallHandler(channel, (_) async {
        throw PlatformException(code: 'profile_write');
      });
      final linked = LinkedAccount(
        address: ServerAddress.parse('https://vault.example.com'),
        serverId: identity().server.wire,
        accountId: identity().account.wire,
        vaultId: identity().vault.wire,
        email: 'test@example.test',
      );
      await expectLater(
        const LinkedAccountStore().save(linked),
        throwsA(isA<PlatformException>()),
      );
    },
    skip: !Platform.isWindows,
  );
}
