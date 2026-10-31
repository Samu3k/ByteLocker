import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/updates/update_manifest.dart';
import 'package:password_manager/updates/update_controller.dart';
import 'package:password_manager/updates/update_banner.dart';

void main() {
  Future<(Uint8List, String)> fixture({
    String? url,
    String expires = '2026-11-05T00:00:00Z',
  }) async {
    final algorithm = Ed25519(), pair = await Ed25519().newKeyPair();
    final key = await pair.extractPublicKey();
    final payload = utf8.encode(
      jsonEncode({
        'schema': 1,
        'version': '0.4.1',
        'build': 10,
        'platform': 'windows-x64',
        'url': url ?? 'https://github.com/Samu3k/ByteLocker/releases/download/v0.4.1/ByteLocker-Windows-0.4.1.zip',
        'sha256': List.filled(64, 'a').join(),
        'size': 1024,
        'expires': expires,
        'files': <Object>[],
      }),
    );
    final signature = await algorithm.sign(payload, keyPair: pair);
    return (
      Uint8List.fromList(
        utf8.encode(
          jsonEncode({
            'schema': 1,
            'payload': base64Encode(payload),
            'signature': base64Encode(signature.bytes),
          }),
        ),
      ),
      base64Encode(key.bytes),
    );
  }

  test('update trust rejects tampering, wrong signer, expired manifests and foreign download URLs', () async {
    final (data, key) = await fixture();
    final now = DateTime.utc(2026, 10, 31);
    final valid = await UpdateManifest.verify(
      data,
      platform: 'windows-x64',
      publicKey: key,
      now: now,
    );
    expect(valid.build, 10);
    final wrapper = jsonDecode(utf8.decode(data)) as Map<String, dynamic>;
    final payload = base64Decode(wrapper['payload'] as String);
    payload[20] ^= 1;
    wrapper['payload'] = base64Encode(payload);
    await expectLater(
      UpdateManifest.verify(
        Uint8List.fromList(utf8.encode(jsonEncode(wrapper))),
        platform: 'windows-x64',
        publicKey: key,
        now: now,
      ),
      throwsA(isA<UpdateFailure>()),
    );
    final (_, otherKey) = await fixture();
    await expectLater(
      UpdateManifest.verify(
        data,
        platform: 'windows-x64',
        publicKey: otherKey,
        now: now,
      ),
      throwsA(isA<UpdateFailure>()),
    );
    await expectLater(
      UpdateManifest.verify(
        data,
        platform: 'windows-x64',
        publicKey: key,
        now: DateTime.utc(2026, 12),
      ),
      throwsA(isA<UpdateFailure>()),
    );
    final (foreign, foreignKey) = await fixture(
      url: 'https://example.test/installer.exe',
    );
    await expectLater(
      UpdateManifest.verify(
        foreign,
        platform: 'windows-x64',
        publicKey: foreignKey,
        now: now,
      ),
      throwsA(isA<UpdateFailure>()),
    );
  });
  testWidgets(
    'update banner fits small and desktop screens and can be dismissed',
    (tester) async {
      final (data, key) = await fixture();
      final update = await UpdateManifest.verify(
        data,
        platform: 'windows-x64',
        publicKey: key,
        now: DateTime.utc(2026, 10, 31),
      );
      final controller = UpdateController()..available = update;
      addTearDown(controller.dispose);
      for (final width in [360.0, 1280.0]) {
        controller.available = update;
        await tester.binding.setSurfaceSize(Size(width, 800));
        await tester.pumpWidget(
          UpdateScope(
            updates: controller,
            child: MaterialApp(
              home: UpdateOverlay(
                child: const Scaffold(body: Text('Vault placeholder')),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.textContaining('0.4.1'), findsOneWidget);
        expect(tester.takeException(), isNull);
        await tester.tap(find.text('Più tardi'));
        await tester.pumpAndSettle();
        expect(find.textContaining('0.4.1'), findsNothing);
      }
      await tester.pumpWidget(const SizedBox());
      await tester.binding.setSurfaceSize(null);
    },
  );
}
