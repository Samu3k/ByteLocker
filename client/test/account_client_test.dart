import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/account/account_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';
import 'package:password_manager/crypto/pm1.dart';

import 'fixtures.dart';

void main() {
  test('legacy session quota is identified from a bounded server problem without exposing arbitrary text', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    var response = <String, Object>{'status': 409, 'code': 'session_limit'};
    server.listen((request) async {
      await request.drain<void>();
      request.response.statusCode = 409;
      request.response.headers.contentType = ContentType(
        'application',
        'problem+json',
      );
      request.response.write(jsonEncode(response));
      await request.response.close();
    });
    final transport = AccountTransport(
      ServerAddress.parse(
        'http://127.0.0.1:${server.port}',
        allowLocalHttp: true,
      ),
    );
    await expectLater(
      transport.request('POST', '/auth/login', body: {}),
      throwsA(
        isA<AccountFailure>().having((e) => e.code, 'code', 'session_limit'),
      ),
    );
    response = {'status': 401, 'code': 'session_limit'};
    await expectLater(
      transport.request('POST', '/auth/login', body: {}),
      throwsA(isA<AccountFailure>().having((e) => e.code, 'code', isNull)),
    );
    response = {'status': 409, 'code': 'arbitrary-private-message'};
    await expectLater(
      transport.request('POST', '/auth/login', body: {}),
      throwsA(isA<AccountFailure>().having((e) => e.code, 'code', isNull)),
    );
  });
  test(
    'registration, email confirmation, login and local lock over native HTTP',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final configJson = Map<String, dynamic>.from(configFixture())
        ..['registration_available'] = true;
      final config = ServerConfig.decode(
        Uint8List.fromList(utf8.encode(jsonEncode(configJson))),
      );
      final accountId = PmId.random(), registrationId = PmId.random();
      final pendingToken = Secret.random(),
          accessToken = Secret.random(),
          refreshToken = Secret.random();
      final bodies = <String>[];
      String? vaultId, descriptor, auth, envelope, epoch;
      var verified = false, revoked = false, tamper = false;
      final requests = server.listen((request) async {
        try {
          final raw = await utf8.decoder.bind(request).join();
          bodies.add(raw);
          final body = raw.isEmpty
              ? <String, dynamic>{}
              : jsonDecode(raw) as Map<String, dynamic>;
          Map<String, dynamic> response = {};
          request.response.headers.contentType = ContentType.json;
          final path = request.uri.path;
          if (path == '/api/v1/registrations') {
            vaultId = body['vault_id'] as String;
            response = {
              'registration_id': registrationId.wire,
              'registration_token': pendingToken.wire,
              'server_id': config.serverId,
              'account_id': accountId.wire,
              'vault_id': vaultId,
              'credential_generation': '1',
            };
            request.response.statusCode = 201;
          } else if (path.endsWith('/material') && request.method == 'PUT') {
            expect(
              request.headers.value('authorization'),
              'Registration ${pendingToken.wire}',
            );
            descriptor = body['password_descriptor'] as String;
            auth = body['auth_secret'] as String;
            envelope = body['password_envelope'] as String;
            epoch = body['epoch_id'] as String;
            request.response.statusCode = 202;
          } else if (path.endsWith('/verify')) {
            expect(body['code'], '12345678');
            verified = true;
            request.response.statusCode = 204;
          } else if (path.endsWith('/prelogin')) {
            response = {
              'server_id': config.serverId,
              'account_id': accountId.wire,
              'vault_id': vaultId,
              'credential_generation': '1',
              'password_descriptor': descriptor,
            };
          } else if (path.endsWith('/login')) {
            expect(verified, isTrue);
            if (body['auth_secret'] != auth) {
              request.response.statusCode = 401;
            } else {
              response = {
                'account_id': accountId.wire,
                'vault_id': vaultId,
                'access_token': accessToken.wire,
                'refresh_token': refreshToken.wire,
              };
            }
          } else if (path == '/api/v1/account/material') {
            expect(
              request.headers.value('authorization'),
              'Bearer ${accessToken.wire}',
            );
            final cipher = decodeWire(envelope!);
            if (tamper) cipher[cipher.length - 1] ^= 1;
            response = {
              'server_id': config.serverId,
              'account_id': accountId.wire,
              'vault_id': vaultId,
              'credential_generation': '1',
              'password_descriptor': descriptor,
              'epoch_id': epoch,
              'password_envelope': encodeWire(cipher),
            };
          } else if (path.endsWith('/logout')) {
            revoked = true;
            request.response.statusCode = 204;
          } else {
            request.response.statusCode = 404;
          }
          if (request.response.statusCode != 204)
            request.response.write(jsonEncode(response));
          await request.response.close();
        } catch (_) {
          request.response.statusCode = 500;
          await request.response.close();
          rethrow;
        }
      });
      addTearDown(requests.cancel);
      final address = ServerAddress.parse(
        'http://127.0.0.1:${server.port}',
        allowLocalHttp: true,
      );
      final client = AccountClient(AccountTransport(address), config);
      const password = 'Test-only registration password!';
      final pending = await client.register(
        ' User@Example.com ',
        password,
        Secret.random().wire,
      );
      expect(pending.email, 'user@example.com');
      await client.verify(pending, '12345678');
      final account = await client.login('user@example.com', password);
      expect(account.locked, isFalse);
      expect(account.vaultKey.copyBytes().length, 32);
      expect(bodies.any((body) => body.contains(password)), isFalse);
      await expectLater(
        client.login('user@example.com', 'wrong password'),
        throwsA(isA<AccountFailure>()),
      );
      tamper = true;
      await expectLater(
        client.login('user@example.com', password),
        throwsA(isA<CryptoFailure>()),
      );
      await client.logout(account);
      expect(revoked, isTrue);
      expect(account.locked, isTrue);
      expect(account.vaultKey.copyBytes, throwsStateError);
    },
  );

  test(
    'transport rejects redirects and malformed successful responses',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      var hits = 0;
      final requests = server.listen((request) async {
        hits++;
        if (request.uri.path.endsWith('/redirect')) {
          request.response.statusCode = 302;
          request.response.headers.set('location', '/api/v1/stolen');
        } else {
          request.response.headers.contentType = ContentType.json;
          request.response.write('{"access_token":"a","access_token":"b"}');
        }
        await request.response.close();
      });
      addTearDown(requests.cancel);
      final transport = AccountTransport(
        ServerAddress.parse(
          'http://127.0.0.1:${server.port}',
          allowLocalHttp: true,
        ),
      );
      await expectLater(
        transport.request(
          'POST',
          '/redirect',
          body: {'auth_secret': 'synthetic'},
        ),
        throwsA(isA<AccountFailure>()),
      );
      expect(hits, 1);
      await expectLater(
        transport.request('GET', '/malformed'),
        throwsA(isA<AccountFailure>()),
      );
    },
  );
}
