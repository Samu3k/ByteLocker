import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/connection/discovery_client.dart';
import 'package:password_manager/connection/server_address.dart';

import 'fixtures.dart';

void main() {
  Future<HttpServer> serve(Future<void> Function(HttpRequest) handle) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final subscription = server.listen((request) {
      unawaited(handle(request));
    });
    addTearDown(() async {
      await server.close(force: true);
      await subscription.cancel();
    });
    return server;
  }

  ServerAddress address(HttpServer server) => ServerAddress.parse(
    'http://127.0.0.1:${server.port}',
    allowLocalHttp: true,
  );
  test(
    'Native transport sends only a discovery GET with no credentials',
    () async {
      final server = await serve((request) async {
        expect(request.method, 'GET');
        expect(request.uri.path, '/api/v1/config');
        expect(request.uri.hasQuery, isFalse);
        expect(request.headers.value('authorization'), isNull);
        expect(request.headers.value('cookie'), isNull);
        request.response.headers.contentType = ContentType.json;
        request.response.add(configBytes());
        await request.response.close();
      });
      expect(
        (await DiscoveryClient().discover(address(server)))
            .registrationAvailable,
        isTrue,
      );
    },
  );
  test('Redirect is rejected and the destination is never contacted', () async {
    var calls = 0;
    final target = await serve((request) async {
      calls++;
      request.response.statusCode = 500;
      await request.response.close();
    });
    final server = await serve((request) async {
      request.response.statusCode = 302;
      request.response.headers.set(
        'location',
        'http://127.0.0.1:${target.port}/',
      );
      await request.response.close();
    });
    await expectLater(
      DiscoveryClient().discover(address(server)),
      throwsA(
        isA<DiscoveryException>().having(
          (e) => e.failure,
          'failure',
          DiscoveryFailure.redirect,
        ),
      ),
    );
    expect(calls, 0);
  });
  test('Chunked responses are bounded even without Content-Length', () async {
    final server = await serve((request) async {
      request.response.headers.contentType = ContentType.json;
      request.response.add(List<int>.filled(65537, 32));
      await request.response.close();
    });
    await expectLater(
      DiscoveryClient().discover(address(server)),
      throwsA(
        isA<DiscoveryException>().having(
          (e) => e.failure,
          'failure',
          DiscoveryFailure.response,
        ),
      ),
    );
  });
  test('Non-JSON and unsuccessful responses are rejected', () async {
    for (final status in [200, 401, 503]) {
      final server = await serve((request) async {
        request.response.statusCode = status;
        request.response.headers.contentType = ContentType.text;
        request.response.write('<html>not a vault server</html>');
        await request.response.close();
      });
      await expectLater(
        DiscoveryClient().discover(address(server)),
        throwsA(isA<DiscoveryException>()),
      );
    }
  });
  test(
    'Total timeout closes the socket instead of retaining a pending response',
    () async {
      final arrived = Completer<void>();
      final server = await serve((request) async {
        arrived.complete();
        // Deliberately leave the response open; teardown closes the server.
      });
      final pending = DiscoveryClient(
        timeout: const Duration(milliseconds: 500),
      ).discover(address(server));
      await arrived.future;
      await expectLater(
        pending,
        throwsA(
          isA<DiscoveryException>().having(
            (e) => e.failure,
            'failure',
            DiscoveryFailure.timeout,
          ),
        ),
      );
    },
  );
}
