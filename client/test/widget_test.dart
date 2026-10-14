import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/app.dart';
import 'package:password_manager/connection/discovery_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';

import 'fixtures.dart';

class FakeDiscovery implements ServerDiscovery {
  int calls = 0;
  Completer<ServerConfig>? pending;
  DiscoveryFailure? failure;
  @override
  Future<ServerConfig> discover(ServerAddress address) async {
    calls++;
    if (failure != null) throw DiscoveryException(failure!);
    if (pending != null) return pending!.future;
    return ServerConfig.decode(configBytes());
  }
}

void main() {
  testWidgets(
    'Invalid URL does not cause a request; success clears when edited',
    (tester) async {
      final discovery = FakeDiscovery();
      await tester.pumpWidget(
        ByteLockerApp(linkedStore: const DisabledLinks(), discovery: discovery),
      );
      await tester.enterText(
        find.byKey(const Key('server-address')),
        'http://example.com',
      );
      await tester.ensureVisible(find.byKey(const Key('check-server')));
      await tester.tap(find.byKey(const Key('check-server')));
      await tester.pump();
      expect(discovery.calls, 0);
      expect(
        find.textContaining('Inserisci un indirizzo HTTPS'),
        findsOneWidget,
      );
      await tester.enterText(
        find.byKey(const Key('server-address')),
        'https://vault.example.com',
      );
      await tester.tap(find.byKey(const Key('check-server')));
      await tester.pumpAndSettle();
      expect(discovery.calls, 1);
      expect(find.byKey(const Key('connection-success')), findsOneWidget);
      expect(find.text('Connessione HTTPS verificata.'), findsOneWidget);
      await tester.enterText(
        find.byKey(const Key('server-address')),
        'https://other.example.com',
      );
      await tester.pump();
      expect(find.byKey(const Key('connection-success')), findsNothing);
    },
  );
  testWidgets(
    'Loading prevents duplicates and errors do not reveal raw diagnostics',
    (tester) async {
      final discovery = FakeDiscovery()..pending = Completer<ServerConfig>();
      await tester.pumpWidget(
        ByteLockerApp(linkedStore: const DisabledLinks(), discovery: discovery),
      );
      await tester.enterText(
        find.byKey(const Key('server-address')),
        'https://vault.example.com',
      );
      await tester.ensureVisible(find.byKey(const Key('check-server')));
      await tester.tap(find.byKey(const Key('check-server')));
      await tester.pump();
      expect(
        tester
            .widget<FilledButton>(find.byKey(const Key('check-server')))
            .onPressed,
        isNull,
      );
      discovery.pending!.completeError(
        const DiscoveryException(DiscoveryFailure.certificate),
      );
      await tester.pumpAndSettle();
      expect(
        find.textContaining('Il certificato del server non è valido'),
        findsOneWidget,
      );
      expect(discovery.calls, 1);
    },
  );
  testWidgets(
    'Late response after closing the screen does not update disposed state',
    (tester) async {
      final discovery = FakeDiscovery()..pending = Completer<ServerConfig>();
      await tester.pumpWidget(
        ByteLockerApp(linkedStore: const DisabledLinks(), discovery: discovery),
      );
      await tester.enterText(
        find.byKey(const Key('server-address')),
        'https://vault.example.com',
      );
      await tester.ensureVisible(find.byKey(const Key('check-server')));
      await tester.tap(find.byKey(const Key('check-server')));
      await tester.pump();
      await tester.pumpWidget(const SizedBox());
      discovery.pending!.complete(ServerConfig.decode(configBytes()));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
    },
  );
  for (final size in [const Size(360, 800), const Size(1280, 800)]) {
    testWidgets('Responsive layout at ${size.width} with large text', (
      tester,
    ) async {
      await tester.binding.setSurfaceSize(size);
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        MaterialApp(
          home: MediaQuery(
            data: MediaQueryData(
              size: size,
              textScaler: const TextScaler.linear(2),
            ),
            child: ServerConnectionPage(discovery: FakeDiscovery()),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(find.byKey(const Key('check-server')));
      expect(find.byKey(const Key('check-server')), findsOneWidget);
    });
  }
}
