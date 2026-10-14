import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/app.dart';
import 'package:password_manager/connection/discovery_client.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';

import 'fixtures.dart';

class NoDefaultServerDiscovery implements ServerDiscovery {
  int calls = 0;
  @override
  Future<ServerConfig> discover(ServerAddress address) async {
    calls++;
    throw StateError(
      'The fresh client must wait for the user to choose a server',
    );
  }
}

void main() {
  testWidgets(
    'fresh installation starts with an empty server and performs no discovery',
    (tester) async {
      final discovery = NoDefaultServerDiscovery();
      await tester.pumpWidget(
        ByteLockerApp(discovery: discovery, linkedStore: const DisabledLinks()),
      );
      await tester.pumpAndSettle();
      expect(discovery.calls, 0);
      final address = tester.widget<TextFormField>(
        find.byType(TextFormField).first,
      );
      expect(address.controller!.text, isEmpty);
      await tester.pump(const Duration(seconds: 5));
      expect(discovery.calls, 0);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
