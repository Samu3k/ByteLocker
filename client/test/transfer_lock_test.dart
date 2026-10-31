import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:password_manager/transfer/transfer_dialog.dart';
import 'package:password_manager/transfer/transfer_files.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

class DeferredExport extends TransferFiles {
  final destination = Completer<String?>();
  int writes = 0;
  @override
  Future<String?> chooseExport() => destination.future;
  @override
  Future<void> write(String destination, Uint8List bytes) async {
    writes++;
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'locking during file selection prevents reading the selected CSV',
    () async {
      final selected = Completer<String?>();
      var allowed = true;
      const channel = MethodChannel('bytelocker/files');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            expect(call.method, 'chooseCsvImport');
            return selected.future;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final pending = const TransferFiles().readCsv(isAllowed: () => allowed);
      allowed = false;
      selected.complete('this-file-must-never-be-read.csv');
      expect(await pending, isNull);
    },
  );
  testWidgets(
    'locking while the save dialog is open prevents plaintext export',
    (tester) async {
      final api = MemoryVaultApi();
      late VaultClient vault;
      await tester.runAsync(() async {
        final account = await api.login(
          'test@example.test',
          'Test-only master password 2026!',
        );
        vault = VaultClient(api, account);
        await vault.reload();
        await vault.save(
          VaultRecord(title: 'Synthetic', password: 'never-export-after-lock'),
        );
      });
      final files = DeferredExport();
      addTearDown(vault.dispose);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: TransferDialog(vault: vault, exporting: true, files: files),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Conferma esportazione'));
      await tester.pump();
      vault.account.lock();
      files.destination.complete('synthetic-destination.csv');
      await tester.pumpAndSettle();
      expect(files.writes, 0);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox());
    },
  );
}
