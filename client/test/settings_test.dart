import 'fixtures.dart';

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/app.dart';
import 'package:password_manager/settings/client_settings.dart';

class FakeSecurity extends NativeSecurity {
  String savedTheme = 'dark';
  bool enrolledValue = false;
  Uint8List? sealed;
  @override
  Future<Map<Object?, Object?>> status() async => {
    'theme': savedTheme,
    'biometrics': true,
    'passkeys': true,
  };
  @override
  Future<void> theme(String value) async {
    savedTheme = value;
  }

  @override
  Future<bool> enrolled(String slot) async => enrolledValue;
  @override
  Future<void> enroll(String slot, Uint8List payload) async {
    sealed = Uint8List.fromList(payload);
    enrolledValue = true;
  }

  @override
  Future<Uint8List?> unlock(String slot) async =>
      sealed == null ? null : Uint8List.fromList(sealed!);
  @override
  Future<void> remove(String slot) async {
    sealed?.fillRange(0, sealed!.length, 0);
    sealed = null;
    enrolledValue = false;
  }
}

void main() {
  testWidgets('mobile settings change theme and retain native preference', (
    tester,
  ) async {
    final native = FakeSecurity();
    final settings = ClientSettings(native: native);
    addTearDown(settings.dispose);
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      ByteLockerApp(linkedStore: const DisabledLinks(), settings: settings),
    );
    await tester.pumpAndSettle();
    expect(
      tester.widget<MaterialApp>(find.byType(MaterialApp)).themeMode,
      ThemeMode.dark,
    );
    await tester.tap(find.byTooltip('Impostazioni'));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<ThemeMode>));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Chiaro').last);
    await tester.pumpAndSettle();
    expect(native.savedTheme, 'light');
    expect(
      tester.widget<MaterialApp>(find.byType(MaterialApp)).themeMode,
      ThemeMode.light,
    );
    final reloaded = ClientSettings(native: native);
    await reloaded.load();
    expect(reloaded.mode, ThemeMode.light);
    reloaded.dispose();
    final biometric = tester.widget<SwitchListTile>(
      find.byType(SwitchListTile),
    );
    expect(
      biometric.onChanged,
      isNull,
    ); // Cannot enroll before an account is unlocked.
    expect(find.text('Gestore passkey Android'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox());
  });

  testWidgets('enrollment failure never toggles biometric preference', (
    tester,
  ) async {
    final settings = ClientSettings(native: FakeSecurity());
    await settings.load();
    addTearDown(settings.dispose);
    await tester.pumpWidget(
      SettingsScope(
        settings: settings,
        child: MaterialApp(
          home: Scaffold(
            body: ClientSettingsPanel(
              onClose: () {},
              onBiometrics: (_) async =>
                  throw StateError('synthetic native cancellation'),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.byType(SwitchListTile));
    await tester.pumpAndSettle();
    expect(
      tester.widget<SwitchListTile>(find.byType(SwitchListTile)).value,
      isFalse,
    );
    expect(find.textContaining('Operazione non completata'), findsOneWidget);
    expect(find.textContaining('synthetic native'), findsNothing);
    await tester.pumpWidget(const SizedBox());
  });
}
