import 'dart:io';

import 'package:flutter/material.dart';

import 'dart:typed_data';

import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/vault/credential_logo.dart';
import 'package:password_manager/vault/vault_record.dart';

void main() {
  test('brand recognition uses URL first and exact domain boundaries', () {
    expect(
      brandFor(
        VaultRecord(
          title: 'Personal account',
          url: 'https://mail.google.com/mail',
        ),
      )?.slug,
      'gmail',
    );
    expect(
      brandFor(VaultRecord(title: 'Google', url: 'https://github.com/login'))
          ?.slug,
      'github',
    );
    expect(
      brandFor(VaultRecord(title: 'work', url: 'GitHub.com/account'))?.slug,
      'github',
    );
    expect(brandFor(VaultRecord(title: 'Gmail personale'))?.slug, 'gmail');
    expect(
      brandFor(
        VaultRecord(
          title: 'Jellyfin di casa',
          url: 'https://media.example.test',
        ),
      )?.slug,
      'jellyfin',
    );
    expect(
      brandFor(VaultRecord(title: 'my account', url: 'https://mail.proton.me'))
          ?.slug,
      'protonmail',
    );
    for (final url in [
      'https://github.com.evil.test',
      'https://fakegithub.com',
      'https://github.com@evil.test',
      'https://evil.test/#github.com',
      'ftp://github.com',
      'https://github.com:notaport',
      'https://%xx',
    ]) {
      expect(
        brandFor(VaultRecord(title: 'GitHub', url: url)),
        isNull,
        reason: url,
      );
    }
    expect(
      brandFor(
        VaultRecord(title: 'Uncatalogued service', url: 'https://example.test'),
      ),
      isNull,
    );
  });

  testWidgets(
    'bundled logos render without network and unknown services use initials',
    (tester) async {
      final previous = HttpOverrides.current;
      HttpOverrides.global = DenyNetwork();
      addTearDown(() => HttpOverrides.global = previous);
      expect(brandLogos.length, greaterThan(3000));
      for (final brand in brandLogos) {
        if (brand.fullColor) {
          final bytes = ByteData.sublistView(
            File(brand.asset).readAsBytesSync(),
          );
          expect(bytes.getUint32(0), 0x89504e47);
          continue;
        }
        final artwork = File(brand.asset).readAsStringSync();
        expect(artwork.contains('<svg'), isTrue);
        expect(
          RegExp(
            r'<script|<image|<use\b|href=',
            caseSensitive: false,
          ).hasMatch(artwork),
          isFalse,
        );
      }
      for (final brand in brandLogos.where(
        (brand) =>
            brand.fullColor ||
            const [
              'protonmail',
              'homeassistant',
              '1password',
              'airbnb',
              'ebay',
            ].contains(brand.slug),
      )) {
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: CredentialLogo(
                record: VaultRecord(title: brand.name, logo: brand.slug),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(
          find.byKey(ValueKey('credential-logo-${brand.slug}')),
          findsOneWidget,
        );
        expect(
          find.byType(brand.fullColor ? Image : SvgPicture),
          findsOneWidget,
        );
        expect(tester.takeException(), isNull);
      }
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: CredentialLogo(
              record: VaultRecord(
                title: 'Example',
                url: 'https://example.test',
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('credential-logo-generic')),
        findsOneWidget,
      );
      expect(find.text('E'), findsOneWidget);
      expect(find.byType(SvgPicture), findsNothing);
    },
  );

  test('expanded domains, overrides and specific services resolve deterministically', () {
    for (final pair in [
      ('https://amazon.it/ap/signin', 'amazon'),
      ('https://outlook.live.com', 'microsoft-outlook'),
      ('https://accounts.google.it', 'google'),
      ('https://drive.google.com', 'google-drive'),
      ('https://chatgpt.com', 'chatgpt'),
      ('https://www.airbnb.com', 'airbnb'),
      ('https://www.ebay.it', 'ebay'),
    ])
      expect(
        brandFor(VaultRecord(title: 'Account', url: pair.$1))?.slug,
        pair.$2,
      );
    expect(
      brandFor(
        VaultRecord(
          title: 'Private server',
          url: 'https://example.test',
          logo: 'immich',
        ),
      )?.slug,
      'immich',
    );
    expect(
      brandFor(
        VaultRecord(
          title: 'Google',
          url: 'https://google.com',
          logo: 'generic',
        ),
      ),
      isNull,
    );
    expect(
      brandFor(VaultRecord(title: 'Unknown', logo: 'removed-brand')),
      isNull,
    );
    for (final url in [
      'https://amazon.it.evil.test',
      'https://google.com:99999',
      'https://outlook.live.com@evil.test',
    ]) {
      expect(brandFor(VaultRecord(title: 'Account', url: url)), isNull);
    }
  });
}

class DenyNetwork extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) =>
      throw StateError('Brand logos must never contact the network');
}
