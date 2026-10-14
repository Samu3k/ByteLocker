import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/connection/server_address.dart';
import 'package:password_manager/connection/server_config.dart';
import 'package:password_manager/connection/strict_json.dart';

import 'fixtures.dart';

void main() {
  test('Origins are HTTPS, credential-free and contain no path or query', () {
    final address = ServerAddress.parse(' https://Vault.Example.com:8443/ ');
    expect(address.origin.toString(), 'https://vault.example.com:8443');
    expect(
      address.discoveryUri.toString(),
      'https://vault.example.com:8443/api/v1/config',
    );
    for (final url in [
      '',
      'vault.example.com',
      'http://vault.example.com',
      'https://user:pass@vault.example.com',
      'https://vault.example.com?token=x',
      'https://vault.example.com#x',
      'https://vault.example.com/api',
      'https://vault.example.com/a/..',
      'https://vault.example.com:0',
      'https://vault.example.com:65536',
      'https://vault.example.com:0443',
      'https://-bad.example.com',
      'https://vault..example.com',
      'https://vault.example.com/%2e%2e',
      'https://vault.example.com\\evil',
      'https://vault.example.com\n.evil',
    ]) {
      expect(
        () => ServerAddress.parse(url),
        throwsFormatException,
        reason: url,
      );
    }
  });

  test(
    'Development HTTP is opt-in and restricted to literal local targets',
    () {
      for (final host in ['localhost', '127.0.0.1', '[::1]', '10.0.2.2']) {
        expect(
          () => ServerAddress.parse('http://$host:8080'),
          throwsFormatException,
        );
        expect(
          ServerAddress.parse(
            'http://$host:8080',
            allowLocalHttp: true,
          ).isSecure,
          isFalse,
        );
      }
      for (final host in [
        '192.168.1.1',
        'localhost.evil.com',
        '127.0.0.1.evil.com',
        'example.com',
      ]) {
        expect(
          () => ServerAddress.parse('http://$host:8080', allowLocalHttp: true),
          throwsFormatException,
        );
      }
    },
  );

  test('Discovery accepts the implemented protocol and safe KDF profiles', () {
    final config = ServerConfig.decode(configBytes());
    expect(config.registrationAvailable, isTrue);
    expect(config.defaultProfile.memoryKiB, 65536);
    expect(config.profiles, hasLength(1));
    final fixture = configFixture()..['future_field'] = 'compatible extension';
    expect(ServerConfig.decode(configBytes(fixture)).serverId, config.serverId);
  });

  test('Incompatible versions and unsafe KDF values are rejected', () {
    for (final field in [
      'api_version',
      'crypto_protocol',
      'envelope_format',
      'registration_mode',
      'email_verification',
    ]) {
      final fixture = configFixture()..[field] = 'unknown';
      expect(
        () => ServerConfig.decode(configBytes(fixture)),
        throwsA(
          isA<ConfigurationException>().having(
            (e) => e.failure,
            'failure',
            ConfigurationFailure.unsupported,
          ),
        ),
      );
    }
    for (final memory in [1, 65535, 65537, 1048576]) {
      final fixture = configFixture();
      fixture['default_kdf_profile'] = {
        'memory_kib': memory,
        'iterations': 3,
        'parallelism': 4,
        'argon_version': 19,
      };
      expect(
        () => ServerConfig.decode(configBytes(fixture)),
        throwsA(isA<ConfigurationException>()),
      );
    }
  });

  test(
    'Malformed types, ambiguous JSON and invalid identities fail closed',
    () {
      for (final change in <void Function(Map<String, Object?>)>[
        (f) => f['server_id'] = 'AAAAAAAAAAAAAAAAAAAAAA',
        (f) => f['server_id'] = 'AQEBAQEBAQEBAQEBAQEBAQ==',
        (f) => f['registration_available'] = 'true',
        (f) => f['features'] = <String, Object?>{},
        (f) => f['kdf_profiles'] = <Object?>[],
        (f) => f['kdf_profiles'] = [
          f['default_kdf_profile'],
          f['default_kdf_profile'],
        ],
        (f) => f['default_kdf_profile'] = {
          'memory_kib': 131072,
          'iterations': 3,
          'parallelism': 4,
          'argon_version': 19,
        },
      ]) {
        final fixture = configFixture();
        change(fixture);
        expect(
          () => ServerConfig.decode(configBytes(fixture)),
          throwsA(isA<ConfigurationException>()),
        );
      }
      for (final source in [
        r'{"a":1,"a":2}',
        r'{"a":1,"\u0061":2}',
        r'{"outer":[{"x":1,"x":2}]}',
        '{"x":',
        '{"x":1,}',
        '[1,]',
        '{',
        '[',
        '',
        'true false',
        '${'[' * 34}0${']' * 34}',
      ]) {
        expect(
          () => decodeStrictJson(Uint8List.fromList(utf8.encode(source))),
          throwsFormatException,
          reason: source,
        );
      }
      expect(
        () => decodeStrictJson(Uint8List.fromList([0xff])),
        throwsFormatException,
      );
      expect(() => decodeStrictJson(Uint8List(65537)), throwsFormatException);
      expect(
        decodeStrictJson(
          Uint8List.fromList(utf8.encode(r'{"a":[1,true,null,"x\"y"]}')),
        ),
        isA<Map<String, dynamic>>(),
      );
    },
  );
}
