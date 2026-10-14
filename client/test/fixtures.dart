import 'package:password_manager/account/linked_account.dart';

import 'dart:convert';
import 'dart:typed_data';

Map<String, Object?> configFixture() {
  final profile = <String, Object?>{
    'memory_kib': 65536,
    'iterations': 3,
    'parallelism': 4,
    'argon_version': 19,
  };
  return {
    'api_version': '1',
    'crypto_protocol': 'PM1',
    'envelope_format': 'PME1',
    'server_id': base64Url.encode(List<int>.filled(16, 1)).replaceAll('=', ''),
    'registration_mode': 'invitation',
    'email_verification': 'registration_only',
    'registration_available': true,
    'kdf_profiles': [profile],
    'default_kdf_profile': profile,
    'features': {
      'offline_sync': false,
      'recovery': false,
      'shared_vaults': false,
    },
  };
}

Uint8List configBytes([Map<String, Object?>? config]) =>
    Uint8List.fromList(utf8.encode(jsonEncode(config ?? configFixture())));

class DisabledLinks extends LinkedAccountStore {
  const DisabledLinks();
  @override
  bool get supported => false;
}
