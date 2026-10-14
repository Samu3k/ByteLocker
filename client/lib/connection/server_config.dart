import 'dart:convert';
import 'dart:typed_data';

import 'strict_json.dart';

enum ConfigurationFailure { malformed, unsupported }

final class ConfigurationException implements Exception {
  const ConfigurationException(this.failure);
  final ConfigurationFailure failure;
}

final class KdfProfile {
  const KdfProfile(
    this.memoryKiB,
    this.iterations,
    this.parallelism,
    this.version,
  );
  final int memoryKiB, iterations, parallelism, version;
  bool matches(KdfProfile other) =>
      memoryKiB == other.memoryKiB &&
      iterations == other.iterations &&
      parallelism == other.parallelism &&
      version == other.version;

  static KdfProfile parse(Object? value) {
    if (value is! Map<String, dynamic>)
      throw const FormatException('KDF object');
    final memory = value['memory_kib'];
    final iterations = value['iterations'];
    final parallelism = value['parallelism'];
    final version = value['argon_version'];
    if (memory is! int ||
        iterations is! int ||
        parallelism is! int ||
        version is! int)
      throw const FormatException('KDF integers');
    if (!const [65536, 131072, 262144].contains(memory) ||
        iterations != 3 ||
        parallelism != 4 ||
        version != 19) {
      throw const ConfigurationException(ConfigurationFailure.unsupported);
    }
    return KdfProfile(memory, iterations, parallelism, version);
  }
}

/// Discovery is compatibility data, never proof that an invite or login is valid.
final class ServerConfig {
  ServerConfig._(
    this.serverId,
    this.registrationAvailable,
    this.profiles,
    this.defaultProfile,
  );
  final String serverId;
  final bool registrationAvailable;
  final List<KdfProfile> profiles;
  final KdfProfile defaultProfile;

  static ServerConfig decode(Uint8List bytes) {
    try {
      final value = decodeStrictJson(bytes);
      if (value is! Map<String, dynamic>)
        throw const FormatException('Config object');
      for (final key in [
        'api_version',
        'crypto_protocol',
        'envelope_format',
        'registration_mode',
        'email_verification',
      ]) {
        if (value[key] is! String) throw const FormatException('Config string');
      }
      if (value['api_version'] != '1' ||
          value['crypto_protocol'] != 'PM1' ||
          value['envelope_format'] != 'PME1' ||
          value['registration_mode'] != 'invitation' ||
          value['email_verification'] != 'registration_only') {
        throw const ConfigurationException(ConfigurationFailure.unsupported);
      }
      final id = value['server_id'];
      if (id is! String || !RegExp(r'^[A-Za-z0-9_-]{22}$').hasMatch(id)) {
        throw const FormatException('Server identity');
      }
      final decoded = base64Url.decode('$id==');
      if (decoded.length != 16 ||
          decoded.every((byte) => byte == 0) ||
          base64Url.encode(decoded).replaceAll('=', '') != id) {
        throw const FormatException('Canonical server identity');
      }
      final available = value['registration_available'];
      final features = value['features'];
      if (available is! bool ||
          features is! Map<String, dynamic> ||
          features['offline_sync'] is! bool ||
          features['recovery'] is! bool ||
          features['shared_vaults'] is! bool) {
        throw const FormatException('Feature flags');
      }
      final rawProfiles = value['kdf_profiles'];
      if (rawProfiles is! List<dynamic> ||
          rawProfiles.isEmpty ||
          rawProfiles.length > 3) {
        throw const FormatException('KDF list');
      }
      final profiles = rawProfiles
          .map(KdfProfile.parse)
          .toList(growable: false);
      if (profiles.map((profile) => profile.memoryKiB).toSet().length !=
          profiles.length) {
        throw const FormatException('Duplicate KDF profile');
      }
      final defaultProfile = KdfProfile.parse(value['default_kdf_profile']);
      if (!profiles.any((profile) => profile.matches(defaultProfile))) {
        throw const FormatException('Default KDF not advertised');
      }
      return ServerConfig._(
        id,
        available,
        List.unmodifiable(profiles),
        defaultProfile,
      );
    } on ConfigurationException {
      rethrow;
    } on FormatException {
      throw const ConfigurationException(ConfigurationFailure.malformed);
    }
  }
}
