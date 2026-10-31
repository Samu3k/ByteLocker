import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../connection/strict_json.dart';
import 'update_key.dart';

const clientVersion = '0.4.0';
const clientBuild = 9;
const maxManifestBytes = 2 * 1024 * 1024;

class UpdateFailure implements Exception {
  const UpdateFailure();
  @override
  String toString() => 'UpdateFailure';
}

class UpdateManifest {
  UpdateManifest._(
    this.version,
    this.build,
    this.platform,
    this.url,
    this.sha256,
    this.size,
    this.signedBytes,
  );
  final String version, platform, sha256;
  final int build, size;
  final Uri url;
  final Uint8List signedBytes;
  static Future<UpdateManifest> verify(
    Uint8List envelope, {
    required String platform,
    String publicKey = updatePublicKey,
    DateTime? now,
  }) async {
    try {
      final wrapper = decodeStrictJson(envelope, maxBytes: maxManifestBytes);
      if (wrapper is! Map<String, dynamic> ||
          wrapper.length != 3 ||
          wrapper['schema'] != 1 ||
          wrapper['payload'] is! String ||
          wrapper['signature'] is! String)
        throw const UpdateFailure();
      final bytes = base64Decode(wrapper['payload'] as String),
          signature = base64Decode(wrapper['signature'] as String),
          key = base64Decode(publicKey);
      if (key.length != 32 ||
          signature.length != 64 ||
          !await Ed25519().verify(
            bytes,
            signature: Signature(
              signature,
              publicKey: SimplePublicKey(key, type: KeyPairType.ed25519),
            ),
          ))
        throw const UpdateFailure();
      final value = decodeStrictJson(
        Uint8List.fromList(bytes),
        maxBytes: maxManifestBytes,
      );
      if (value is! Map<String, dynamic> ||
          value['schema'] != 1 ||
          value['platform'] != platform ||
          value['version'] is! String ||
          value['build'] is! int ||
          value['size'] is! int ||
          value['sha256'] is! String ||
          value['url'] is! String ||
          value['expires'] is! String ||
          value['files'] is! List)
        throw const UpdateFailure();
      final version = value['version'] as String,
          build = value['build'] as int,
          size = value['size'] as int,
          hash = value['sha256'] as String;
      if (!RegExp(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$').hasMatch(version) ||
          build < 1 ||
          build > 2147483647 ||
          size < 1 ||
          size > 128 * 1024 * 1024 ||
          !RegExp(r'^[a-f0-9]{64}$').hasMatch(hash))
        throw const UpdateFailure();
      final expires = DateTime.parse(value['expires'] as String).toUtc();
      final clock = (now ?? DateTime.now()).toUtc();
      if (!expires.isAfter(clock) ||
          expires.difference(clock) > const Duration(days: 370))
        throw const UpdateFailure();
      final uri = Uri.parse(value['url'] as String);
      final name = platform == 'windows-x64'
          ? 'ByteLocker-Windows-$version.zip'
          : platform == 'android-arm64'
          ? 'ByteLocker-$version-android-arm64.apk'
          : throw const UpdateFailure();
      if (uri.scheme != 'https' ||
          uri.host != 'github.com' ||
          uri.hasPort ||
          uri.userInfo.isNotEmpty ||
          uri.hasQuery ||
          uri.hasFragment ||
          uri.path != '/Samu3k/ByteLocker/releases/download/v$version/$name')
        throw const UpdateFailure();
      return UpdateManifest._(
        version,
        build,
        platform,
        uri,
        hash,
        size,
        Uint8List.fromList(envelope),
      );
    } catch (_) {
      throw const UpdateFailure();
    }
  }
}
