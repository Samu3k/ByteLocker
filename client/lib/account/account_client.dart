import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../connection/server_address.dart';
import '../connection/server_config.dart';
import '../connection/strict_json.dart';
import '../crypto/pm1.dart';

final class AccountFailure implements Exception {
  const AccountFailure(this.status, {this.code});
  final int status;
  final String? code;
  @override
  String toString() => 'AccountFailure($status)';
}

/// Native HTTPS transport. No redirects, cookies, credential logging or retries.
/// A fresh connection pool per request also bounds cancellation on timeout.
class AccountTransport {
  AccountTransport(this.address);
  final ServerAddress address;
  Future<Map<String, dynamic>> request(
    String method,
    String path, {
    Map<String, dynamic>? body,
    String? authorization,
    int expected = 200,
    Map<String, String>? query,
    Map<String, String> headers = const {},
    int maxBytes = 65536,
  }) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 5)
      ..autoUncompress = false;
    try {
      return await (() async {
        final request = await client.openUrl(
          method,
          address.origin.replace(path: '/api/v1$path', queryParameters: query),
        );
        request.followRedirects = false;
        request.headers.set(HttpHeaders.acceptHeader, 'application/json');
        request.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
        headers.forEach(request.headers.set);
        if (authorization != null)
          request.headers.set(HttpHeaders.authorizationHeader, authorization);
        if (body != null) {
          final encoded = utf8.encode(jsonEncode(body));
          request.headers.contentType = ContentType.json;
          request.contentLength = encoded.length;
          request.add(encoded);
        }
        final response = await request.close();
        if (response.statusCode != expected) {
          String? code;
          if (response.headers.contentType?.mimeType ==
                  'application/problem+json' &&
              (response.headers.value(HttpHeaders.contentEncodingHeader) ??
                      'identity') ==
                  'identity') {
            final errorBytes = BytesBuilder(copy: false);
            try {
              await for (final chunk in response) {
                if (errorBytes.length + chunk.length > 4096) break;
                errorBytes.add(chunk);
              }
              final problem = decodeStrictJson(
                errorBytes.takeBytes(),
                maxBytes: 4096,
              );
              if (problem is Map<String, dynamic> &&
                  problem['status'] == response.statusCode &&
                  problem['code'] == 'session_limit')
                code = 'session_limit';
            } catch (_) {
              /* Preserve the HTTP status if an error body is malformed. */
            }
          }
          throw AccountFailure(response.statusCode, code: code);
        }
        if (expected == 204) {
          await response.drain<void>();
          return <String, dynamic>{};
        }
        if (response.headers.contentType?.mimeType != 'application/json' ||
            (response.headers.value(HttpHeaders.contentEncodingHeader) ??
                    'identity') !=
                'identity' ||
            response.contentLength > maxBytes) {
          throw const AccountFailure(0);
        }
        final bytes = BytesBuilder(copy: false);
        await for (final chunk in response) {
          if (bytes.length + chunk.length > maxBytes)
            throw const AccountFailure(0);
          bytes.add(chunk);
        }
        final decoded = decodeStrictJson(bytes.takeBytes(), maxBytes: maxBytes);
        if (decoded is! Map<String, dynamic>) throw const AccountFailure(0);
        return decoded;
      })().timeout(const Duration(seconds: 30));
    } on AccountFailure {
      rethrow;
    } catch (_) {
      throw const AccountFailure(0);
    } finally {
      client.close(force: true);
    }
  }
}

String _string(Map<String, dynamic> value, String key) {
  final result = value[key];
  if (result is! String) throw const CryptoFailure();
  return result;
}

BigInt _counter(Map<String, dynamic> value, String key) {
  final raw = _string(value, key);
  if (!RegExp(r'^[1-9][0-9]{0,19}$').hasMatch(raw)) throw const CryptoFailure();
  final number = BigInt.parse(raw);
  if (number > EnvelopeContext.maxU64) throw const CryptoFailure();
  return number;
}

String normalizeEmail(String value) {
  final email = value.trim().toLowerCase();
  if (email.length > 254 ||
      !RegExp(r'^[a-z0-9._+-]{1,64}@[a-z0-9.-]+$').hasMatch(email) ||
      email.split('@').length != 2 ||
      !email.split('@').last.contains('.')) {
    throw const FormatException('Email');
  }
  final parts = email.split('@');
  if (parts.first.startsWith('.') ||
      parts.first.endsWith('.') ||
      parts.first.contains('..') ||
      parts.last
          .split('.')
          .any(
            (label) =>
                label.isEmpty ||
                label.length > 63 ||
                label.startsWith('-') ||
                label.endsWith('-'),
          ))
    throw const FormatException('Email');
  return email;
}

final class PendingAccount {
  PendingAccount._(this.id, this._token, this.email);
  final PmId id;
  final Secret _token;
  final String email;
  void destroy() => _token.destroy();
  @override
  String toString() => 'PendingAccount([REDACTED])';
}

/// No keys or tokens are persisted until a native protected store is implemented.
final class UnlockedAccount {
  UnlockedAccount._(
    this.identity,
    this.epoch,
    this.generation,
    this.vaultKey,
    this._access,
    this._refresh,
    this._authentication,
    this._descriptor,
  );
  final Identity identity;
  final PmId epoch;
  final BigInt generation;
  final Secret vaultKey, _access, _refresh, _authentication;
  final Uint8List _descriptor;
  bool _locked = false;
  bool get locked => _locked;
  void lock() {
    vaultKey.destroy();
    _access.destroy();
    _refresh.destroy();
    _authentication.destroy();
    _descriptor.fillRange(0, _descriptor.length, 0);
    _locked = true;
  }

  @override
  String toString() => 'UnlockedAccount([REDACTED])';
}

class AccountClient {
  AccountClient(this.transport, this.config);
  final AccountTransport transport;
  final ServerConfig config;
  final PasswordEngine _passwords = PasswordEngine();
  final EnvelopeCrypto _crypto = EnvelopeCrypto();
  bool _busy = false;

  Identity _identity(Map<String, dynamic> value) {
    final identity = Identity(
      PmId.parse(_string(value, 'server_id')),
      PmId.parse(_string(value, 'account_id')),
      PmId.parse(_string(value, 'vault_id')),
    );
    if (identity.server.wire != config.serverId) throw const CryptoFailure();
    return identity;
  }

  Future<T> _exclusive<T>(Future<T> Function() operation) async {
    if (_busy) throw StateError('Account operation already running');
    _busy = true;
    try {
      return await operation();
    } finally {
      _busy = false;
    }
  }

  Future<PendingAccount> register(
    String email,
    String password,
    String invitation,
  ) => _exclusive(() async {
    if (!config.registrationAvailable) throw const AccountFailure(404);
    email = normalizeEmail(email);
    final checked = passwordBytes(password, creating: true);
    checked.fillRange(0, checked.length, 0);
    decodeWire(invitation, length: 32);
    final vault = PmId.random();
    final created = await transport.request(
      'POST',
      '/registrations',
      expected: 201,
      body: {
        'email': email,
        'invitation_secret': invitation,
        'vault_id': vault.wire,
      },
    );
    final identity = _identity(created);
    if (!identity.vault.matches(vault) ||
        _counter(created, 'credential_generation') != BigInt.one) {
      throw const CryptoFailure();
    }
    final pending = PendingAccount._(
      PmId.parse(_string(created, 'registration_id')),
      Secret(decodeWire(_string(created, 'registration_token'), length: 32)),
      email,
    );
    PasswordKeys? keys;
    final root = Secret.random();
    try {
      final descriptor = PasswordDescriptor.random(config.defaultProfile);
      keys = await _passwords.derive(
        password,
        identity,
        descriptor,
        creating: true,
      );
      final plain = root.copyBytes();
      late Uint8List envelope;
      final epoch = PmId.random();
      try {
        envelope = await _crypto.encrypt(
          keys.wrapping,
          EnvelopeContext(
            kind: 1,
            identity: identity,
            epoch: epoch,
            generation: BigInt.one,
            metadata: descriptor.bytes,
          ),
          plain,
        );
      } finally {
        plain.fillRange(0, plain.length, 0);
      }
      await transport.request(
        'PUT',
        '/registrations/${pending.id.wire}/material',
        expected: 202,
        authorization: 'Registration ${pending._token.wire}',
        body: {
          'epoch_id': epoch.wire,
          'password_descriptor': encodeWire(descriptor.bytes),
          'auth_secret': keys.authentication.wire,
          'password_envelope': encodeWire(envelope),
        },
      );
      return pending;
    } catch (_) {
      pending.destroy();
      rethrow;
    } finally {
      keys?.destroy();
      root.destroy();
    }
  });

  Future<void> verify(PendingAccount pending, String code) =>
      _exclusive(() async {
        if (!RegExp(r'^[0-9]{8}$').hasMatch(code))
          throw const FormatException('Code');
        await transport.request(
          'POST',
          '/registrations/${pending.id.wire}/verify',
          expected: 204,
          authorization: 'Registration ${pending._token.wire}',
          body: {'code': code},
        );
        pending.destroy();
      });

  Future<void> resend(PendingAccount pending) => _exclusive(() async {
    await transport.request(
      'POST',
      '/registrations/${pending.id.wire}/resend',
      expected: 202,
      authorization: 'Registration ${pending._token.wire}',
      body: {},
    );
  });

  Future<UnlockedAccount> login(
    String email,
    String password,
  ) => _exclusive(() async {
    email = normalizeEmail(email);
    final prelogin = await transport.request(
      'POST',
      '/auth/prelogin',
      body: {'email': email},
    );
    final identity = _identity(prelogin);
    final generation = _counter(prelogin, 'credential_generation');
    final descriptor = PasswordDescriptor.decode(
      decodeWire(_string(prelogin, 'password_descriptor'), length: 30),
    );
    if (!config.profiles.any((p) => p.matches(descriptor.profile)))
      throw const CryptoFailure();
    final keys = await _passwords.derive(password, identity, descriptor);
    Secret? access, refresh;
    try {
      final tokens = await transport.request(
        'POST',
        '/auth/login',
        body: {
          'email': email,
          'account_id': identity.account.wire,
          'vault_id': identity.vault.wire,
          'credential_generation': generation.toString(),
          'auth_secret': keys.authentication.wire,
          'device_id': PmId.random().wire,
          'device_name': 'ByteLocker',
          'platform': Platform.isAndroid ? 'android' : 'windows',
        },
      );
      if (_string(tokens, 'account_id') != identity.account.wire ||
          _string(tokens, 'vault_id') != identity.vault.wire)
        throw const CryptoFailure();
      access = Secret(decodeWire(_string(tokens, 'access_token'), length: 32));
      refresh = Secret(
        decodeWire(_string(tokens, 'refresh_token'), length: 32),
      );
      final material = await transport.request(
        'GET',
        '/account/material',
        authorization: 'Bearer ${access.wire}',
      );
      final actual = _identity(material);
      if (!actual.account.matches(identity.account) ||
          !actual.vault.matches(identity.vault) ||
          _counter(material, 'credential_generation') != generation ||
          !sameBytes(
            decodeWire(_string(material, 'password_descriptor'), length: 30),
            descriptor.bytes,
          )) {
        throw const CryptoFailure();
      }
      final epoch = PmId.parse(_string(material, 'epoch_id'));
      final plaintext = await _crypto.decrypt(
        keys.wrapping,
        EnvelopeContext(
          kind: 1,
          identity: identity,
          epoch: epoch,
          generation: generation,
          metadata: descriptor.bytes,
        ),
        decodeWire(_string(material, 'password_envelope')),
      );
      try {
        return UnlockedAccount._(
          identity,
          epoch,
          generation,
          Secret(plaintext),
          access,
          refresh,
          Secret(keys.authentication.copyBytes()),
          descriptor.bytes,
        );
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
    } catch (_) {
      if (access != null) {
        try {
          await transport.request(
            'POST',
            '/auth/logout',
            expected: 204,
            authorization: 'Bearer ${access.wire}',
            body: {},
          );
        } catch (_) {
          // Local destruction below is unconditional even if revocation fails.
        }
      }
      access?.destroy();
      refresh?.destroy();
      rethrow;
    } finally {
      keys.destroy();
    }
  });

  Future<void> logout(UnlockedAccount account) async {
    if (account.locked) return;
    final authorization = 'Bearer ${account._access.wire}';
    account.lock();
    await transport.request(
      'POST',
      '/auth/logout',
      authorization: authorization,
      body: {},
      expected: 204,
    );
  }

  /// Only pass these bytes directly to the hardware-bound native seal operation.
  Uint8List biometricPayload(UnlockedAccount account) {
    if (account.locked) throw const AccountFailure(401);
    return Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'schema': 1,
          'origin': transport.address.origin.toString(),
          'server_id': account.identity.server.wire,
          'account_id': account.identity.account.wire,
          'vault_id': account.identity.vault.wire,
          'epoch_id': account.epoch.wire,
          'credential_generation': account.generation.toString(),
          'password_descriptor': encodeWire(account._descriptor),
          'vault_key': account.vaultKey.wire,
          'auth_secret': account._authentication.wire,
        }),
      ),
    );
  }

  Future<UnlockedAccount> biometricLogin(
    String email,
    Uint8List payload,
  ) => _exclusive(() async {
    final value = decodeStrictJson(payload, maxBytes: 4096);
    if (value is! Map<String, dynamic> ||
        value.length != 10 ||
        value['schema'] != 1 ||
        value['schema'] is! int ||
        value['origin'] != transport.address.origin.toString())
      throw const CryptoFailure();
    final identity = _identity(value);
    final epoch = PmId.parse(_string(value, 'epoch_id'));
    final generation = _counter(value, 'credential_generation');
    final descriptor = decodeWire(
      _string(value, 'password_descriptor'),
      length: 30,
    );
    final decodedDescriptor = PasswordDescriptor.decode(descriptor);
    if (!config.profiles.any(
      (profile) => profile.matches(decodedDescriptor.profile),
    ))
      throw const CryptoFailure();
    Secret? access, refresh;
    final root = Secret(decodeWire(_string(value, 'vault_key'), length: 32));
    final authentication = Secret(
      decodeWire(_string(value, 'auth_secret'), length: 32),
    );
    try {
      final prelogin = await transport.request(
        'POST',
        '/auth/prelogin',
        body: {'email': normalizeEmail(email)},
      );
      final actual = _identity(prelogin);
      if (!actual.account.matches(identity.account) ||
          !actual.vault.matches(identity.vault) ||
          _counter(prelogin, 'credential_generation') != generation ||
          !sameBytes(
            decodeWire(_string(prelogin, 'password_descriptor'), length: 30),
            descriptor,
          ))
        throw const CryptoFailure();
      final tokens = await transport.request(
        'POST',
        '/auth/login',
        body: {
          'email': normalizeEmail(email),
          'account_id': identity.account.wire,
          'vault_id': identity.vault.wire,
          'credential_generation': generation.toString(),
          'auth_secret': authentication.wire,
          'device_id': PmId.random().wire,
          'device_name': 'ByteLocker',
          'platform': Platform.isAndroid ? 'android' : 'windows',
        },
      );
      access = Secret(decodeWire(_string(tokens, 'access_token'), length: 32));
      refresh = Secret(
        decodeWire(_string(tokens, 'refresh_token'), length: 32),
      );
      if (_string(tokens, 'account_id') != identity.account.wire ||
          _string(tokens, 'vault_id') != identity.vault.wire)
        throw const CryptoFailure();
      final material = await transport.request(
        'GET',
        '/account/material',
        authorization: 'Bearer ${access.wire}',
      );
      final current = _identity(material);
      if (!current.account.matches(identity.account) ||
          !current.vault.matches(identity.vault) ||
          _string(material, 'epoch_id') != epoch.wire ||
          _counter(material, 'credential_generation') != generation ||
          !sameBytes(
            decodeWire(_string(material, 'password_descriptor'), length: 30),
            descriptor,
          ))
        throw const CryptoFailure();
      return UnlockedAccount._(
        identity,
        epoch,
        generation,
        root,
        access,
        refresh,
        authentication,
        descriptor,
      );
    } catch (_) {
      if (access != null) {
        try {
          await transport.request(
            'POST',
            '/auth/logout',
            expected: 204,
            authorization: 'Bearer ${access.wire}',
            body: {},
          );
        } catch (_) {}
      }
      access?.destroy();
      refresh?.destroy();
      root.destroy();
      authentication.destroy();
      rethrow;
    }
  });

  Future<Map<String, dynamic>> vaultRequest(
    UnlockedAccount account,
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? query,
    Map<String, String> headers = const {},
    int expected = 200,
  }) async {
    if (account.locked) throw const AccountFailure(401);
    if (!path.startsWith('/vault/')) throw ArgumentError('Vault path');
    final response = await transport.request(
      method,
      path,
      body: body,
      authorization: 'Bearer ${account._access.wire}',
      query: query,
      headers: headers,
      expected: expected,
      maxBytes: 4 * 1024 * 1024,
    );
    if (account.locked) throw const AccountFailure(401);
    return response;
  }
}
