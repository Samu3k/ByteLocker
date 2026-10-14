import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'server_address.dart';
import 'server_config.dart';

enum DiscoveryFailure {
  unreachable,
  timeout,
  certificate,
  redirect,
  response,
  malformed,
  incompatible,
}

final class DiscoveryException implements Exception {
  const DiscoveryException(this.failure);
  final DiscoveryFailure failure;
}

abstract interface class ServerDiscovery {
  Future<ServerConfig> discover(ServerAddress address);
}

/// Native Android/Windows transport. No credentials, cookies, automatic
/// redirects, certificate bypass or unbounded response buffering.
final class DiscoveryClient implements ServerDiscovery {
  DiscoveryClient({this.timeout = const Duration(seconds: 10)});
  final Duration timeout;
  static const maxResponseBytes = 65536;

  @override
  Future<ServerConfig> discover(ServerAddress address) async {
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 5)
      ..autoUncompress = false;
    try {
      return await _load(client, address).timeout(timeout);
    } on DiscoveryException {
      rethrow;
    } on ConfigurationException catch (error) {
      throw DiscoveryException(
        error.failure == ConfigurationFailure.unsupported
            ? DiscoveryFailure.incompatible
            : DiscoveryFailure.malformed,
      );
    } on HandshakeException {
      throw const DiscoveryException(DiscoveryFailure.certificate);
    } on TimeoutException {
      throw const DiscoveryException(DiscoveryFailure.timeout);
    } on SocketException {
      throw const DiscoveryException(DiscoveryFailure.unreachable);
    } on HttpException {
      throw const DiscoveryException(DiscoveryFailure.response);
    } finally {
      // Future.timeout alone does not cancel I/O. Closing forcefully also
      // cancels a late response and prevents a background socket from surviving.
      client.close(force: true);
    }
  }

  Future<ServerConfig> _load(HttpClient client, ServerAddress address) async {
    final request = await client.getUrl(address.discoveryUri);
    request.followRedirects = false;
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    request.headers.set(HttpHeaders.acceptEncodingHeader, 'identity');
    final response = await request.close();
    if (response.statusCode >= 300 && response.statusCode < 400) {
      throw const DiscoveryException(DiscoveryFailure.redirect);
    }
    final media = response.headers.contentType;
    final charset = media?.charset;
    final encodings = response.headers[HttpHeaders.contentEncodingHeader];
    if (response.statusCode != 200 ||
        media?.mimeType != 'application/json' ||
        (charset != null && charset.toLowerCase() != 'utf-8') ||
        (encodings != null &&
            (encodings.length != 1 || encodings.single != 'identity')) ||
        response.contentLength > maxResponseBytes) {
      throw const DiscoveryException(DiscoveryFailure.response);
    }
    final bytes = BytesBuilder(copy: false);
    await for (final chunk in response) {
      if (bytes.length + chunk.length > maxResponseBytes) {
        throw const DiscoveryException(DiscoveryFailure.response);
      }
      bytes.add(chunk);
    }
    return ServerConfig.decode(bytes.takeBytes());
  }
}
