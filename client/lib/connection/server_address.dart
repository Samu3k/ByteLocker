/// An origin only. Account credentials must never be accepted in this URL.
final class ServerAddress {
  ServerAddress._(this.origin);
  final Uri origin;
  bool get isSecure => origin.scheme == 'https';
  Uri get discoveryUri => origin.replace(path: '/api/v1/config');

  static ServerAddress parse(String input, {bool allowLocalHttp = false}) {
    final value = input.trim();
    final match = RegExp(
      r'^(https|http)://(\[[0-9a-fA-F:.]+\]|[a-zA-Z0-9.-]+)(?::([0-9]+))?/?$',
    ).firstMatch(value);
    if (match == null) throw const FormatException('Invalid server origin');
    final uri = Uri.tryParse(value);
    if (uri == null ||
        uri.host.isEmpty ||
        uri.userInfo.isNotEmpty ||
        uri.hasQuery ||
        uri.hasFragment) {
      throw const FormatException('Invalid server origin');
    }
    final port = match.group(3);
    if (port != null) {
      final number = int.tryParse(port);
      if (number == null ||
          number < 1 ||
          number > 65535 ||
          number.toString() != port) {
        throw const FormatException('Invalid server port');
      }
    }
    final host = uri.host.toLowerCase();
    if (!host.contains(':')) {
      if (host.length > 253 ||
          host
              .split('.')
              .any(
                (label) =>
                    label.isEmpty ||
                    label.length > 63 ||
                    !RegExp(r'^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$')
                        .hasMatch(label),
              )) {
        throw const FormatException('Invalid server host');
      }
    }
    const localHosts = {'localhost', '127.0.0.1', '::1', '[::1]', '10.0.2.2'};
    if (uri.scheme != 'https' &&
        !(allowLocalHttp &&
            uri.scheme == 'http' &&
            localHosts.contains(host))) {
      throw const FormatException('HTTPS required');
    }
    return ServerAddress._(uri.replace(path: '', host: host));
  }
}
