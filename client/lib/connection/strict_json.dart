import 'dart:convert';
import 'dart:typed_data';

/// Bounded UTF-8 JSON with duplicate-key rejection, including escaped aliases.
/// A structural scan enforces depth first; jsonDecode validates the grammar.
Object? decodeStrictJson(Uint8List bytes, {int maxBytes = 65536}) {
  if (bytes.length > maxBytes) throw const FormatException('JSON too large');
  if (bytes.length >= 3 &&
      bytes[0] == 0xef &&
      bytes[1] == 0xbb &&
      bytes[2] == 0xbf) {
    throw const FormatException('JSON BOM');
  }
  final source = utf8.decode(bytes, allowMalformed: false);
  if (source.startsWith('\uFEFF')) throw const FormatException('JSON BOM');
  final scan = _KeyScanner(source);
  scan.value(0);
  scan.whitespace();
  if (scan.position != source.length) {
    throw const FormatException('Trailing JSON');
  }
  return jsonDecode(source);
}

final class _KeyScanner {
  _KeyScanner(this.source);
  final String source;
  int position = 0;

  void whitespace() {
    while (position < source.length &&
        const [9, 10, 13, 32].contains(source.codeUnitAt(position))) {
      position++;
    }
  }

  String string() {
    if (position >= source.length || source.codeUnitAt(position) != 34) {
      throw const FormatException('Expected JSON string');
    }
    final start = position++;
    while (position < source.length) {
      final char = source.codeUnitAt(position++);
      if (char == 92) {
        position++;
      } else if (char == 34) {
        return jsonDecode(source.substring(start, position)) as String;
      }
    }
    throw const FormatException('Unterminated JSON string');
  }

  void value(int depth) {
    if (depth > 32) throw const FormatException('JSON too deep');
    whitespace();
    if (position >= source.length)
      throw const FormatException('Missing JSON value');
    final char = source.codeUnitAt(position);
    if (char == 123) {
      position++;
      whitespace();
      final keys = <String>{};
      if (position < source.length && source.codeUnitAt(position) == 125) {
        position++;
        return;
      }
      while (true) {
        whitespace();
        if (!keys.add(string()))
          throw const FormatException('Duplicate JSON key');
        whitespace();
        if (position >= source.length || source.codeUnitAt(position++) != 58) {
          throw const FormatException('Expected colon');
        }
        value(depth + 1);
        whitespace();
        if (position >= source.length)
          throw const FormatException('Unclosed object');
        final separator = source.codeUnitAt(position++);
        if (separator == 125) return;
        if (separator != 44) throw const FormatException('Expected comma');
      }
    } else if (char == 91) {
      position++;
      whitespace();
      if (position < source.length && source.codeUnitAt(position) == 93) {
        position++;
        return;
      }
      while (true) {
        value(depth + 1);
        whitespace();
        if (position >= source.length)
          throw const FormatException('Unclosed array');
        final separator = source.codeUnitAt(position++);
        if (separator == 93) return;
        if (separator != 44) throw const FormatException('Expected comma');
      }
    } else if (char == 34) {
      string();
    } else {
      final start = position;
      while (position < source.length &&
          !const [
            9,
            10,
            13,
            32,
            44,
            93,
            125,
          ].contains(source.codeUnitAt(position))) {
        position++;
      }
      if (position == start) throw const FormatException('Missing JSON value');
    }
  }
}
