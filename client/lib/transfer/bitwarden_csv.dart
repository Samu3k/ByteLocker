import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../vault/vault_record.dart';
import '../vault/vault_client.dart';
import '../vault/totp.dart';

const maxTransferBytes = 10 * 1024 * 1024;
const maxImportRecords = 5000;

class TransferFailure implements Exception {
  const TransferFailure();
  @override
  String toString() => 'TransferFailure([REDACTED])';
}

class ImportItem {
  const ImportItem(this.record, this.folder);
  final VaultRecord record;
  final String folder;
  @override
  String toString() => 'ImportItem([REDACTED])';
}

class ImportPlan {
  ImportPlan(
    this.items, {
    this.duplicates = 0,
    this.invalid = 0,
    this.unsupported = 0,
    this.customFields = 0,
    this.reprompt = 0,
  });
  final List<ImportItem> items;
  int duplicates, invalid, unsupported, customFields, reprompt;
  void clear() => items.clear();
  @override
  String toString() => 'ImportPlan([REDACTED])';
}

/// Strict RFC-4180 parsing. Never interprets cells as formulas or logs contents.
List<List<String>> parseCsv(String text) {
  if (text.startsWith('\ufeff')) text = text.substring(1);
  final rows = <List<String>>[], row = <String>[];
  var cell = StringBuffer(),
      quoted = false,
      endedQuote = false,
      started = false;
  void field() {
    row.add(cell.toString());
    cell = StringBuffer();
    quoted = false;
    endedQuote = false;
    started = false;
    if (row.length > 64) throw const TransferFailure();
  }

  void line() {
    field();
    if (row.any((v) => v.isNotEmpty)) rows.add(List.of(row));
    row.clear();
    if (rows.length > maxImportRecords + 1) throw const TransferFailure();
  }

  for (var i = 0; i < text.length; i++) {
    final c = text[i];
    if (quoted) {
      if (c == '"') {
        if (i + 1 < text.length && text[i + 1] == '"') {
          cell.write('"');
          i++;
        } else {
          quoted = false;
          endedQuote = true;
        }
      } else {
        cell.write(c);
      }
      continue;
    }
    if (c == ',') {
      field();
      continue;
    }
    if (c == '\n' || c == '\r') {
      if (c == '\r' && i + 1 < text.length && text[i + 1] == '\n') i++;
      line();
      continue;
    }
    if (endedQuote) throw const TransferFailure();
    if (c == '"') {
      if (started) throw const TransferFailure();
      quoted = true;
      started = true;
      continue;
    }
    cell.write(c);
    started = true;
  }
  if (quoted) throw const TransferFailure();
  if (started || endedQuote || cell.isNotEmpty || row.isNotEmpty) line();
  return rows;
}

Future<String> recordFingerprint(VaultRecord r, String folder) async {
  final bytes = utf8.encode(
    jsonEncode([
      r.title,
      r.username,
      r.email,
      r.password,
      r.url,
      r.notes,
      r.totp?.secret,
      r.tags,
      folder.trim().toLowerCase(),
      r.favorite,
    ]),
  );
  try {
    return base64Encode((await Sha256().hash(bytes)).bytes);
  } finally {
    bytes.fillRange(0, bytes.length, 0);
  }
}

Future<ImportPlan> planBitwardenCsv(
  Uint8List bytes,
  List<VaultEntry> existing,
  List<VaultEntry> categories,
) async {
  if (bytes.isEmpty || bytes.length > maxTransferBytes)
    throw const TransferFailure();
  List<List<String>> rows;
  try {
    rows = parseCsv(utf8.decode(bytes));
  } catch (_) {
    throw const TransferFailure();
  }
  if (rows.isEmpty) throw const TransferFailure();
  final header = rows.first;
  if (header.toSet().length != header.length ||
      ![
        'type',
        'name',
        'login_username',
        'login_password',
      ].every(header.contains))
    throw const TransferFailure();
  final folders = {for (final e in categories) e.id.wire: e.record.title};
  final seen = <String>{};
  for (final entry in existing)
    seen.add(
      await recordFingerprint(
        entry.record,
        folders[entry.record.categoryId] ?? '',
      ),
    );
  final plan = ImportPlan([]);
  for (final row in rows.skip(1)) {
    if (row.length != header.length) {
      plan.invalid++;
      continue;
    }
    final values = {for (var i = 0; i < header.length; i++) header[i]: row[i]};
    String get(String key) => values[key] ?? '';
    final type = get('type');
    if (type != 'login' && type != 'note') {
      plan.unsupported++;
      continue;
    }
    try {
      final folder = get('folder');
      if (folder.isNotEmpty) VaultRecord(title: folder, isCategory: true);
      var notes = get('notes'), email = '';
      var tags = <String>[];
      var metadata = false;
      final custom = <String>[];
      for (final field in get('fields').split('\n')) {
        if (field.startsWith('ByteLocker metadata: ')) {
          try {
            final data = jsonDecode(
              field.substring('ByteLocker metadata: '.length),
            );
            if (data is! Map<String, dynamic> ||
                data.length != 4 ||
                data['schema'] != 1 ||
                data['email'] is! String ||
                data['tags'] is! List)
              throw const TransferFailure();
            email = data['email'] as String;
            tags = List<String>.from(data['tags'] as List);
            metadata = true;
          } catch (_) {
            custom.add(field);
          }
        } else if (field.isNotEmpty) {
          custom.add(field);
        }
      }
      if (custom.isNotEmpty) {
        notes = [
          if (notes.isNotEmpty) notes,
          'Bitwarden custom fields:',
          custom.join('\n'),
        ].join('\n\n');
        plan.customFields++;
      }
      if (!metadata &&
          RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$').hasMatch(get('login_username')))
        email = get('login_username');
      final totp = get('login_totp');
      final record = VaultRecord(
        title: get('name'),
        username: type == 'login' ? get('login_username') : '',
        email: email,
        password: type == 'login' ? get('login_password') : '',
        url: type == 'login' ? get('login_uri') : '',
        notes: notes,
        tags: tags,
        totp: totp.isEmpty ? null : Totp.parse(totp),
        favorite: get('favorite') == '1' || get('favorite') == 'true',
      );
      if (!['', '0', '1', 'true', 'false'].contains(get('favorite')))
        throw const TransferFailure();
      if (get('reprompt') == '1') plan.reprompt++;
      final fingerprint = await recordFingerprint(record, folder);
      if (!seen.add(fingerprint)) {
        plan.duplicates++;
        continue;
      }
      plan.items.add(ImportItem(record, folder));
    } catch (_) {
      plan.invalid++;
    }
  }
  return plan;
}

Uint8List exportBitwardenCsv(
  List<VaultEntry> entries,
  List<VaultEntry> categories,
) {
  final folders = {for (final e in categories) e.id.wire: e.record.title};
  String cell(String value) => '"${value.replaceAll('"', '""')}"';
  final rows = <List<String>>[
    [
      'folder',
      'favorite',
      'type',
      'name',
      'notes',
      'fields',
      'reprompt',
      'login_uri',
      'login_username',
      'login_password',
      'login_totp',
    ],
  ];
  for (final entry in entries) {
    final r = entry.record;
    rows.add([
      folders[r.categoryId] ?? '',
      r.favorite ? '1' : '0',
      'login',
      r.title,
      r.notes,
      'ByteLocker metadata: ${jsonEncode({'schema': 1, 'email': r.email, 'tags': r.tags, 'reserved': null})}',
      '0',
      r.url,
      r.username,
      r.password,
      r.totp?.secret ?? '',
    ]);
  }
  final encoded = Uint8List.fromList(
    utf8.encode(
      rows.map((row) => row.map(cell).join(',')).join('\r\n') + '\r\n',
    ),
  );
  if (encoded.length > maxTransferBytes) {
    encoded.fillRange(0, encoded.length, 0);
    throw const TransferFailure();
  }
  return encoded;
}
