import 'dart:convert';
import 'dart:typed_data';

import '../connection/strict_json.dart';
import 'totp.dart';
import 'passkey.dart';
import '../crypto/pm1.dart';

bool _validUnicode(String value) {
  final units = value.codeUnits;
  for (var i = 0; i < units.length; i++) {
    if (units[i] >= 0xd800 && units[i] <= 0xdbff) {
      if (++i >= units.length || units[i] < 0xdc00 || units[i] > 0xdfff)
        return false;
    } else if (units[i] >= 0xdc00 && units[i] <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/// Versioned application payload. All fields, including tags, are encrypted.
final class VaultRecord {
  VaultRecord({
    required this.title,
    this.username = '',
    this.email = '',
    this.password = '',
    this.url = '',
    this.notes = '',
    this.totp,
    this.passkey,
    this.categoryId,
    this.favorite = false,
    this.logo,
    this.isCategory = false,
    List<String> tags = const [],
  }) : tags = List.unmodifiable(tags) {
    if (categoryId != null) {
      try {
        PmId.parse(categoryId!);
      } on CryptoFailure {
        throw const RecordFailure();
      }
    }
    if (logo != null && !RegExp(r'^[a-z0-9][a-z0-9-]{0,79}$').hasMatch(logo!))
      throw const RecordFailure();
    if (isCategory &&
        (username.isNotEmpty ||
            email.isNotEmpty ||
            password.isNotEmpty ||
            url.isNotEmpty ||
            notes.isNotEmpty ||
            tags.isNotEmpty ||
            totp != null ||
            passkey != null ||
            categoryId != null ||
            favorite ||
            logo != null))
      throw const RecordFailure();
    // Validate individually: identical values must not collapse a field's limit.
    for (final pair in [
      (title, 200),
      (username, 1024),
      (email, 1024),
      (password, 4096),
      (url, 4096),
      (notes, 65536),
    ]) {
      if (!_validUnicode(pair.$1) || utf8.encode(pair.$1).length > pair.$2)
        throw const RecordFailure();
    }
    if (title.trim().isEmpty ||
        tags.length > 32 ||
        tags.any(
          (tag) =>
              !_validUnicode(tag) ||
              tag.trim().isEmpty ||
              utf8.encode(tag).length > 100,
        ) ||
        tags.toSet().length != tags.length) {
      throw const RecordFailure();
    }
  }
  final String title, username, email, password, url, notes;
  final Totp? totp;
  final VaultPasskey? passkey;
  final List<String> tags;
  final String? categoryId, logo;
  final bool favorite, isCategory;
  VaultRecord withOrganization({
    bool? favorite,
    String? categoryId,
    bool clearCategory = false,
  }) => VaultRecord(
    title: title,
    username: username,
    email: email,
    password: password,
    url: url,
    notes: notes,
    tags: tags,
    totp: totp,
    passkey: passkey,
    categoryId: clearCategory ? null : categoryId ?? this.categoryId,
    favorite: favorite ?? this.favorite,
    logo: logo,
    isCategory: isCategory,
  );
  VaultRecord withPasskey(VaultPasskey? value) => VaultRecord(
    title: title,
    username: username,
    email: email,
    password: password,
    url: url,
    notes: notes,
    tags: tags,
    totp: totp,
    passkey: value,
    categoryId: categoryId,
    favorite: favorite,
    logo: logo,
    isCategory: isCategory,
  );
  bool get _extended => categoryId != null || favorite || logo != null;
  Uint8List encode() => isCategory
      ? Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'schema': 4,
              'deleted': false,
              'type': 'category',
              'title': title,
            }),
          ),
        )
      : Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'schema': _extended
                  ? 4
                  : passkey != null
                  ? 3
                  : totp == null
                  ? 1
                  : 2,
              'deleted': false,
              'type': 'credential',
              'title': title,
              'username': username,
              'email': email,
              'password': password,
              'url': url,
              'notes': notes,
              'tags': tags,
              if (_extended || totp != null || passkey != null)
                'totp': totp?.secret,
              if (_extended || passkey != null) 'passkey': passkey?.encode(),
              if (_extended) 'category_id': categoryId,
              if (_extended) 'favorite': favorite,
              if (_extended) 'logo': logo,
            }),
          ),
        );

  static VaultRecord? decode(Uint8List bytes) {
    try {
      final value = decodeStrictJson(bytes, maxBytes: 1048576);
      if (value is! Map<String, dynamic> ||
          (value['schema'] != 1 &&
              value['schema'] != 2 &&
              value['schema'] != 3 &&
              value['schema'] != 4) ||
          value['schema'] is! int ||
          value['deleted'] is! bool)
        throw const RecordFailure();
      if (value['deleted'] == true) {
        if (value.length != 2 || value['schema'] != 1)
          throw const RecordFailure();
        return null;
      }
      final schema = value['schema'] as int;
      if (value['schema'] == 4 && value['type'] == 'category') {
        if (value.length != 4 || value['title'] is! String)
          throw const RecordFailure();
        return VaultRecord(title: value['title'] as String, isCategory: true);
      }
      final fields = {
        'schema',
        'deleted',
        'type',
        'title',
        'username',
        'email',
        'password',
        'url',
        'notes',
        'tags',
        if (schema >= 2) 'totp',
        if (schema >= 3) 'passkey',
        if (value['schema'] == 4) ...['category_id', 'favorite', 'logo'],
      };
      if (value.length != fields.length ||
          !value.keys.every(fields.contains) ||
          value['type'] != 'credential' ||
          value['tags'] is! List<dynamic>)
        throw const RecordFailure();
      String field(String key) {
        final text = value[key];
        if (text is! String) throw const RecordFailure();
        return text;
      }

      final tags = value['tags'] as List<dynamic>;
      if (tags.any((tag) => tag is! String)) throw const RecordFailure();
      if (value['schema'] == 3 && value['passkey'] == null)
        throw const RecordFailure();
      if (value['schema'] == 4 &&
          (value['favorite'] is! bool ||
              (value['category_id'] != null &&
                  value['category_id'] is! String) ||
              (value['logo'] != null && value['logo'] is! String)))
        throw const RecordFailure();
      return VaultRecord(
        title: field('title'),
        username: field('username'),
        email: field('email'),
        password: field('password'),
        url: field('url'),
        notes: field('notes'),
        tags: tags.cast<String>(),
        totp: value['schema'] == 2 || schema >= 3 && value['totp'] != null
            ? Totp.parse(field('totp'))
            : null,
        passkey: schema >= 3 && value['passkey'] != null
            ? VaultPasskey.decode(value['passkey'])
            : null,
        categoryId: value['schema'] == 4
            ? value['category_id'] as String?
            : null,
        favorite: value['schema'] == 4 ? value['favorite'] as bool : false,
        logo: value['schema'] == 4 ? value['logo'] as String? : null,
      );
    } on CryptoFailure {
      throw const RecordFailure();
    } on TotpFailure {
      throw const RecordFailure();
    } on FormatException {
      throw const RecordFailure();
    }
  }

  static Uint8List tombstone() =>
      Uint8List.fromList(utf8.encode('{"schema":1,"deleted":true}'));
  bool matches(String query) {
    final normalized = query.trim().toLowerCase();
    return [
      title,
      username,
      email,
      url,
      ...tags,
    ].any((field) => field.toLowerCase().contains(normalized));
  }

  @override
  String toString() => 'VaultRecord([REDACTED])';
}

final class RecordFailure implements Exception {
  const RecordFailure();
  @override
  String toString() => 'RecordFailure: unsupported or invalid vault record';
}
