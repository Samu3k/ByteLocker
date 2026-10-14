import 'dart:typed_data';

import '../account/account_client.dart';
import '../crypto/pm1.dart';
import 'vault_record.dart';

String _text(Map<String, dynamic> value, String key) {
  final raw = value[key];
  if (raw is! String) throw const CryptoFailure();
  return raw;
}

BigInt vaultCounter(Object? raw, {bool zero = false}) {
  if (raw is! String || !RegExp(r'^(0|[1-9][0-9]{0,19})$').hasMatch(raw))
    throw const CryptoFailure();
  final value = BigInt.parse(raw);
  if ((!zero && value == BigInt.zero) || value > EnvelopeContext.maxU64)
    throw const CryptoFailure();
  return value;
}

final class VaultEntry {
  const VaultEntry(this.id, this.revision, this.sequence, this.record);
  final PmId id;
  final BigInt revision, sequence;
  final VaultRecord record;
  @override
  String toString() => 'VaultEntry([REDACTED])';
}

final class _PendingWrite {
  const _PendingWrite(
    this.object,
    this.revision,
    this.method,
    this.path,
    this.body,
    this.headers,
  );
  final PmId object;
  final BigInt revision;
  final String method, path;
  final Map<String, dynamic> body;
  final Map<String, String> headers;
}

/// Online vault only. A full snapshot is published after every page authenticates.
/// No plaintext or keys are written to disk. Persistent offline sync comes later.
final class VaultClient {
  VaultClient(this.api, this.account);
  final AccountClient api;
  final UnlockedAccount account;
  final EnvelopeCrypto _crypto = EnvelopeCrypto();
  List<VaultEntry> _entries = const [];
  List<VaultEntry> _credentials = const [], _categories = const [];
  bool _busy = false, _disposed = false, _ready = false;
  _PendingWrite? _pending;
  void Function()? onDispose;
  List<VaultEntry> get entries =>
      _disposed || account.locked ? const [] : _credentials;
  List<VaultEntry> get categories =>
      _disposed || account.locked ? const [] : _categories;
  bool get ready => _ready && !_disposed && !account.locked;
  bool get hasPendingWrite => _pending != null;
  bool get busy => _busy;

  void dispose() {
    final erase = onDispose;
    onDispose = null;
    erase?.call();
    _disposed = true;
    _ready = false;
    _entries = const [];
    _credentials = const [];
    _categories = const [];
    _pending = null;
  }

  void _active() {
    if (_disposed || account.locked) throw const AccountFailure(401);
  }

  Future<T> _exclusive<T>(Future<T> Function() operation) async {
    _active();
    if (_busy) throw StateError('Vault operation already running');
    _busy = true;
    try {
      return await operation();
    } finally {
      _busy = false;
    }
  }

  Future<Map<String, dynamic>> _request(
    String method,
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? query,
    Map<String, String> headers = const {},
    int expected = 200,
  }) async {
    _active();
    final result = await api.vaultRequest(
      account,
      method,
      path,
      body: body,
      query: query,
      headers: headers,
      expected: expected,
    );
    _active();
    return result;
  }

  Future<void> reload() => _exclusive(_load);

  Future<void> _load() async {
    _ready = false;
    final state = await _request('GET', '/vault/state');
    if (_text(state, 'server_id') != account.identity.server.wire ||
        _text(state, 'account_id') != account.identity.account.wire ||
        _text(state, 'vault_id') != account.identity.vault.wire ||
        _text(state, 'epoch_id') != account.epoch.wire ||
        vaultCounter(state['credential_generation']) != account.generation) {
      throw const CryptoFailure();
    }
    final ceiling = vaultCounter(state['collection_revision'], zero: true);
    final count = state['object_count'];
    if (count is! int || count < 0 || count > 10000)
      throw const CryptoFailure();
    final staged = <VaultEntry>[];
    final identifiers = <String>{};
    var after = BigInt.zero;
    var totalBytes = 0;
    while (true) {
      final page = await _request(
        'GET',
        '/vault/sync',
        query: {
          'epoch_id': account.epoch.wire,
          'since': '0',
          'ceiling': ceiling.toString(),
          'after_sequence': after.toString(),
          'limit': '100',
        },
      );
      if (_text(page, 'epoch_id') != account.epoch.wire ||
          vaultCounter(page['snapshot_revision'], zero: true) != ceiling ||
          page['items'] is! List<dynamic>)
        throw const CryptoFailure();
      final items = page['items'] as List<dynamic>;
      if (items.length > 100) throw const CryptoFailure();
      var last = after;
      for (final raw in items) {
        if (raw is! Map<String, dynamic>) throw const CryptoFailure();
        final id = PmId.parse(_text(raw, 'object_id'));
        final revision = vaultCounter(raw['revision']);
        final sequence = vaultCounter(raw['sequence']);
        if (sequence <= last ||
            sequence > ceiling ||
            revision > sequence ||
            !identifiers.add(id.wire) ||
            identifiers.length > count)
          throw const CryptoFailure();
        final encrypted = decodeWire(_text(raw, 'envelope'));
        totalBytes += encrypted.length;
        if (totalBytes > 64 * 1024 * 1024) throw const CryptoFailure();
        final plain = await _crypto.decrypt(
          account.vaultKey,
          EnvelopeContext(
            kind: 3,
            identity: account.identity,
            epoch: account.epoch,
            object: id,
            generation: revision,
          ),
          encrypted,
        );
        try {
          final record = VaultRecord.decode(plain);
          if (record != null)
            staged.add(VaultEntry(id, revision, sequence, record));
        } finally {
          plain.fillRange(0, plain.length, 0);
        }
        _active();
        last = sequence;
      }
      final next = page['next_after_sequence'];
      if (next == null) break;
      final cursor = vaultCounter(next);
      if (items.isEmpty ||
          cursor != last ||
          cursor <= after ||
          cursor >= ceiling) {
        throw const CryptoFailure();
      }
      after = cursor;
    }
    if (identifiers.length != count) throw const CryptoFailure();
    staged.sort((a, b) {
      final result = a.record.title.toLowerCase().compareTo(
        b.record.title.toLowerCase(),
      );
      return result != 0 ? result : a.id.wire.compareTo(b.id.wire);
    });
    _active();
    _entries = List.unmodifiable(staged);
    _credentials = List.unmodifiable(
      staged.where((entry) => !entry.record.isCategory),
    );
    _categories = List.unmodifiable(
      staged.where((entry) => entry.record.isCategory),
    );
    _ready = _pending == null;
  }

  Future<void> save(VaultRecord record, {VaultEntry? replacing}) => _exclusive(
    () async {
      if (!ready || _pending != null)
        throw StateError('Reload or resolve the pending write first');
      if (replacing != null &&
          !_entries.any(
            (entry) =>
                entry.id.matches(replacing.id) &&
                entry.revision == replacing.revision,
          ))
        throw const CryptoFailure();
      if (replacing != null && replacing.record.isCategory != record.isCategory)
        throw const RecordFailure();
      if (record.categoryId != null &&
          !_categories.any((entry) => entry.id.wire == record.categoryId))
        throw const RecordFailure();
      if (record.isCategory &&
          _categories.any(
            (entry) =>
                entry.id.wire != replacing?.id.wire &&
                entry.record.title.trim().toLowerCase() ==
                    record.title.trim().toLowerCase(),
          ))
        throw const RecordFailure();
      final plaintext = record.encode();
      try {
        await _prepare(plaintext, replacing);
      } finally {
        plaintext.fillRange(0, plaintext.length, 0);
      }
      await _send();
    },
  );

  Future<void> remove(VaultEntry entry) => _exclusive(() async {
    if (!ready || _pending != null || !_entries.contains(entry))
      throw StateError('Reload first');
    if (entry.record.isCategory &&
        _credentials.any((item) => item.record.categoryId == entry.id.wire))
      throw const RecordFailure();
    final plaintext = VaultRecord.tombstone();
    try {
      await _prepare(plaintext, entry);
    } finally {
      plaintext.fillRange(0, plaintext.length, 0);
    }
    await _send();
  });

  Future<void> _prepare(Uint8List plaintext, VaultEntry? replacing) async {
    final id = replacing?.id ?? PmId.random();
    final revision = replacing == null
        ? BigInt.one
        : replacing.revision + BigInt.one;
    if (revision > EnvelopeContext.maxU64) throw const CryptoFailure();
    final envelope = await _crypto.encrypt(
      account.vaultKey,
      EnvelopeContext(
        kind: 3,
        identity: account.identity,
        epoch: account.epoch,
        object: id,
        generation: revision,
      ),
      plaintext,
    );
    _active();
    _pending = _PendingWrite(
      id,
      revision,
      replacing == null ? 'POST' : 'PUT',
      replacing == null ? '/vault/objects' : '/vault/objects/${id.wire}',
      Map.unmodifiable({
        'epoch_id': account.epoch.wire,
        if (replacing == null) 'object_id': id.wire,
        'envelope': encodeWire(envelope),
      }),
      Map.unmodifiable({
        'Idempotency-Key': PmId.random().wire,
        if (replacing != null)
          'If-Match': '"o:${account.epoch.wire}:${replacing.revision}"',
      }),
    );
    _ready = false;
  }

  Future<void> retryPending() => _exclusive(() async {
    if (_pending == null) throw StateError('No pending write');
    await _send();
  });

  Future<void> _send() async {
    final pending = _pending!;
    try {
      final result = await _request(
        pending.method,
        pending.path,
        body: pending.body,
        headers: pending.headers,
        expected: pending.method == 'POST' ? 201 : 200,
      );
      if (_text(result, 'epoch_id') != account.epoch.wire ||
          _text(result, 'object_id') != pending.object.wire ||
          vaultCounter(result['revision']) != pending.revision)
        throw const CryptoFailure();
      final sequence = vaultCounter(result['sequence']);
      final collection = vaultCounter(result['collection_revision']);
      if (sequence != collection || sequence < pending.revision)
        throw const CryptoFailure();
      _pending = null;
    } on AccountFailure catch (error) {
      if (const [
        400,
        401,
        403,
        404,
        409,
        412,
        413,
        428,
        429,
      ].contains(error.status)) {
        _pending = null;
      }
      rethrow;
    }
    await _load();
  }
}
