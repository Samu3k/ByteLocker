import '../l10n/app_strings.dart';
import '../brand.dart';

import 'dart:async';

import 'package:flutter/material.dart';

import '../account/account_client.dart';
import 'vault_client.dart';
import 'vault_record.dart';
import 'credential_logo.dart';
import 'totp.dart';
import 'totp_code.dart';
import '../settings/client_settings.dart';
import 'passkey_panel.dart';
import 'sensitive_clipboard.dart';

class VaultPage extends StatefulWidget {
  const VaultPage({
    super.key,
    required this.vault,
    required this.onLogout,
    this.onBiometrics,
    this.biometricEnabled = false,
  });
  final VaultClient vault;
  final Future<void> Function() onLogout;
  final Future<void> Function(bool)? onBiometrics;
  final bool biometricEnabled;
  @override
  State<VaultPage> createState() => _VaultPageState();
}

class _VaultPageState extends State<VaultPage> {
  final _scaffold = GlobalKey<ScaffoldState>();
  DialogRoute<String>? _dialog;
  String _section = 'all';
  String? _selectedCategory, _selectedTag, _formCategory, _formLogo;
  bool _formFavorite = false;
  final _search = TextEditingController();
  final _form = GlobalKey<FormState>();
  final _fields = <String, TextEditingController>{
    for (final name in [
      'Titolo',
      'Username',
      'Email',
      'Password',
      'URL',
      'Note',
      'Tag',
      'Segreto 2FA',
    ])
      name: TextEditingController(),
  };
  bool _busy = false,
      _editor = false,
      _showPassword = false,
      _confirmDelete = false;
  VaultEntry? _editing;
  VaultEntry? _viewing;
  String? _message;
  bool _settings = false;
  PasskeyRequest? _passkeyRequest;
  bool _passkeyError = false;
  bool _confirmRemovePasskey = false, _removePasskey = false;

  @override
  void initState() {
    super.initState();
    widget.vault.onDispose = _eraseSensitive;
    unawaited(
      _run(() async {
        await widget.vault.reload();
        final native = NativePasskeyClient();
        try {
          final request = await native.pending();
          if (!mounted || widget.vault.account.locked || request == null)
            return;
          await native.verified(request);
          if (mounted && !widget.vault.account.locked)
            setState(() => _passkeyRequest = request);
        } catch (_) {
          if (mounted)
            setState(() {
              _passkeyError = true;
              _message = tr(
                context,
                'La richiesta passkey del sito o dell’app non può essere verificata da questa versione.',
              );
            });
        }
      }),
    );
  }

  @override
  void dispose() {
    unawaited(SensitiveClipboard.clear());
    widget.vault.onDispose = null;
    _editing = null;
    _viewing = null;
    _search.clear();
    _search.dispose();
    for (final field in _fields.values) {
      field.clear();
      field.dispose();
    }
    super.dispose();
  }

  void _eraseSensitive() {
    unawaited(SensitiveClipboard.clear());
    final dialog = _dialog;
    _dialog = null;
    if (dialog != null && dialog.isActive)
      dialog.navigator?.removeRoute(dialog);
    _formCategory = null;
    _formLogo = null;
    _formFavorite = false;
    _selectedCategory = null;
    _selectedTag = null;
    _section = 'all';
    _editing = null;
    _viewing = null;
    _passkeyRequest = null;
    _search.clear();
    for (final field in _fields.values) {
      field.clear();
    }
    _showPassword = false;
  }

  Future<void> _run(
    Future<void> Function() operation, {
    bool closeEditor = false,
  }) async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _message = null;
    });
    try {
      await operation();
      if (!mounted) return;
      if (closeEditor) _clearEditor();
    } catch (error) {
      if (!mounted) return;
      if (error is AccountFailure && error.status == 401) {
        unawaited(widget.onLogout());
        return;
      }
      setState(() {
        _message = error is AccountFailure && error.status == 412
            ? tr(
                context,
                'La credenziale è stata modificata su un altro dispositivo. Aggiorna il vault e riapri la voce prima di salvarla.',
              )
            : widget.vault.hasPendingWrite
            ? tr(
                context,
                'La scrittura non è confermata. Ripeti la stessa operazione con il pulsante qui sotto.',
              )
            : tr(
                context,
                'Operazione non completata. Aggiorna il vault e riprova; le modifiche nel modulo sono ancora qui.',
              );
      });
    } finally {
      if (mounted)
        setState(() {
          _busy = false;
        });
    }
  }

  void _clearEditor() {
    for (final field in _fields.values) {
      field.clear();
    }
    setState(() {
      _editor = false;
      _editing = null;
      _viewing = null;
      _showPassword = false;
      _confirmDelete = false;
      _confirmRemovePasskey = false;
      _removePasskey = false;
      _formCategory = null;
      _formFavorite = false;
      _formLogo = null;
    });
  }

  void _edit([VaultEntry? entry]) {
    final record = entry?.record;
    final values = {
      'Titolo': record?.title ?? '',
      'Username': record?.username ?? '',
      'Email': record?.email ?? '',
      'Password': record?.password ?? '',
      'URL': record?.url ?? '',
      'Note': record?.notes ?? '',
      'Tag': record?.tags.join(', ') ?? '',
      'Segreto 2FA': record?.totp?.secret ?? '',
    };
    for (final field in _fields.entries) {
      field.value.text = values[field.key]!;
    }
    setState(() {
      _editor = true;
      _viewing = null;
      _editing = entry;
      _showPassword = false;
      _confirmDelete = false;
      _confirmRemovePasskey = false;
      _removePasskey = false;
      _message = null;
      _formCategory =
          record?.categoryId ??
          (_section == 'category' ? _selectedCategory : null);
      _formFavorite = record?.favorite ?? false;
      _formLogo = record?.logo;
    });
  }

  Future<void> _save() async {
    if (_busy || !_form.currentState!.validate()) return;
    FocusScope.of(context).unfocus();
    try {
      final tags = _fields['Tag']!.text
          .split(',')
          .map((tag) => tag.trim())
          .where((tag) => tag.isNotEmpty)
          .toSet()
          .toList();
      final record = VaultRecord(
        title: _fields['Titolo']!.text,
        username: _fields['Username']!.text,
        email: _fields['Email']!.text,
        password: _fields['Password']!.text,
        url: _fields['URL']!.text,
        notes: _fields['Note']!.text,
        tags: tags,
        categoryId: _formCategory,
        favorite: _formFavorite,
        logo: _formLogo,
        passkey: _removePasskey ? null : _editing?.record.passkey,
        totp: _fields['Segreto 2FA']!.text.trim().isEmpty
            ? null
            : Totp.parse(_fields['Segreto 2FA']!.text),
      );
      await _run(
        () => widget.vault.save(record, replacing: _editing),
        closeEditor: true,
      );
    } on RecordFailure {
      if (mounted)
        setState(() {
          _message = tr(
            context,
            'Un campo supera il limite consentito. Riduci il testo o i tag.',
          );
        });
    }
  }

  Widget _editorView() => Form(
    key: _form,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(
          _editing == null
              ? tr(context, 'Nuova credenziale')
              : tr(context, 'Modifica credenziale'),
          style: Theme.of(context).textTheme.headlineSmall,
        ),
        const SizedBox(height: 24),
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              children: [
                Row(
                  children: [
                    CredentialLogo(
                      record: VaultRecord(
                        title: _editing?.record.title ?? 'Nuova credenziale',
                        url: _editing?.record.url ?? '',
                        logo: _formLogo,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        _formLogo == null
                            ? tr(context, 'Logo automatico dal sito')
                            : brandBySlug(_formLogo)?.name ??
                                  'Icona con iniziale',
                      ),
                    ),
                    IconButton(
                      tooltip: tr(context, 'Scegli il logo'),
                      onPressed: _busy ? null : _chooseLogo,
                      icon: const Icon(Icons.image_search_outlined),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                DropdownButtonFormField<String>(
                  key: ValueKey(
                    'category-${_formCategory ?? "none"}-${widget.vault.categories.length}',
                  ),
                  initialValue:
                      widget.vault.categories.any(
                        (item) => item.id.wire == _formCategory,
                      )
                      ? _formCategory
                      : '',
                  isExpanded: true,
                  decoration: InputDecoration(
                    labelText: tr(context, 'Categoria'),
                    prefixIcon: Icon(Icons.folder_outlined),
                  ),
                  items: [
                    DropdownMenuItem(
                      value: '',
                      child: Text(tr(context, 'Senza categoria')),
                    ),
                    for (final category in widget.vault.categories)
                      DropdownMenuItem(
                        value: category.id.wire,
                        child: Text(
                          category.record.title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                  ],
                  onChanged: _busy
                      ? null
                      : (value) => setState(
                          () => _formCategory = value == '' ? null : value,
                        ),
                ),
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: _busy
                        ? null
                        : () => _createCategory(assign: true),
                    icon: const Icon(Icons.create_new_folder_outlined),
                    label: Text(tr(context, 'Nuova categoria')),
                  ),
                ),
                SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(tr(context, 'Preferito')),
                  secondary: Icon(
                    _formFavorite
                        ? Icons.star_rounded
                        : Icons.star_outline_rounded,
                  ),
                  value: _formFavorite,
                  onChanged: _busy
                      ? null
                      : (value) => setState(() => _formFavorite = value),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 16),
        for (final entry in _fields.entries)
          Padding(
            padding: const EdgeInsets.only(bottom: 16),
            child: TextFormField(
              key: ValueKey('record-${entry.key}'),
              controller: entry.value,
              enabled: !_busy,
              obscureText:
                  entry.key == 'Segreto 2FA' ||
                  (entry.key == 'Password' && !_showPassword),
              autocorrect: false,
              enableSuggestions: false,
              maxLines: entry.key == 'Note' ? 5 : 1,
              keyboardType: entry.key == 'URL'
                  ? TextInputType.url
                  : entry.key == 'Email'
                  ? TextInputType.emailAddress
                  : TextInputType.text,
              decoration: InputDecoration(
                helperMaxLines: 3,
                labelText: tr(context, entry.key),
                helperText: entry.key == 'Tag'
                    ? tr(context, 'Separa i tag con una virgola')
                    : entry.key == 'Segreto 2FA'
                    ? tr(
                        context,
                        'Chiave di configurazione o link otpauth://. Lascia vuoto per rimuovere il 2FA salvato.',
                      )
                    : null,
                suffixIcon: entry.key == 'Password'
                    ? IconButton(
                        tooltip: _showPassword
                            ? tr(context, 'Nascondi password')
                            : tr(context, 'Mostra password'),
                        onPressed: _busy
                            ? null
                            : () => setState(() {
                                _showPassword = !_showPassword;
                              }),
                        icon: Icon(
                          _showPassword
                              ? Icons.visibility_off_outlined
                              : Icons.visibility_outlined,
                        ),
                      )
                    : null,
              ),
              validator: entry.key == 'Titolo'
                  ? (value) => value == null || value.trim().isEmpty
                        ? tr(context, 'Inserisci un titolo')
                        : null
                  : entry.key == 'Segreto 2FA'
                  ? (value) {
                      if (value == null || value.trim().isEmpty) return null;
                      try {
                        Totp.parse(value);
                        return null;
                      } on TotpFailure {
                        return tr(
                          context,
                          'Usa una chiave Base32 o TOTP SHA-1, 6 cifre, 30 secondi.',
                        );
                      }
                    }
                  : null,
            ),
          ),
        ValueListenableBuilder<TextEditingValue>(
          valueListenable: _fields['Segreto 2FA']!,
          builder: (context, value, child) => TotpCode(input: value.text),
        ),
        Text('Passkey', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        if (_editing?.record.passkey != null && !_removePasskey) ...[
          Text(
            '${_editing!.record.passkey!.rpId}\n${_editing!.record.passkey!.userName}',
          ),
          TextButton.icon(
            onPressed: _busy
                ? null
                : () => setState(() {
                    if (_confirmRemovePasskey) {
                      _removePasskey = true;
                    } else {
                      _confirmRemovePasskey = true;
                    }
                  }),
            icon: const Icon(Icons.key_off_outlined),
            label: Text(
              _confirmRemovePasskey
                  ? tr(context, 'Conferma rimozione dal vault')
                  : tr(context, 'Rimuovi passkey dalla credenziale'),
            ),
          ),
        ] else
          Text(
            _removePasskey
                ? tr(
                    context,
                    'La passkey sarà rimossa al salvataggio. Per revocarla sul sito, usa anche le impostazioni del sito.',
                  )
                : tr(
                    context,
                    'Crea la passkey dalle impostazioni di sicurezza del sito o dell’app e scegli ByteLocker come gestore.',
                  ),
          ),
        const SizedBox(height: 24),
        FilledButton(
          onPressed: _busy || !widget.vault.ready ? null : _save,
          child: Text(tr(context, 'Salva credenziale')),
        ),
        TextButton(
          onPressed: _busy ? null : _clearEditor,
          child: Text(tr(context, 'Chiudi senza salvare')),
        ),
        if (_editing != null) ...[
          const Divider(),
          TextButton.icon(
            onPressed: _busy || !widget.vault.ready
                ? null
                : () {
                    if (!_confirmDelete) {
                      setState(() {
                        _confirmDelete = true;
                      });
                      return;
                    }
                    unawaited(
                      _run(
                        () => widget.vault.remove(_editing!),
                        closeEditor: true,
                      ),
                    );
                  },
            icon: const Icon(Icons.delete_outline),
            label: Text(
              _confirmDelete
                  ? tr(context, 'Conferma eliminazione')
                  : tr(context, 'Elimina credenziale'),
            ),
          ),
          if (_confirmDelete)
            Text(
              tr(
                context,
                'La voce sarà rimossa dall’elenco. La cancellazione viene salvata cifrata sul server.',
              ),
            ),
        ],
      ],
    ),
  );

  void _view(VaultEntry entry) {
    _clearEditor();
    setState(() {
      _viewing = entry;
      _message = null;
    });
  }

  Future<String?> _prompt(Widget child) async {
    final route = DialogRoute<String>(context: context, builder: (_) => child);
    _dialog = route;
    final result = await Navigator.of(context).push(route);
    if (_dialog == route) _dialog = null;
    return mounted && !widget.vault.account.locked ? result : null;
  }

  Future<void> _chooseLogo() async {
    final slug = await _prompt(const BrandPicker());
    if (slug != null && mounted)
      setState(() => _formLogo = slug.isEmpty ? null : slug);
  }

  Future<void> _createCategory({bool assign = false}) async {
    final name = await _prompt(const _CategoryDialog());
    if (name == null || !mounted) return;
    if (widget.vault.categories.any(
      (item) => item.record.title.toLowerCase() == name.toLowerCase(),
    )) {
      setState(
        () =>
            _message = tr(context, 'Esiste già una categoria con questo nome.'),
      );
      return;
    }
    await _run(
      () => widget.vault.save(VaultRecord(title: name, isCategory: true)),
    );
    if (!mounted || widget.vault.account.locked) return;
    final matches = widget.vault.categories.where(
      (item) => item.record.title == name,
    );
    if (matches.isNotEmpty) {
      if (assign) {
        setState(() => _formCategory = matches.first.id.wire);
      } else {
        _navigate('category', category: matches.first.id.wire);
      }
    }
  }

  Future<void> _renameCategory(VaultEntry category) async {
    final name = await _prompt(_CategoryDialog(initial: category.record.title));
    if (name == null || !mounted || name == category.record.title) return;
    if (widget.vault.categories.any(
      (item) =>
          item.id.wire != category.id.wire &&
          item.record.title.toLowerCase() == name.toLowerCase(),
    )) {
      setState(
        () =>
            _message = tr(context, 'Esiste già una categoria con questo nome.'),
      );
      return;
    }
    await _run(
      () => widget.vault.save(
        VaultRecord(title: name, isCategory: true),
        replacing: category,
      ),
    );
  }

  Future<void> _copy(String value, String label) async {
    try {
      await SensitiveClipboard.copy(value);
      if (mounted && !widget.vault.account.locked) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(AppStrings.of(context).copied(label)),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (_) {
      if (mounted)
        setState(
          () => _message = tr(
            context,
            'Impossibile copiare negli appunti. Riprova.',
          ),
        );
    }
  }

  Future<void> _toggleFavorite(VaultEntry entry) => _run(() async {
    await widget.vault.save(
      entry.record.withOrganization(favorite: !entry.record.favorite),
      replacing: entry,
    );
    if (mounted && _viewing?.id.wire == entry.id.wire) {
      final updated = widget.vault.entries.where(
        (item) => item.id.wire == entry.id.wire,
      );
      setState(() => _viewing = updated.isEmpty ? null : updated.first);
    }
  });

  String _categoryName(String? id) {
    final matches = widget.vault.categories.where((item) => item.id.wire == id);
    return matches.isEmpty
        ? tr(context, 'Senza categoria')
        : matches.first.record.title;
  }

  String get _sectionTitle => switch (_section) {
    'favorites' => tr(context, 'Preferiti'),
    'uncategorized' => tr(context, 'Senza categoria'),
    'category' => _categoryName(_selectedCategory),
    'tag' => 'Tag: $_selectedTag',
    _ => tr(context, 'Il tuo vault'),
  };
  bool _inSection(VaultEntry entry) => switch (_section) {
    'favorites' => entry.record.favorite,
    'category' => entry.record.categoryId == _selectedCategory,
    'tag' => entry.record.tags.contains(_selectedTag),
    'uncategorized' => !widget.vault.categories.any(
      (item) => item.id.wire == entry.record.categoryId,
    ),
    _ => true,
  };
  void _navigate(String section, {String? category, String? tag}) {
    if (_busy || _passkeyRequest != null) return;
    _clearEditor();
    setState(() {
      _settings = false;
      _section = section;
      _selectedCategory = category;
      _selectedTag = tag;
    });
    _scaffold.currentState?.closeDrawer();
  }

  Widget _navigation() {
    final tags =
        widget.vault.entries
            .expand((entry) => entry.record.tags)
            .toSet()
            .toList()
          ..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
    Widget item(
      String title,
      IconData icon,
      String section,
      int count, {
      String? category,
      String? tag,
    }) => ListTile(
      selected:
          _section == section &&
          (category == null || category == _selectedCategory) &&
          (tag == null || tag == _selectedTag),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      leading: Icon(icon),
      title: Text(title, maxLines: 2, overflow: TextOverflow.ellipsis),
      trailing: Text('$count'),
      onTap: _busy || _passkeyRequest != null
          ? null
          : () => _navigate(section, category: category, tag: tag),
    );
    return ListView(
      padding: const EdgeInsets.all(12),
      children: [
        Padding(
          padding: EdgeInsets.fromLTRB(16, 20, 16, 20),
          child: Text(
            tr(context, 'IL TUO SPAZIO'),
            style: TextStyle(
              fontSize: 12,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.5,
            ),
          ),
        ),
        item(
          tr(context, 'Tutti i login'),
          Icons.grid_view_rounded,
          'all',
          widget.vault.entries.length,
        ),
        item(
          tr(context, 'Preferiti'),
          Icons.star_outline_rounded,
          'favorites',
          widget.vault.entries.where((entry) => entry.record.favorite).length,
        ),
        item(
          tr(context, 'Senza categoria'),
          Icons.folder_off_outlined,
          'uncategorized',
          widget.vault.entries
              .where(
                (entry) => !widget.vault.categories.any(
                  (category) => category.id.wire == entry.record.categoryId,
                ),
              )
              .length,
        ),
        const Divider(height: 32),
        Row(
          children: [
            Expanded(
              child: Padding(
                padding: EdgeInsets.only(left: 16),
                child: Text(
                  tr(context, 'Categorie'),
                  style: TextStyle(fontWeight: FontWeight.w700),
                ),
              ),
            ),
            IconButton(
              tooltip: tr(context, 'Nuova categoria'),
              onPressed: _busy || !widget.vault.ready || _passkeyRequest != null
                  ? null
                  : () => _createCategory(),
              icon: const Icon(Icons.create_new_folder_outlined),
            ),
          ],
        ),
        if (widget.vault.categories.isEmpty)
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              tr(context, 'Crea categorie come Personale o Lavoro.'),
              style: TextStyle(fontSize: 12),
            ),
          ),
        for (final category in widget.vault.categories)
          Row(
            children: [
              Expanded(
                child: item(
                  category.record.title,
                  Icons.folder_outlined,
                  'category',
                  widget.vault.entries
                      .where(
                        (entry) => entry.record.categoryId == category.id.wire,
                      )
                      .length,
                  category: category.id.wire,
                ),
              ),
              IconButton(
                tooltip: AppStrings.of(context)
                    .renameCategory(category.record.title),
                onPressed: _busy || _passkeyRequest != null
                    ? null
                    : () => _renameCategory(category),
                icon: const Icon(Icons.edit_outlined, size: 18),
              ),
            ],
          ),
        const Divider(height: 32),
        const Padding(
          padding: EdgeInsets.only(left: 16, bottom: 12),
          child: Text('Tag', style: TextStyle(fontWeight: FontWeight.w700)),
        ),
        if (tags.isEmpty)
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              tr(context, 'Aggiungi tag quando modifichi un login.'),
              style: TextStyle(fontSize: 12),
            ),
          ),
        for (final tag in tags)
          item(
            tag,
            Icons.tag_rounded,
            'tag',
            widget.vault.entries
                .where((entry) => entry.record.tags.contains(tag))
                .length,
            tag: tag,
          ),
      ],
    );
  }

  Widget _detailField(String label, String value, {bool copy = false}) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(label, style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 6),
            Row(
              children: [
                Expanded(child: SelectableText(value)),
                if (copy)
                  IconButton(
                    tooltip: AppStrings.of(context).copy(label.toLowerCase()),
                    icon: const Icon(Icons.copy_rounded),
                    onPressed: () => _copy(value, label),
                  ),
              ],
            ),
          ],
        ),
      );

  Widget _detailView(VaultEntry entry) {
    final record = entry.record;
    return Column(
      key: const ValueKey('credential-details'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Align(
          alignment: Alignment.centerLeft,
          child: TextButton.icon(
            onPressed: _clearEditor,
            icon: const Icon(Icons.arrow_back),
            label: Text(tr(context, 'Torna al vault')),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          tr(context, 'Dettagli credenziale'),
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            CredentialLogo(record: record),
            const SizedBox(width: 14),
            Expanded(
              child: Text(
                record.title,
                style: Theme.of(context).textTheme.headlineSmall,
              ),
            ),
            IconButton(
              tooltip: record.favorite
                  ? tr(context, 'Rimuovi dai preferiti')
                  : tr(context, 'Aggiungi ai preferiti'),
              onPressed: _busy ? null : () => _toggleFavorite(entry),
              icon: Icon(
                record.favorite
                    ? Icons.star_rounded
                    : Icons.star_outline_rounded,
                color: record.favorite ? Colors.amber : null,
              ),
            ),
            IconButton(
              tooltip: tr(context, 'Modifica credenziale'),
              onPressed: _busy ? null : () => _edit(entry),
              icon: const Icon(Icons.edit_outlined),
            ),
          ],
        ),
        const SizedBox(height: 28),
        if (record.categoryId != null)
          _detailField(
            tr(context, 'Categoria'),
            _categoryName(record.categoryId),
          ),
        if (record.username.isNotEmpty)
          _detailField('Username', record.username, copy: true),
        if (record.email.isNotEmpty)
          _detailField('Email', record.email, copy: true),
        Text('Password', style: Theme.of(context).textTheme.bodySmall),
        Row(
          children: [
            Expanded(
              child: SelectableText(
                enableInteractiveSelection: false,
                record.password.isEmpty
                    ? tr(context, 'Non impostata')
                    : _showPassword
                    ? record.password
                    : '••••••••',
                key: const ValueKey('detail-password'),
              ),
            ),
            if (record.password.isNotEmpty)
              IconButton(
                tooltip: tr(context, 'Copia password'),
                icon: const Icon(Icons.copy_rounded),
                onPressed: () => _copy(record.password, 'Password'),
              ),
            if (record.password.isNotEmpty)
              IconButton(
                tooltip: _showPassword
                    ? tr(context, 'Nascondi password')
                    : tr(context, 'Mostra password'),
                onPressed: () => setState(() => _showPassword = !_showPassword),
                icon: Icon(
                  _showPassword
                      ? Icons.visibility_off_outlined
                      : Icons.visibility_outlined,
                ),
              ),
          ],
        ),
        const SizedBox(height: 20),
        if (record.url.isNotEmpty) _detailField('URL', record.url, copy: true),
        if (record.notes.isNotEmpty)
          _detailField(tr(context, 'Note'), record.notes),
        if (record.tags.isNotEmpty) _detailField('Tag', record.tags.join(', ')),
        if (record.totp != null) TotpCode(input: record.totp!.secret),
        if (record.passkey != null) ...[
          _detailField('Passkey', record.passkey!.rpId),
          _detailField(
            tr(context, 'Account passkey'),
            record.passkey!.userName,
          ),
        ],
      ],
    );
  }

  Widget _listView() {
    final entries = widget.vault.entries
        .where(
          (entry) => entry.record.matches(_search.text) && _inSection(entry),
        )
        .toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(_sectionTitle, style: Theme.of(context).textTheme.headlineMedium),
        const SizedBox(height: 8),
        Text(
          AppStrings.of(context).credentials(entries.length),
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 24),
        TextField(
          autocorrect: false,
          enableSuggestions: false,
          controller: _search,
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            labelText: tr(context, 'Cerca per titolo, account, sito o tag'),
            prefixIcon: Icon(Icons.search),
          ),
        ),
        const SizedBox(height: 20),
        FilledButton.icon(
          onPressed: _busy || !widget.vault.ready ? null : () => _edit(),
          icon: const Icon(Icons.add),
          label: Text(tr(context, 'Nuova credenziale')),
        ),
        const SizedBox(height: 24),
        if (entries.isEmpty && !_busy)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 32),
            child: Text(
              widget.vault.entries.isEmpty
                  ? tr(
                      context,
                      'Il vault è vuoto. Aggiungi la tua prima credenziale.',
                    )
                  : tr(context, 'Nessuna credenziale trovata.'),
              textAlign: TextAlign.center,
            ),
          ),
        for (final entry in entries)
          Card(
            child: ListTile(
              leading: CredentialLogo(record: entry.record),
              title: Text(entry.record.title),
              subtitle: Text(
                entry.record.username.isNotEmpty
                    ? entry.record.username
                    : entry.record.email,
              ),
              trailing: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  IconButton(
                    tooltip: entry.record.favorite
                        ? tr(context, 'Rimuovi dai preferiti')
                        : tr(context, 'Aggiungi ai preferiti'),
                    onPressed: _busy || !widget.vault.ready
                        ? null
                        : () => _toggleFavorite(entry),
                    icon: Icon(
                      entry.record.favorite
                          ? Icons.star_rounded
                          : Icons.star_outline_rounded,
                      color: entry.record.favorite ? Colors.amber : null,
                    ),
                  ),
                  IconButton(
                    key: ValueKey('edit-${entry.id.wire}'),
                    tooltip: tr(context, 'Modifica credenziale'),
                    icon: const Icon(Icons.edit_outlined),
                    onPressed: _busy || !widget.vault.ready
                        ? null
                        : () => _edit(entry),
                  ),
                ],
              ),
              onTap: _busy || !widget.vault.ready ? null : () => _view(entry),
            ),
          ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final wide =
          constraints.maxWidth >= 1050 &&
          MediaQuery.textScalerOf(context).scale(1) <= 1.5;
      return Scaffold(
        key: _scaffold,
        drawer: wide ? null : Drawer(child: SafeArea(child: _navigation())),
        appBar: AppBar(
          leading: wide
              ? null
              : IconButton(
                  tooltip: tr(context, 'Categorie e preferiti'),
                  onPressed: () => _scaffold.currentState?.openDrawer(),
                  icon: const Icon(Icons.menu_rounded),
                ),
          title: const ByteLockerTitle(),
          automaticallyImplyLeading: false,
          actions: [
            IconButton(
              tooltip: tr(context, 'Impostazioni'),
              onPressed: _busy || _passkeyRequest != null
                  ? null
                  : () {
                      _clearEditor();
                      setState(() => _settings = !_settings);
                    },
              icon: const Icon(Icons.settings_outlined),
            ),
            IconButton(
              tooltip: tr(context, 'Aggiorna vault'),
              onPressed: _busy || _passkeyRequest != null
                  ? null
                  : () => unawaited(
                      _run(widget.vault.reload, closeEditor: _viewing != null),
                    ),
              icon: const Icon(Icons.sync),
            ),
            IconButton(
              tooltip: tr(context, 'Blocca ed esci'),
              onPressed: () => unawaited(widget.onLogout()),
              icon: const Icon(Icons.lock_outline),
            ),
          ],
        ),
        body: SafeArea(
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (wide) ...[
                SizedBox(width: 270, child: _navigation()),
                const VerticalDivider(width: 1),
              ],
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(24),
                  child: Center(
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(maxWidth: 760),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          if (_busy) const LinearProgressIndicator(),
                          if (_message != null)
                            Padding(
                              padding: const EdgeInsets.symmetric(vertical: 16),
                              child: Semantics(
                                liveRegion: true,
                                child: Text(_message!),
                              ),
                            ),
                          if (_passkeyError)
                            TextButton(
                              onPressed: () => unawaited(
                                _run(() async {
                                  await NativePasskeyClient().cancel();
                                  if (mounted)
                                    setState(() => _passkeyError = false);
                                }),
                              ),
                              child: Text(
                                tr(context, 'Annulla richiesta passkey'),
                              ),
                            ),
                          if (widget.vault.hasPendingWrite &&
                              _passkeyRequest == null) ...[
                            Text(
                              tr(
                                context,
                                'Una scrittura cifrata è in attesa di conferma. Non chiudere l’app se vuoi conservarne il tentativo.',
                              ),
                            ),
                            TextButton(
                              onPressed: _busy
                                  ? null
                                  : () => unawaited(
                                      _run(
                                        widget.vault.retryPending,
                                        closeEditor: true,
                                      ),
                                    ),
                              child: Text(
                                tr(context, 'Ripeti operazione in attesa'),
                              ),
                            ),
                          ],
                          const SizedBox(height: 12),
                          _passkeyRequest != null
                              ? PasskeyPanel(
                                  request: _passkeyRequest!,
                                  vault: widget.vault,
                                  onComplete: () =>
                                      setState(() => _passkeyRequest = null),
                                )
                              : _settings
                              ? ClientSettingsPanel(
                                  onClose: () =>
                                      setState(() => _settings = false),
                                  onBiometrics: widget.onBiometrics,
                                  biometricEnabled: widget.biometricEnabled,
                                )
                              : _editor
                              ? _editorView()
                              : _viewing != null
                              ? _detailView(_viewing!)
                              : _listView(),
                          const SizedBox(height: 24),
                          Text(
                            tr(
                              context,
                              'I contenuti sono cifrati sul dispositivo prima dell’invio.',
                            ),
                            style: TextStyle(fontSize: 12),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    },
  );
}

class _CategoryDialog extends StatefulWidget {
  const _CategoryDialog({this.initial = ''});
  final String initial;
  @override
  State<_CategoryDialog> createState() => _CategoryDialogState();
}

class _CategoryDialogState extends State<_CategoryDialog> {
  late final _name = TextEditingController(text: widget.initial);
  final _form = GlobalKey<FormState>();
  @override
  void dispose() {
    _name.clear();
    _name.dispose();
    super.dispose();
  }

  void _save() {
    if (_form.currentState!.validate())
      Navigator.pop(context, _name.text.trim());
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(
      widget.initial.isEmpty
          ? tr(context, 'Nuova categoria')
          : tr(context, 'Rinomina categoria'),
    ),
    content: Form(
      key: _form,
      child: TextFormField(
        key: const ValueKey('category-name'),
        controller: _name,
        autofocus: true,
        autocorrect: false,
        enableSuggestions: false,
        decoration: InputDecoration(
          labelText: tr(context, 'Nome'),
          hintText: tr(context, 'Per esempio: Lavoro'),
        ),
        onFieldSubmitted: (_) => _save(),
        validator: (value) {
          try {
            VaultRecord(title: (value ?? '').trim(), isCategory: true);
            return null;
          } on RecordFailure {
            return tr(context, 'Inserisci un nome breve, massimo 200 byte.');
          }
        },
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: Text(tr(context, 'Annulla')),
      ),
      FilledButton(
        onPressed: _save,
        child: Text(tr(context, 'Salva categoria')),
      ),
    ],
  );
}
