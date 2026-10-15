import '../l10n/app_strings.dart';

import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import 'vault_record.dart';
part 'brand_catalog.g.dart';

final class BrandLogo {
  const BrandLogo(
    this.slug,
    this.name,
    this.color,
    this.domains,
    this.names, {
    this.fullColor = false,
  });
  final String slug, name;
  final Color color;
  final List<String> domains, names;
  final bool fullColor;
  String get asset => 'assets/brands/$slug.${fullColor ? 'png' : 'svg'}';
}

final _brandsBySlug = {for (final brand in brandLogos) brand.slug: brand};
final _brandsByDomain = {
  for (final brand in brandLogos)
    for (final domain in brand.domains) domain: brand,
};
final _brandNames = [
  for (final brand in brandLogos)
    for (final name in brand.names) (name, brand),
]..sort((a, b) => b.$1.length.compareTo(a.$1.length));
BrandLogo? brandBySlug(String? slug) => _brandsBySlug[slug];

BrandLogo? brandFor(VaultRecord record) {
  if (record.logo != null) return brandBySlug(record.logo);
  final address = record.url.trim();
  if (address.isNotEmpty) {
    try {
      final uri = Uri.tryParse(
        address.contains('://') ? address : 'https://$address',
      );
      if (uri == null ||
          !const ['https', 'http'].contains(uri.scheme) ||
          uri.host.isEmpty ||
          uri.userInfo.isNotEmpty ||
          uri.port < 1 ||
          uri.port > 65535)
        return null;
      final host = uri.host.toLowerCase().replaceFirst(RegExp(r'\.$'), '');
      // Most-specific host wins: mail.google.com uses Gmail, not Google.
      var suffix = host;
      while (suffix.contains('.')) {
        final found = _brandsByDomain[suffix];
        if (found != null) return found;
        suffix = suffix.substring(suffix.indexOf('.') + 1);
      }
      // Self-hosted apps legitimately use domains unrelated to their publisher.
      return _byName(record.title, onlySelfHosted: true);
    } on FormatException {
      return null;
    }
  }
  return _byName(record.title);
}

BrandLogo? _byName(String title, {bool onlySelfHosted = false}) {
  final normalized = title
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9]+'), ' ')
      .trim();
  for (final pair in _brandNames) {
    final name = pair.$1, logo = pair.$2;
    if (onlySelfHosted &&
        !const [
          'jellyfin',
          'immich',
          'gitlab',
          'bitwarden',
          'nextcloud',
          'homeassistant',
          'casaos',
          'plex',
          'synology',
          'proxmox',
        ].contains(logo.slug))
      continue;
    if (normalized == name ||
        name.length > 3 &&
            (normalized.startsWith('$name ') || normalized.endsWith(' $name')))
      return logo;
  }
  return null;
}

class CredentialLogo extends StatelessWidget {
  const CredentialLogo({super.key, required this.record});
  final VaultRecord record;
  @override
  Widget build(BuildContext context) {
    final brand = brandFor(record);
    final fallback = Icon(
      Icons.key_outlined,
      color: Theme.of(context).colorScheme.onPrimaryContainer,
    );
    return Semantics(
      label: brand == null ? 'Icona credenziale' : 'Logo ${brand.name}',
      image: true,
      child: Container(
        key: ValueKey(
          brand == null
              ? 'credential-logo-generic'
              : 'credential-logo-${brand.slug}',
        ),
        width: 44,
        height: 44,
        padding: const EdgeInsets.all(9),
        decoration: BoxDecoration(
          color: brand == null
              ? Theme.of(context).colorScheme.primaryContainer
              : !brand.fullColor && brand.color.computeLuminance() > 0.6
              ? const Color(0xff1c2533)
              : Colors.white,
          borderRadius: BorderRadius.circular(12),
        ),
        child: ExcludeSemantics(
          child: brand == null
              ? (record.title.trim().isEmpty
                    ? fallback
                    : Center(
                        child: Text(
                          String.fromCharCode(record.title.trim().runes.first)
                              .toUpperCase(),
                          maxLines: 1,
                          overflow: TextOverflow.clip,
                          style: TextStyle(
                            fontWeight: FontWeight.w700,
                            fontSize: 18,
                            color: Theme.of(context)
                                .colorScheme
                                .onPrimaryContainer,
                          ),
                        ),
                      ))
              : brand.fullColor
              ? Image.asset(
                  brand.asset,
                  fit: BoxFit.contain,
                  errorBuilder: (_, _, _) => fallback,
                )
              : SvgPicture.asset(
                  brand.asset,
                  colorFilter: ColorFilter.mode(brand.color, BlendMode.srcIn),
                  placeholderBuilder: (_) => const SizedBox(),
                  errorBuilder: (_, _, _) => fallback,
                ),
        ),
      ),
    );
  }
}

/// Searchable offline catalogue. Only the selected brand ID enters the vault.
class BrandPicker extends StatefulWidget {
  const BrandPicker({super.key});
  @override
  State<BrandPicker> createState() => _BrandPickerState();
}

class _BrandPickerState extends State<BrandPicker> {
  final _search = TextEditingController();
  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final query = _search.text.trim().toLowerCase();
    final results = query.isEmpty
        ? brandLogos
        : brandLogos
              .where(
                (brand) =>
                    brand.name.toLowerCase().contains(query) ||
                    brand.slug.contains(query) ||
                    brand.names.any((name) => name.contains(query)),
              )
              .toList();
    return AlertDialog(
      title: Text(tr(context, 'Scegli il logo')),
      content: SizedBox(
        width: 500,
        height: 420,
        child: Column(
          children: [
            TextField(
              controller: _search,
              autocorrect: false,
              enableSuggestions: false,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(
                labelText: tr(context, 'Cerca un servizio'),
                prefixIcon: Icon(Icons.search),
              ),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: ListView.builder(
                itemCount: results.length,
                itemBuilder: (context, index) {
                  final brand = results[index];
                  return ListTile(
                    leading: CredentialLogo(
                      record: VaultRecord(title: brand.name, logo: brand.slug),
                    ),
                    title: Text(brand.name),
                    onTap: () => Navigator.pop(context, brand.slug),
                  );
                },
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, ''),
          child: Text(tr(context, 'Automatico')),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context, 'generic'),
          child: Text(tr(context, 'Solo iniziale')),
        ),
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(tr(context, 'Annulla')),
        ),
      ],
    );
  }
}
