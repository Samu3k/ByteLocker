import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:password_manager/transfer/bitwarden_csv.dart';
import 'package:password_manager/vault/vault_client.dart';
import 'package:password_manager/vault/vault_record.dart';

import 'vault_fixtures.dart';

Uint8List csv(String body) => Uint8List.fromList(utf8.encode(body));
const header =
    'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\r\n';
void main() {
  test('CSV preserves multiline notes, literal passwords, folders, favorites and TOTP', () async {
    final plan = await planBitwardenCsv(
      csv(
        '\ufeff$header"Work",1,login,"Example, inc.","line 1\r\nline 2 with ""quotes""",,0,https://example.test,alice@example.test," =secret,with ""quotes"" ",GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\r\n',
      ),
      [],
      [],
    );
    expect(plan.items.length, 1);
    final item = plan.items.single;
    expect(item.folder, 'Work');
    expect(item.record.favorite, isTrue);
    expect(item.record.title, 'Example, inc.');
    expect(item.record.password, ' =secret,with "quotes" ');
    expect(item.record.notes, 'line 1\r\nline 2 with "quotes"');
    expect(item.record.email, 'alice@example.test');
    expect(item.record.totp, isNotNull);
  });
  test('invalid grammar and unknown files fail without including contents in errors', () async {
    await expectLater(
      planBitwardenCsv(csv('$header"secret-not-closed'), [], []),
      throwsA(isA<TransferFailure>()),
    );
    await expectLater(
      planBitwardenCsv(csv('{"password":"never-print"}'), [], []),
      throwsA(isA<TransferFailure>()),
    );
    expect(const TransferFailure().toString(), isNot(contains('secret')));
  });
  test('unsupported rows and invalid TOTP are reported, never silently downgraded', () async {
    final plan = await planBitwardenCsv(
      csv(
        '${header}Work,0,card,Card,,,,,,,\r\n,0,login,Invalid,,,,https://example.test,user,pw,not-valid-2fa\r\n,0,login,Valid,,favorite: yes,1,https://example.test,user,pw,\r\n',
      ),
      [],
      [],
    );
    expect(plan.unsupported, 1);
    expect(plan.invalid, 1);
    expect(plan.items.length, 1);
    expect(plan.reprompt, 1);
    expect(plan.items.single.record.notes, contains('favorite: yes'));
  });
  test('encrypted import acknowledgements reload once; repeated CSV skips duplicates', () async {
    final api = MemoryVaultApi();
    final account = await api.login(
      'test@example.test',
      'Test-only master password 2026!',
    );
    final vault = VaultClient(api, account);
    addTearDown(() {
      vault.dispose();
      account.lock();
    });
    await vault.reload();
    await vault.saveImported(VaultRecord(title: 'Work', isCategory: true));
    final folder = vault.categories.single.id.wire;
    await vault.saveImported(
      VaultRecord(
        title: 'Literal',
        username: 'u',
        email: 'e@example.test',
        password: ' +pw\nline ',
        notes: 'notes,with quotes "',
        tags: ['work', 'a,b'],
        categoryId: folder,
        favorite: true,
      ),
    );
    final output = exportBitwardenCsv(vault.entries, vault.categories);
    final plan = await planBitwardenCsv(output, [], []);
    expect(plan.items.single.record.password, ' +pw\nline ');
    expect(plan.items.single.record.tags, ['work', 'a,b']);
    expect(plan.items.single.record.email, 'e@example.test');
    final duplicate = await planBitwardenCsv(
      output,
      vault.entries,
      vault.categories,
    );
    expect(duplicate.items, isEmpty);
    expect(duplicate.duplicates, 1);
    await vault.reload();
    expect(vault.entries.single.record.password, ' +pw\nline ');
    account.lock();
    await expectLater(
      vault.saveImported(VaultRecord(title: 'blocked')),
      throwsA(anything),
    );
    expect(vault.entries, isEmpty);
  });
  test('repeated CSV rows are skipped within the file', () async {
    const row = ',0,login,Example,,,0,https://example.test,user,pw,\r\n';
    final plan = await planBitwardenCsv(csv('$header$row$row'), [], []);
    expect(plan.items.length, 1);
    expect(plan.duplicates, 1);
  });
}
