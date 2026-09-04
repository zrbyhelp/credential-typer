import 'dart:typed_data';

import 'package:credential_typer/transport/account_import.dart';
import 'package:credential_typer/vault/account.dart';
import 'package:credential_typer/transport/filter_sync.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('account import frame round trips website and password', () {
    final frame = AccountImportPayload.encode(
      title: 'GitHub',
      username: 'user@example.com',
      website: 'example.com',
      note: 'n',
      passwordBytes: Uint8List.fromList([1, 2, 3]),
    );
    final decoded = AccountImportPayload.decode(frame);
    expect(decoded.website, 'example.com');
    expect(decoded.passwordBytes, [1, 2, 3]);
  });

  test('website normalization strips scheme and path', () {
    expect(Account.normalizeWebsite(' https://www.Example.com/login?a=1 '),
        'example.com');
  });

  test('filter sync frame round trips', () {
    final frame = FilterSyncFrame.encode('ChatGPT.exe');
    expect(FilterSyncFrame.decode(frame), 'ChatGPT.exe');
  });
}
