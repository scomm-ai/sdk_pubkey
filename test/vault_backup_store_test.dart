import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('LocalFileBackupStore round-trips a scomm-vault-export blob', () async {
    final files = <String, Uint8List>{};
    final store = LocalFileBackupStore(
      writeBytes: (identity, bytes) async => files[identity] = bytes,
      readBytes: (identity) async => files[identity],
      deleteBytes: (identity) async => files.remove(identity),
    );
    const identity = 'alice@example.com';
    final blob = {
      'kind': vaultExportKind,
      'header': {
        'format_version': vaultExportFormatVersion,
        'identity': identity,
        'tier': 'limited',
      },
      'vek_envelope': {'kdf': 'argon2id'},
    };
    await store.put(identity: identity, blob: blob);
    final got = await store.get(identity: identity);
    expect(got?['kind'], vaultExportKind);
    expect(jsonDecode(utf8.decode(files[identity]!))['header']['identity'],
        identity);
    await store.delete(identity: identity);
    expect(await store.get(identity: identity), isNull);
  });
}
