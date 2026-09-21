import 'dart:convert';
import 'dart:io';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('DiscoveryDocument preserves unknown extensions', () {
    final doc = DiscoveryDocument.fromJson({
      'schemaVersion': '1.0',
      'mailbox': 'alice@example.com',
      'capabilities': {
        'crypto': {
          'encryption': {
            'keys': [
              {'family': 'openpgp', 'keyId': '1'},
            ],
          },
          'verification': {
            'keys': [
              {'family': 'openpgp', 'keyId': '2'},
            ],
          },
        },
      },
      'extensions': {
        'https://example.org/discovery/appointment/v1': {'bookingRequired': true},
      },
      'futureRoot': true,
    });
    expect(doc.encryptionKeys(), hasLength(1));
    expect(doc.verificationKeys(), hasLength(1));
    expect(doc.raw['futureRoot'], isTrue);
    expect(
      doc.extensions['https://example.org/discovery/appointment/v1'],
      isA<Map>(),
    );
  });

  test('ScommKeyId is content-addressable XXXX-XXXX', () {
    final id = ScommKeyId.derive(utf8.encode('sig-key-material'));
    expect(id, matches(RegExp(r'^[0-9A-F]{4}-[0-9A-F]{4}$')));
    expect(ScommKeyId.derive(utf8.encode('sig-key-material')), id);
    expect(ScommKeyId.equals(id, id.replaceAll('-', '').toLowerCase()), isTrue);
  });

  test('mailbox path encoding keeps plus tags before canonicalization', () {
    final client = PubkeyClient(
      crypto: DartCryptoProvider(),
      readBaseUrl: 'https://pubkey.test',
      writeBaseUrl: 'https://api.pubkey.test',
    );
    // Server normalizeEmail strips +tags; path still encodes the canonical form.
    final encoded = client.encodeMailboxPath('Alice+tag@Example.COM');
    expect(encoded, contains('%40'));
    expect(encoded.toLowerCase(), isNot(contains('+')));
  });

  test('PubkeyException parses nested error envelope', () {
    final ex = PubkeyException.fromResponse(400, {
      'error': {
        'code': 'challenge_expired',
        'message': 'The challenge has expired.',
        'details': {},
      },
    });
    expect(ex.code, 'challenge_expired');
    expect(ex.message, contains('expired'));
  });

  test('signing vectors match SComm/Pubkey canonicalization', () {
    final file = File('conformance/fixtures/discovery/signing-vectors.json');
    final fixture = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final vector = (fixture['vectors'] as List).first as Map<String, dynamic>;
    final envelope = vector['envelope'] as Map<String, dynamic>;
    expect(
      payloadSha256Hex(envelope['payload']),
      vector['payload_sha256'],
    );
    final canonical = canonicalSignedUtf8(
      protocolVersion: envelope['protocol_version'] as int,
      operation: envelope['operation'] as String,
      principal: envelope['principal'] as String,
      timestamp: envelope['timestamp'] as int,
      nonce: envelope['nonce'] as String,
      payload: envelope['payload'],
    );
    expect(canonical, vector['canonical_utf8']);
  });

  test('mailbox-discovery fixture parses', () {
    final file = File('conformance/fixtures/discovery/mailbox-discovery.json');
    final json = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final doc = DiscoveryDocument.fromJson(json);
    expect(doc.schemaVersion, '1.0');
    expect(doc.mailbox, 'alice@example.com');
    expect(doc.encryptionKeys(), isNotEmpty);
    // Public discovery documents must not project verification key material.
    expect(doc.verificationKeys(), isEmpty);
  });
}
