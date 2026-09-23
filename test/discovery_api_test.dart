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

  test('identity path rejects a mailbox address', () {
    final client = PubkeyClient(
      crypto: DartCryptoProvider(),
      readBaseUrl: 'https://pubkey.test',
      writeBaseUrl: 'https://api.pubkey.test',
    );
    expect(
      () => client.encodeIdentityPath('Alice+tag@Example.COM'),
      throwsA(isA<PubkeyException>()),
    );
    expect(client.encodeIdentityPath('ab' * 32), 'ab' * 32);
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

  test('DISCOVERY_PROTOCOL_VERSION pin declares specCommit', () {
    final pin = jsonDecode(
      File('DISCOVERY_PROTOCOL_VERSION.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    expect(pin['protocolVersion'], isNotEmpty);
    expect(pin['schemaVersion'], isNotEmpty);
    expect(pin['apiVersion']?.toString(), isNotEmpty);
    expect(pin['specCommit'], isNotEmpty);
  });

  test('signing vectors match SComm/Pubkey canonicalization', () {
    final file = File('conformance/fixtures/discovery/signing-vectors.json');
    expect(file.existsSync(), isTrue);
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
    expect(file.existsSync(), isTrue);
    final json = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final doc = DiscoveryDocument.fromJson(json);
    expect(doc.schemaVersion, '1.0');
    expect(doc.mailbox, 'alice@example.com');
    expect(doc.encryptionKeys(), isNotEmpty);
    // Public Discovery Documents MUST NOT project verification keys (gated
    // signing fetch). Encryption-only fixtures are expected.
    expect(doc.verificationKeys(), isEmpty);
  });

  group('Discovery Document encryption selection', () {
    DiscoveryDocument dualPublishDoc() => DiscoveryDocument.fromJson({
          'schemaVersion': '1.0',
          'mailbox': 'alice@example.com',
          'capabilities': {
            'crypto': {
              'encryption': {
                'keys': [
                  {
                    'family': 'openpgp',
                    'keyId': 'AAAA-0001',
                    'publicKey': 'classical-material',
                    'algorithms': ['openpgp-cv25519'],
                  },
                  {
                    'family': 'openpgp',
                    'keyId': 'BBBB-0002',
                    'publicKey': 'pqc-material',
                    'algorithms': ['openpgp-mlkem768-x25519'],
                  },
                ],
              },
            },
          },
        });

    test('classical-only sender gets cv25519, not PQC', () {
      final selected = dualPublishDoc().selectBestEncryptionKey({
        'families': {
          'pgp': ['openpgp-cv25519'],
        },
      });
      expect(selected, isNotNull);
      expect(selected!['algorithm'], 'openpgp-cv25519');
      expect(selected['public_material'], 'classical-material');
      expect(selected['published_key_id'], 'AAAA-0001');
    });

    test('PQC-capable sender prefers ML-KEM over classical', () {
      final selected = dualPublishDoc().selectBestEncryptionKey({
        'families': {
          'pgp': [
            'openpgp-cv25519',
            'openpgp-mlkem768-x25519',
          ],
        },
      });
      expect(selected, isNotNull);
      expect(selected!['algorithm'], 'openpgp-mlkem768-x25519');
      expect(selected['public_material'], 'pqc-material');
    });

    test('unsupported families yield null (no keys.first fallback)', () {
      final selected = dualPublishDoc().selectBestEncryptionKey({
        'families': {
          'smime': ['smime-rsa-oaep-sha256'],
        },
      });
      expect(selected, isNull);
    });

    test('maps openpgp family token to wire pgp for selection artifacts', () {
      final artifacts = dualPublishDoc().encryptionArtifactsForSelection();
      expect(artifacts, hasLength(2));
      expect(artifacts.every((a) => a['family'] == Families.pgp), isTrue);
      expect(artifacts.every((a) => a['purpose'] == Purposes.encryption), isTrue);
    });
  });
}
