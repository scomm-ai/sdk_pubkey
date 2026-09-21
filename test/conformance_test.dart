import 'dart:convert';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

import 'helpers.dart';

void main() {
  group('identity fixtures', () {
    final fixtures = loadFixture('normalized-identities.json');

    for (final raw in fixtures['vectors'] as List) {
      final vector = Map<String, dynamic>.from(raw as Map);
      test(vector['id'] as String, () {
        expect(normalizeEmail(vector['input'] as String), vector['canonical']);
        expect(
          emailSha256Hex(vector['canonical'] as String),
          vector['sha256'],
        );
        expect(
          principalFromEmail(vector['input'] as String),
          vector['principal'],
        );
      });
    }

    test('accepts valid mailboxes', () {
      for (final email in fixtures['valid'] as List) {
        expect(isValidEmail(email as String), isTrue, reason: email);
      }
    });

    test('rejects invalid mailboxes', () {
      for (final email in fixtures['invalid'] as List) {
        expect(isValidEmail(email as String), isFalse, reason: email);
      }
    });

    test('requireCanonicalEmail rejects non-canonical input', () {
      expect(requireCanonicalEmail('alice@example.com'), 'alice@example.com');
      expect(
        requireCanonicalEmail('alice+work@example.com'),
        'alice+work@example.com',
      );
      expect(
        () => requireCanonicalEmail('Alice@example.com'),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.emailNotCanonical,
          ),
        ),
      );
    });

    test('plus-tag is a distinct principal from the base mailbox', () {
      expect(
        normalizeEmail('alice+work@example.com'),
        isNot(normalizeEmail('alice@example.com')),
      );
      expect(
        principalFromEmail('alice+work@example.com'),
        isNot(principalFromEmail('alice@example.com')),
      );
      expect(
        principalFromEmail('alice+work@gmail.com'),
        isNot(principalFromEmail('alice@gmail.com')),
      );
    });
  });

  group('signed-request fixtures', () {
    final fixtures = loadFixture('signed-requests.json');

    for (final raw in fixtures['vectors'] as List) {
      final vector = Map<String, dynamic>.from(raw as Map);
      test(vector['id'] as String, () {
        final env = Map<String, dynamic>.from(vector['envelope'] as Map);
        expect(canonicalizeJson(env['payload']), vector['payload_jcs']);
        expect(payloadSha256Hex(env['payload']), vector['payload_sha256']);
        expect(
          canonicalSignedUtf8(
            protocolVersion: env['protocol_version'] as int,
            operation: env['operation'] as String,
            principal: env['principal'] as String,
            timestamp: env['timestamp'] as int,
            nonce: env['nonce'] as String,
            payload: env['payload'],
          ),
          vector['canonical_utf8'],
        );
      });
    }
  });

  group('capability negotiation', () {
    final fixtures = loadFixture('capability-negotiation.json');

    for (final raw in fixtures['cases'] as List) {
      final testCase = Map<String, dynamic>.from(raw as Map);
      test(testCase['id'] as String, () {
        final selected = selectBestArtifact(
          testCase['artifacts'] as List,
          Map<String, dynamic>.from(testCase['capabilities'] as Map),
          Map<String, dynamic>.from(testCase['preferences'] as Map),
        );
        final expected = testCase['expected'];
        if (expected == null) {
          expect(selected, isNull);
        } else {
          final want = Map<String, dynamic>.from(expected as Map);
          expect(selected!['key_id'], want['key_id']);
          expect(selected['family'], want['family']);
          expect(selected['algorithm'], want['algorithm']);
        }
      });
    }
  });

  test('Ed25519 sign/verify of fixture canonical bytes', () async {
    final fixtures = loadFixture('signed-requests.json');
    final msk = Map<String, dynamic>.from(fixtures['msk'] as Map);
    final vector = Map<String, dynamic>.from(
      (fixtures['vectors'] as List).first as Map,
    );
    final canonical = utf8.encode(vector['canonical_utf8'] as String);
    final publicKey = hexToBytes(msk['public_key_hex'] as String);
    final privateKey = hexToBytes(msk['private_key_hex'] as String);
    final fixtureSig = decodeBase64Url(vector['signature_base64url'] as String);

    final crypto = DartCryptoProvider();
    expect(
      await crypto.verify(publicKey, canonical, fixtureSig),
      isTrue,
    );

    final key = await crypto.importPrivateKey(
      PortablePrivateKey(
        algorithm: 'ed25519',
        encoding: 'raw-32',
        bytes: privateKey,
        publicKey: publicKey,
      ),
    );
    final signature = await crypto.sign(key, canonical);
    expect(encodeBase64Url(signature), vector['signature_base64url']);
    expect(await crypto.verify(publicKey, canonical, signature), isTrue);

    canonical[0] = canonical[0] ^ 1;
    expect(await crypto.verify(publicKey, canonical, fixtureSig), isFalse);
  });

  test('error codes include required machine-readable values', () {
    for (final code in [
      'invalid_signature',
      'unknown_principal',
      'master_key_not_armed',
      'timestamp_out_of_window',
      'nonce_replayed',
      'unsupported_protocol_version',
      'otp_invalid',
      'provider_unavailable',
      'hardware_protection_unavailable',
      'key_not_exportable',
      'vault_locked',
      'vault_authentication_failure',
    ]) {
      expect(ErrorCodes.all, contains(code));
    }
  });
}
