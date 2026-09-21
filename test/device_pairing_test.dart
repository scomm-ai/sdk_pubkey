import 'dart:convert';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

const String _crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const String _locator = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';

Future<({Uint8List tek, Uint8List ya, Uint8List yb, Uint8List isk})> _honestCpace(
  DartCryptoProvider crypto, {
  required Uint8List password,
  String sessionId = 'session-a',
  String requestedTier = 'full',
}) async {
  final sid = DevicePairing.pairingSid(
    sessionId: sessionId,
    identityLocator: _locator,
    requestedTier: requestedTier,
  );
  final ci = DevicePairing.pairingCi(_locator);
  final start = await crypto.cpaceStart(password: password, sid: sid, ci: ci);
  final responded = await crypto.cpaceRespond(
    password: password,
    sid: sid,
    peerPublicElement: start.publicElement,
    ci: ci,
  );
  final iskA = await crypto.cpaceFinish(start, responded.publicElement);
  expect(iskA, equals(responded.isk));
  final tek = await DevicePairing.deriveTekV2(
    crypto,
    iskA,
    sessionId: sessionId,
    ya: start.publicElement,
    yb: responded.publicElement,
    identityLocator: _locator,
    requestedTier: requestedTier,
  );
  return (
    tek: tek,
    ya: start.publicElement,
    yb: responded.publicElement,
    isk: iskA,
  );
}

void main() {
  group('DevicePairing.generateSessionId', () {
    test('is 32-character lowercase hex', () {
      final crypto = DartCryptoProvider();
      for (var i = 0; i < 20; i++) {
        final id = DevicePairing.generateSessionId(crypto);
        expect(id, hasLength(32));
        expect(id, matches(RegExp(r'^[0-9a-f]{32}$')));
      }
    });
  });

  group('DevicePairing typed password', () {
    test('is 16 Crockford characters', () {
      final crypto = DartCryptoProvider();
      for (var i = 0; i < 50; i++) {
        final code = DevicePairing.generateTypedPassword(crypto);
        expect(code, hasLength(16));
        for (final ch in code.split('')) {
          expect(_crockfordAlphabet.contains(ch), isTrue);
        }
      }
    });

    test('rejects 8-character locators as typed passwords', () {
      expect(
        () => DevicePairing.typedPasswordBytes('ABCD1234'),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.pairingPasswordMismatch,
          ),
        ),
      );
    });
  });

  group('PairingUri', () {
    test('round-trips session id and 128-bit password', () {
      final crypto = DartCryptoProvider();
      final sid = DevicePairing.generateSessionId(crypto);
      final pw = DevicePairing.generateHighEntropyPassword(crypto);
      final encoded = PairingUri(sessionId: sid, password: pw).toUriString();
      expect(encoded, startsWith('scomm-pair:v2?'));
      final parsed = PairingUri.tryParse(encoded);
      expect(parsed, isNotNull);
      expect(parsed!.sessionId, sid);
      expect(parsed.password, pw);
    });

    test('rejects v1 URIs', () {
      expect(PairingUri.tryParse('scomm-pair:v1?sid=aa&pw=bb'), isNull);
    });
  });

  group('DevicePairing TEK derivation (CPace+HKDF v2)', () {
    test('both sides of the handshake derive the same TEK', () async {
      final crypto = DartCryptoProvider();
      final password = DevicePairing.generateHighEntropyPassword(crypto);
      final honest = await _honestCpace(crypto, password: password);
      expect(honest.tek, hasLength(32));
    });

    test('different passwords derive different TEKs', () async {
      final crypto = DartCryptoProvider();
      final a = await _honestCpace(
        crypto,
        password: DevicePairing.generateHighEntropyPassword(crypto),
      );
      final b = await _honestCpace(
        crypto,
        password: DevicePairing.generateHighEntropyPassword(crypto),
        sessionId: 'session-b',
      );
      expect(a.tek, isNot(equals(b.tek)));
    });

    test('refuseV1Tek never falls back to ECDH', () {
      expect(
        DevicePairing.refuseV1Tek,
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.pairingProtocolUnsupported,
          ),
        ),
      );
    });
  });

  group('DevicePairing wrap/unwrap transfer', () {
    test('round-trips VEK only (limited tier — no AEK envelope)', () async {
      final crypto = DartCryptoProvider();
      final password = DevicePairing.generateHighEntropyPassword(crypto);
      final honest = await _honestCpace(crypto, password: password);
      final vek = KeyHierarchy.generateVek(crypto);

      final envelopes =
          await DevicePairing.wrapForTransfer(crypto, honest.tek, vek);
      expect(envelopes.aekEnvelope, isNull);

      final recovered = await DevicePairing.unwrapTransfer(
        crypto,
        honest.tek,
        envelopes.vekEnvelope,
      );
      expect(recovered.vek, equals(vek));
      expect(recovered.aek, isNull);
    });

    test('round-trips VEK and AEK together (full tier)', () async {
      final crypto = DartCryptoProvider();
      final password = DevicePairing.generateHighEntropyPassword(crypto);
      final honest = await _honestCpace(crypto, password: password);
      final vek = KeyHierarchy.generateVek(crypto);
      final aek = KeyHierarchy.generateAek(crypto);

      final envelopes = await DevicePairing.wrapForTransfer(
        crypto,
        honest.tek,
        vek,
        aek,
      );
      expect(envelopes.aekEnvelope, isNotNull);

      final recovered = await DevicePairing.unwrapTransfer(
        crypto,
        honest.tek,
        envelopes.vekEnvelope,
        envelopes.aekEnvelope,
      );
      expect(recovered.vek, equals(vek));
      expect(recovered.aek, equals(aek));
    });

    test('tampered VEK ciphertext throws envelope_authentication_failure, '
        'no fallback', () async {
      final crypto = DartCryptoProvider();
      final password = DevicePairing.generateHighEntropyPassword(crypto);
      final honest = await _honestCpace(crypto, password: password);
      final vek = KeyHierarchy.generateVek(crypto);
      final envelopes =
          await DevicePairing.wrapForTransfer(crypto, honest.tek, vek);

      final tampered = WrappedKey(
        iv: envelopes.vekEnvelope.iv,
        ciphertext: Uint8List.fromList(envelopes.vekEnvelope.ciphertext)
          ..[0] ^= 1,
      );

      expect(
        () => DevicePairing.unwrapTransfer(crypto, honest.tek, tampered),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });

    test('wrong TEK fails to unwrap', () async {
      final crypto = DartCryptoProvider();
      final honest = await _honestCpace(
        crypto,
        password: DevicePairing.generateHighEntropyPassword(crypto),
      );
      final other = await _honestCpace(
        crypto,
        password: DevicePairing.generateHighEntropyPassword(crypto),
        sessionId: 'other',
      );
      final vek = KeyHierarchy.generateVek(crypto);
      final envelopes =
          await DevicePairing.wrapForTransfer(crypto, honest.tek, vek);

      expect(
        () => DevicePairing.unwrapTransfer(
          crypto,
          other.tek,
          envelopes.vekEnvelope,
        ),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.envelopeAuthenticationFailure,
          ),
        ),
      );
    });
  });

  group('MSK transcript', () {
    test('signs and verifies the canonical pairing transcript', () async {
      final crypto = DartCryptoProvider();
      final password = DevicePairing.generateHighEntropyPassword(crypto);
      final honest = await _honestCpace(crypto, password: password);
      final tagBox = await crypto.encryptAead(
        honest.tek,
        utf8.encode(pairingConfirmPlaintext),
      );
      final tag = WrappedKey(iv: tagBox.iv, ciphertext: tagBox.ciphertext);
      final transcript = DevicePairing.canonicalTranscript(
        sessionId: 'session-a',
        identityLocator: _locator,
        requestedTier: 'full',
        ya: honest.ya,
        yb: honest.yb,
        confirmationTag: tag,
      );
      final msk = await crypto.generateMSK();
      final sig = await crypto.sign(msk, transcript);
      expect(await crypto.verify(msk.publicKey!, transcript, sig), isTrue);
      transcript[10] ^= 1;
      expect(await crypto.verify(msk.publicKey!, transcript, sig), isFalse);
    });
  });

  group('PairingSessionStatus.fromJson (wire contract)', () {
    test('parses a PENDING response', () {
      final json = {
        'session_id': 'aa' * 16,
        'state': 'PENDING',
        'device_name': "Alice's iPhone",
        'requested_tier': 'full',
        'b_pake_element': encodeBase64Url([1, 2, 3]),
        'device_id': 'device-b-id',
      };
      final status = PairingSessionStatus.fromJson(json);
      expect(status.state, PairingSessionState.pending);
      expect(status.deviceName, "Alice's iPhone");
      expect(status.requestedTier, 'full');
      expect(status.bPakeElement, equals([1, 2, 3]));
      expect(status.deviceId, 'device-b-id');
      expect(status.aPakeElement, isNull);
      expect(status.vekEnvelope, isNull);
    });

    test('parses a RESPONDED response', () {
      final json = {
        'session_id': 'aa' * 16,
        'state': 'RESPONDED',
        'a_pake_element': encodeBase64Url([4, 5, 6]),
        'vek_envelope': {
          'iv': encodeBase64Url([7, 8]),
          'ciphertext': encodeBase64Url([9, 10]),
        },
        'confirmation_tag': {
          'iv': encodeBase64Url([11, 12]),
          'ciphertext': encodeBase64Url([13, 14]),
        },
        'msk_signature': encodeBase64Url(List.filled(64, 7)),
        'aek_envelope': null,
      };
      final status = PairingSessionStatus.fromJson(json);
      expect(status.state, PairingSessionState.responded);
      expect(status.aPakeElement, equals([4, 5, 6]));
      expect(status.vekEnvelope, isNotNull);
      expect(status.confirmationTag, isNotNull);
      expect(status.mskSignature, isNotNull);
      expect(status.aekEnvelope, isNull);
    });

    test('rejects v1 ephemeral fields', () {
      expect(
        () => PairingSessionStatus.fromJson({
          'session_id': 'ABCD1234',
          'state': 'PENDING',
          'b_ephemeral_public_key': encodeBase64Url([1, 2, 3]),
        }),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.pairingProtocolUnsupported,
          ),
        ),
      );
    });

    test('parses a COMPLETED response', () {
      final json = {'session_id': 'aa' * 16, 'state': 'COMPLETED'};
      final status = PairingSessionStatus.fromJson(json);
      expect(status.state, PairingSessionState.completed);
      expect(status.vekEnvelope, isNull);
      expect(status.deviceName, isNull);
    });
  });
}
