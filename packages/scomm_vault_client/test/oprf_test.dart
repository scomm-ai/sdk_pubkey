import 'openssl_ckvf.dart';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

Map<String, dynamic> fixture(String name) =>
    jsonDecode(File('test/fixtures/$name').readAsStringSync())
        as Map<String, dynamic>;

Uint8List b64(String s) => base64Url.decode(base64Url.normalize(s));

Uint8List flip(Uint8List b, int i) => Uint8List.fromList(b)..[i] = b[i] ^ 0x01;

void main() {
  OpensslCkvfCrypto();
  group('pepper POPRF (ckvf test-vectors/pepper-oprf/poprf.json)', () {
    final v = fixture('pepper-poprf.json');
    final key = v['key'] as Map<String, dynamic>;
    final publicKey = b64(key['public_key'] as String);

    test('public key derives from the vector secret key', () {
      expect(oprfPublicKey(b64(key['secret_key'] as String)), publicKey);
    });

    for (final c in (v['cases'] as List).cast<Map<String, dynamic>>()) {
      final info = pepperInfo(v['vault_id'] as String, c['slot_id'] as String);
      final input = utf8.encode(c['secret'] as String);

      PoprfBlindState blindIt() => poprfBlind(
            input,
            info,
            publicKey,
            blind: b64(c['blind'] as String),
          );

      test('${c['id']}: blind, tweaked key, finalize', () {
        expect(info, b64(c['info'] as String));
        final state = blindIt();
        expect(state.blinded, b64(c['blinded'] as String));
        expect(state.tweakedKey, b64(c['tweaked_key'] as String));
        final rwd = poprfFinalize(
          state,
          b64(c['evaluated'] as String),
          b64(c['proof'] as String),
        );
        expect(rwd, b64(c['rwd'] as String));
      });

      test('${c['id']}: host evaluation matches noble', () {
        final out = poprfBlindEvaluate(
          b64(key['secret_key'] as String),
          info,
          b64(c['blinded'] as String),
        );
        expect(out.evaluated, b64(c['evaluated'] as String));
        expect(
          poprfFinalize(blindIt(), out.evaluated, out.proof),
          b64(c['rwd'] as String),
        );
      });

      test('${c['id']}: tampered proof or wrong key is rejected', () {
        final evaluated = b64(c['evaluated'] as String);
        final proof = b64(c['proof'] as String);
        expect(
          () => poprfFinalize(blindIt(), evaluated, flip(proof, 3)),
          throwsA(isA<VaultClientException>()
              .having((e) => e.code, 'code', 'invalid_evaluation')),
        );
        final otherKey = oprfPublicKey(Uint8List(32)..[0] = 9);
        final wrong = poprfBlind(
          input,
          info,
          otherKey,
          blind: b64(c['blind'] as String),
        );
        expect(
          () => poprfFinalize(wrong, evaluated, proof),
          throwsA(isA<VaultClientException>()),
        );
      });
    }
  });

  group('identity VOPRF', () {
    final v = fixture('identity-voprf.json');
    final publicKey = b64(v['public_key'] as String);
    IdentityBlindState blindIt() => identityBlind(
          utf8.encode(v['input'] as String),
          blind: b64(v['blind'] as String),
        );

    test('mode 0 blind, VOPRF proof, same identity_id', () {
      final state = blindIt();
      expect(state.blinded, b64(v['blinded'] as String));
      final out = identityFinalize(
        state,
        b64(v['evaluated'] as String),
        b64(v['proof'] as String),
        publicKey,
      );
      expect(out, b64(v['output'] as String));
      expect(identityIdFromOutput(out), v['identity_id']);
    });

    test('proof against another key is rejected', () {
      expect(
        () => identityFinalize(
          blindIt(),
          b64(v['evaluated'] as String),
          b64(v['proof'] as String),
          oprfPublicKey(Uint8List(32)..[0] = 9),
        ),
        throwsA(isA<VaultClientException>()),
      );
    });
  });
}
