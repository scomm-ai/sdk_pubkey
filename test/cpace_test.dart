import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  group('CPace-Ristretto255-SHA512', () {
    test('honest initiator and responder share isk', () async {
      final crypto = DartCryptoProvider();
      final password = crypto.random(16);
      final sid = crypto.random(32);
      final ci = Uint8List.fromList([1, 2, 3]);
      final start = await crypto.cpaceStart(password: password, sid: sid, ci: ci);
      final responded = await crypto.cpaceRespond(
        password: password,
        sid: sid,
        peerPublicElement: start.publicElement,
        ci: ci,
      );
      final isk = await crypto.cpaceFinish(start, responded.publicElement);
      expect(isk, equals(responded.isk));
      expect(isk, isNot(equals(Uint8List(isk.length))));
    });

    test('mutated Ya diverges or is rejected', () async {
      final crypto = DartCryptoProvider();
      final password = crypto.random(16);
      final sid = crypto.random(32);
      final start = await crypto.cpaceStart(password: password, sid: sid);
      final mutated = Uint8List.fromList(start.publicElement)..[0] ^= 0x01;
      try {
        final responded = await crypto.cpaceRespond(
          password: password,
          sid: sid,
          peerPublicElement: mutated,
        );
        final isk = await crypto.cpaceFinish(start, responded.publicElement);
        expect(isk, isNot(equals(responded.isk)));
      } on PubkeyException {
        // Invalid encoding after mutation is also a successful reject.
      }
    });

    test('wrong password diverges isk', () async {
      final crypto = DartCryptoProvider();
      final sid = crypto.random(32);
      final start = await crypto.cpaceStart(
        password: crypto.random(16),
        sid: sid,
      );
      final responded = await crypto.cpaceRespond(
        password: crypto.random(16),
        sid: sid,
        peerPublicElement: start.publicElement,
      );
      final isk = await crypto.cpaceFinish(start, responded.publicElement);
      expect(isk, isNot(equals(responded.isk)));
    });

    test('invalid point is rejected', () async {
      final crypto = DartCryptoProvider();
      final start = await crypto.cpaceStart(
        password: crypto.random(16),
        sid: crypto.random(32),
      );
      expect(
        () => crypto.cpaceFinish(start, Uint8List(32)),
        throwsA(
          isA<PubkeyException>().having(
            (e) => e.code,
            'code',
            ErrorCodes.invalidPublicKey,
          ),
        ),
      );
    });
  });
}
