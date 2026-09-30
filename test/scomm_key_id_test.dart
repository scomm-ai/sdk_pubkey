import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('v4 OpenPGP key id is the last 8 octets of the SHA-1 fingerprint', () {
    final body = Uint8List.fromList([
      4, 0, 0, 0, 1, 27, 10, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, //
      0x01, 0x07, 0x40, 1, 2, 3, 4, 5, 6, 7,
    ]);
    final packet = Uint8List(2 + body.length);
    packet[0] = 0xc6;
    packet[1] = body.length;
    packet.setRange(2, packet.length, body);
    expect(ScommKeyId.derive(packet, purpose: 'verify'), '147CD60F0737319A');
    expect(ScommKeyId.derive(packet, purpose: 'encryption'), '147CD60F0737319A');
  });
}
