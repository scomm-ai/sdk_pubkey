import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:secmail_pubkey_sdk/src/identity.dart';
import 'package:secmail_pubkey_sdk/src/oprf/identity_oprf.dart';
import 'package:test/test.dart';

void main() {
  test('RFC 9497 A.1.1 vector 1 blinds and finalizes', () {
    final file = File('conformance/fixtures/identity-oprf.json');
    final doc = jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    final vector = (doc['vectors'] as List).first as Map<String, dynamic>;
    final input = _hex(vector['inputHex'] as String);
    final blind = _hex(vector['blindHex'] as String);
    final blinded = oprfBlind(input, blind: blind);
    expect(bytesToHex(blinded.blindedElement), vector['blindedElementHex']);

    final evaluated = oprfBlindEvaluate(
      secretKey: _hex(
        '5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e',
      ),
      blindedElement: blinded.blindedElement,
    );
    expect(bytesToHex(evaluated), vector['evaluationElementHex']);

    final output = oprfFinalize(
      input: input,
      blind: blind,
      evaluatedElement: evaluated,
    );
    expect(bytesToHex(output), vector['outputHex']);
    expect(identityIdFromOprfFinalize(output), bytesToHex(output.sublist(0, 32)));
  });
}

Uint8List _hex(String value) {
  final clean = value.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
