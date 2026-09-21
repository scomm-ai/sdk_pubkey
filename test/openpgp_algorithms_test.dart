import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:secmail_pubkey_sdk/src/runtime/pubkey_runtime.dart';
import 'package:test/test.dart';

void main() {
  group('OpenPgpAlgorithms.advertised', () {
    test('classical only when rfc9980Ready is false', () {
      expect(
        OpenPgpAlgorithms.advertised(rfc9980Ready: false),
        OpenPgpAlgorithms.classicalAdvertised,
      );
      expect(
        OpenPgpAlgorithms.advertised(rfc9980Ready: false),
        isNot(contains(OpenPgpAlgorithms.mlkem768X25519)),
      );
    });

    test('includes RFC 9980 names when the engine can run them', () {
      final names = OpenPgpAlgorithms.advertised(rfc9980Ready: true);
      expect(names, containsAll(OpenPgpAlgorithms.classicalAdvertised));
      expect(names, contains(OpenPgpAlgorithms.mldsa65Ed25519));
      expect(names, contains(OpenPgpAlgorithms.mlkem768X25519));
    });
  });

  test('discovery client advertises PQC by default', () {
    final client = createDiscoveryPubkeyClient(
      readBaseUrl: 'https://pubkey.test',
      writeBaseUrl: 'https://api.pubkey.test',
    );
    expect(
      client.pgpEngine.advertisedAlgorithms,
      contains(OpenPgpAlgorithms.mlkem768X25519),
    );
  });

  test('discovery client advertises PQC independent of subscription', () {
    final client = createDiscoveryPubkeyClient(
      rfc9980Ready: true,
      readBaseUrl: 'https://pubkey.test',
      writeBaseUrl: 'https://api.pubkey.test',
    );
    expect(
      client.pgpEngine.advertisedAlgorithms,
      contains(OpenPgpAlgorithms.mlkem768X25519),
    );
  });

  test('discovery client advertises S/MIME classical and PQC', () {
    final client = createDiscoveryPubkeyClient(
      readBaseUrl: 'https://pubkey.test',
      writeBaseUrl: 'https://api.pubkey.test',
    );
    expect(
      client.smimeEngine.advertisedAlgorithms,
      containsAll(SmimeAlgorithms.classicalAdvertised),
    );
    expect(
      client.smimeEngine.advertisedAlgorithms,
      contains(SmimeAlgorithms.mlkem768X25519),
    );
  });
}
