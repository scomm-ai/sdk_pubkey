import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:scomm_vault_client/src/pairing/cpace.dart';
import 'package:test/test.dart';

import 'fake_host.dart';

const identityId =
    'abababababababababababababababababababababababababababababababab';

void main() {
  final crypto = DartCkvfCrypto();

  test('CPace and TEK match the pubkey SDK v2 pairing bytes', () {
    const session = '00112233445566778899aabbccddeeff';
    final password = Uint8List.fromList(List.generate(16, (i) => i + 1));
    final sid = PairingProtocol.sid(session, identityId);
    final ci = PairingProtocol.ci(identityId);
    final a = cpaceStart(
      password: password,
      sid: sid,
      ci: ci,
      random64: List.generate(64, (i) => i),
    );
    final r = cpaceRespond(
      password: password,
      sid: sid,
      ci: ci,
      peerYa: a.ya,
      random64: List.generate(64, (i) => 255 - i),
    );
    expect(
        bytesToBase64url(sid), 'SbfR8pRSVdhHYQ98z3fNphvbEu0OlJXPtLzsa6euWlc');
    expect(
        bytesToBase64url(a.ya), '-uy2n2V4XupURljlMHqqVgfc2kXork1iM0gICnX2KR4');
    expect(
        bytesToBase64url(r.yb), 'BB8od_SmIPWRzh_xvQ4NM3ryYp16XR2R_NpzKAwj8So');
    expect(
      bytesToBase64url(r.isk),
      'o0CknlXcaZskEW6UmK0u-yhZcGWpnbSaaNADTAWtWOlw0cZuXkUvjO-3lFJvm1S9Rgd2YI-hCBzOv60RREzXzg',
    );
    expect(cpaceFinish(a, r.yb), r.isk);
    expect(
      bytesToBase64url(PairingProtocol.tek(r.isk,
          sessionId: session, ya: a.ya, yb: r.yb, identityId: identityId)),
      'G1cUDjJ4GdmndkSeW205zVLUKfuJ0hA65q5SH6KJZJ8',
    );
  });

  test('pairing URI and typed passwords round-trip', () {
    final pw = PairingProtocol.generateHighEntropyPassword(crypto);
    final uri = PairingUri(sessionId: 'abc', password: pw).toUriString();
    final parsed = PairingUri.tryParse(uri)!;
    expect(parsed.sessionId, 'abc');
    expect(parsed.password, pw);
    expect(PairingUri.tryParse('scomm-pair:v1?sid=a&pw=b'), isNull);

    final typed = PairingProtocol.generateTypedPassword(crypto);
    expect(typed, hasLength(16));
    expect(PairingProtocol.typedPasswordBytes(typed.toLowerCase()),
        PairingProtocol.typedPasswordBytes(typed));
    expect(() => PairingProtocol.typedPasswordBytes('short'),
        throwsA(isA<VaultClientException>()));
  });

  group('device pairing over the host mailbox', () {
    late FakeVaultHost host;
    late KeyVault laptop;

    VaultHostBinding bind() => VaultHostBinding(
          host: host,
          identityId: identityId,
          authorize: (_, __) async => VaultAuthorization.device('test'),
        );

    setUp(() async {
      host = FakeVaultHost();
      laptop =
          KeyVault(MemoryLocalVaultStore(), crypto: crypto, binding: bind());
      await laptop.create(
        email: 'alice@example.com',
        device: const VaultDevice(deviceId: 'dev-laptop', name: 'Laptop'),
      );
    });

    test('the new device receives the VEK and joins with its own slot',
        () async {
      final offer = await startPairing(
        host: host,
        identityId: identityId,
        deviceName: 'Phone',
        deviceId: 'dev-phone',
        pollInterval: const Duration(milliseconds: 5),
        crypto: crypto,
      );
      final parsed = PairingUri.tryParse(offer.uri)!;
      final request = await fetchPairingRequest(host, parsed.sessionId);
      expect(request.deviceName, 'Phone');
      await approvePairing(
        vault: laptop,
        request: request,
        password: parsed.password,
        pollInterval: const Duration(milliseconds: 5),
      );
      final opened = await offer.completed;

      final phone =
          KeyVault(MemoryLocalVaultStore(), crypto: crypto, binding: bind());
      await phone.adopt(
        opened,
        device: const VaultDevice(deviceId: 'dev-phone', name: 'Phone'),
        storedOnHost: true,
      );
      await phone.push();
      await laptop.pull();
      expect(
          laptop.devices.map((d) => d.name), containsAll(['Laptop', 'Phone']));
      expect(phone.mskPublicKey, laptop.mskPublicKey);
    });

    test('a wrong password fails the confirmation', () async {
      final offer = await startPairing(
        host: host,
        identityId: identityId,
        deviceName: 'Phone',
        deviceId: 'dev-phone',
        typedPassword: true,
        pollInterval: const Duration(milliseconds: 5),
        crypto: crypto,
      );
      final request = await fetchPairingRequest(host, offer.sessionId);
      final wrong = PairingProtocol.typedPasswordBytes(
        PairingProtocol.generateTypedPassword(crypto),
      );
      final completed = expectLater(
        offer.completed,
        throwsA(isA<VaultClientException>()
            .having((e) => e.code, 'code', 'pairing_password_mismatch')),
      );
      await approvePairing(
        vault: laptop,
        request: request,
        password: wrong,
        pollInterval: const Duration(milliseconds: 5),
      );
      await completed;
    });
  });
}
