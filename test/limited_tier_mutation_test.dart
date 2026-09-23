import 'package:secmail_pubkey_sdk/runtime.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

/// A device paired at the "limited" tier holds VEK but no AEK: it can read
/// the vault and cannot sign for it. That is its tier, not a fault.
///
/// [PubkeyRuntime.mutateUnlockedVault] is the best-effort "mirror this local
/// key into the vault" path. On a limited device it used to reach
/// [PubkeyRuntime.requireMsk] and throw `device_not_authorized` — which
/// crashed the app at startup, because `hydrateKeyManagerFromVault` mirrors
/// every key it imports back into the vault, including the ones it had just
/// read out of that same vault.
void main() {
  setUp(() {
    PubkeyRuntime.resetForTest();
    PubkeyRuntime.factory = (email, {dio}) => createPubkeyRuntime(
          email,
          dio: dio,
          readBaseUrl: 'http://127.0.0.1:3000',
          writeBaseUrl: 'http://127.0.0.1:3000',
        );
  });
  tearDown(PubkeyRuntime.resetForTest);

  test('a limited-tier device skips a best-effort vault mirror', () async {
    const email = 'limited-tier@example.com';
    final runtime = PubkeyRuntime.instance(email: email);
    final vek = runtime.crypto.random(32);
    await runtime.store.ensureDkek(runtime.crypto);
    await runtime.store.setVek(runtime.crypto, vek);
    await runtime.vault.createVault('ab' * 32);
    // VEK only — exactly what a "limited" pairing grant leaves behind.
    expect(await runtime.store.getAek(runtime.crypto), isNull);

    var ran = false;
    await runtime.mutateUnlockedVault(
      email: email,
      mutation: (_) => ran = true,
    );

    expect(
      ran,
      isFalse,
      reason: 'nothing to upload without authority — and nothing to throw',
    );
  });

  test('a deliberate mutation still refuses to pretend it uploaded', () async {
    const email = 'limited-tier-strict@example.com';
    final runtime = PubkeyRuntime.instance(email: email);
    final vek = runtime.crypto.random(32);
    await runtime.store.ensureDkek(runtime.crypto);
    await runtime.store.setVek(runtime.crypto, vek);
    await runtime.vault.createVault('ab' * 32);

    await expectLater(
      runtime.mutateAndUpload(email: email, mutation: (_) {}),
      throwsA(
        isA<PubkeyException>().having(
          (e) => e.code,
          'code',
          ErrorCodes.deviceNotAuthorized,
        ),
      ),
    );
  });
}
