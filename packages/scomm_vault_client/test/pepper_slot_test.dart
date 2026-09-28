import 'openssl_ckvf.dart';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:dio/dio.dart';
import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

const now = '2026-09-27T00:00:00Z';
const password = 'generated-high-entropy-password';

/// Real crypto with Argon2id at the test floor so pepper slots (m=65536,
/// t=3 in the container) stay fast.
class FastKdfCrypto extends OpensslCkvfCrypto {
  @override
  Future<Uint8List> argon2id({
    required List<int> password,
    required List<int> salt,
    required int m,
    required int t,
    required int p,
    required int keyLength,
  }) =>
      super.argon2id(
        password: password,
        salt: salt,
        m: testArgon2id.m,
        t: testArgon2id.t,
        p: testArgon2id.p,
        keyLength: keyLength,
      );
}

/// In-memory vault host: `/v1/id/oprf/*` and `/v1/pw-oprf/*`.
class FakeVaultHost implements HttpClientAdapter {
  FakeVaultHost({required this.pepperKeys, required this.currentKid});

  /// kid → 32-byte POPRF secret key.
  final Map<String, Uint8List> pepperKeys;
  String currentKid;
  final tokens = <String>{'good-token'};
  Uint8List? identitySecret;
  var evaluations = 0;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    final path = options.uri.path;
    final body = options.data is Map ? options.data as Map : const {};
    if (path == '/v1/pw-oprf/keys') {
      return _ok({
        'suite': 'ristretto255-SHA512',
        'mode': 'poprf',
        'current_kid': currentKid,
        'keys': [
          for (final e in pepperKeys.entries)
            {
              'kid': e.key,
              'public_key': _b64(oprfPublicKey(e.value)),
              'status': e.key == currentKid ? 'current' : 'retired',
            },
        ],
      });
    }
    if (path == '/v1/pw-oprf/evaluate') {
      final auth = '${options.headers['Authorization'] ?? ''}';
      if (!auth.startsWith('OprfToken ') ||
          !tokens.contains(auth.substring(10))) {
        return _err(401, 'unauthorized');
      }
      final sk = pepperKeys[body['kid']];
      if (sk == null) return _err(400, 'unknown_kid');
      evaluations++;
      final out = poprfBlindEvaluate(
        sk,
        pepperInfo('${body['vault_id']}', '${body['slot_id']}'),
        base64Url.decode(base64Url.normalize('${body['blind']}')),
      );
      return _ok({
        'kid': body['kid'],
        'evaluation': _b64(out.evaluated),
        'proof': _b64(out.proof),
      });
    }
    if (path == '/v1/id/oprf/key') {
      return _ok({
        'suite': 'ristretto255-SHA512',
        'public_key': _b64(oprfPublicKey(identitySecret!)),
      });
    }
    if (path == '/v1/id/oprf/evaluate') {
      final blinded = base64Url.decode(base64Url.normalize('${body['blind']}'));
      return _ok(testIdentityEvaluate(identitySecret!, blinded));
    }
    return _err(404, 'not_found');
  }

  @override
  void close({bool force = false}) {}
}

Map<String, String> testIdentityEvaluate(Uint8List sk, Uint8List blinded) {
  final out = identityBlindEvaluateForTests(sk, blinded);
  return {'evaluation': _b64(out.evaluated), 'proof': _b64(out.proof)};
}

String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');

ResponseBody _ok(Object body) => ResponseBody.fromString(
      jsonEncode(body),
      200,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );

ResponseBody _err(int status, String code) => ResponseBody.fromString(
      jsonEncode({
        'error': {'code': code, 'message': code, 'details': {}},
        'code': code,
        'message': code,
      }),
      status,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );

Uint8List key(int b) => Uint8List(32)..[0] = b;

void main() {
  OpensslCkvfCrypto();
  final crypto = FastKdfCrypto();
  late FakeVaultHost host;
  late VaultHostClient client;
  final token = VaultAuthorization.oprfToken('good-token');

  setUp(() {
    host = FakeVaultHost(pepperKeys: {'k1': key(11)}, currentKid: 'k1');
    client = VaultHostClient(
      'https://vault.test',
      dio: Dio()..httpClientAdapter = host,
    );
  });

  Future<UnlockedVault> vaultWithPepperSlot() async {
    final keys = await client.pepperKeys();
    final vault = await createVault(
      CreateVaultOptions(
        identityType: 'email',
        identityValue: 'alice@example.com',
        password: password,
        crypto: crypto,
        now: now,
        kdf: testArgon2id,
      ),
    );
    return addPepperSlot(
      vault,
      crypto,
      method: passwordOprfMethod,
      secret: password,
      pepper: HostPepperOprf(client, token),
      key: keys.current,
      now: now,
    );
  }

  test('pepper slot round-trips through the host', () async {
    final vault = await vaultWithPepperSlot();
    final opened = await openVaultWithPepper(
      serializeContainer(vault.container),
      secret: password,
      pepper: HostPepperOprf(client, token),
      crypto: crypto,
    );
    expect(opened.vek, vault.vek);
    expect(host.evaluations, 2);
  });

  test('no unwrap without the host evaluation', () async {
    final vault = await vaultWithPepperSlot();
    final json = serializeContainer(vault.container);
    await expectLater(
      openVaultWithPepper(
        json,
        secret: password,
        pepper: HostPepperOprf(client, VaultAuthorization.oprfToken('stolen')),
        crypto: crypto,
      ),
      throwsA(isA<VaultClientException>()
          .having((e) => e.code, 'code', 'unauthorized')
          .having((e) => e.status, 'status', 401)),
    );
  });

  test('wrong host pepper key fails proof verification', () async {
    final vault = await vaultWithPepperSlot();
    host.pepperKeys['k1'] = key(99);
    await expectLater(
      openVaultWithPepper(
        serializeContainer(vault.container),
        secret: password,
        pepper: HostPepperOprf(client, token),
        crypto: crypto,
      ),
      throwsA(isA<VaultClientException>()
          .having((e) => e.code, 'code', 'invalid_evaluation')),
    );
  });

  test('kid rotation rewraps on unlock', () async {
    var vault = await vaultWithPepperSlot();
    final slotId = vault.container.unlockSlots.last.slotId;
    host.pepperKeys['k2'] = key(22);
    host.currentKid = 'k2';

    final json = serializeContainer(vault.container);
    final pepper = HostPepperOprf(client, token);
    final opened = await openVaultWithPepper(
      json,
      secret: password,
      pepper: pepper,
      crypto: crypto,
    );
    final keys = await client.pepperKeys();
    final slot = opened.container.unlockSlots.last;
    expect(keys.needsRewrap(slot.oprf!.kid), isTrue);
    vault = await rewrapPepperSlot(
      opened,
      crypto,
      slotId: slotId,
      secret: password,
      pepper: pepper,
      key: keys.current,
      now: now,
    );
    expect(vault.container.unlockSlots.last.oprf!.kid, 'k2');

    host.pepperKeys.remove('k1');
    final reopened = await openVaultWithPepper(
      serializeContainer(vault.container),
      secret: password,
      pepper: pepper,
      crypto: crypto,
    );
    expect(reopened.vek, vault.vek);
    await expectLater(
      openVaultWithPepper(json,
          secret: password, pepper: pepper, crypto: crypto),
      throwsA(isA<VaultClientException>()
          .having((e) => e.code, 'code', 'unknown_kid')),
    );
  });

  test('identity_id over HTTP matches the fixture', () async {
    final v = jsonDecode(
      File('test/fixtures/identity-voprf.json').readAsStringSync(),
    ) as Map<String, dynamic>;
    host.identitySecret =
        base64Url.decode(base64Url.normalize(v['secret_key'] as String));
    final pinned =
        base64Url.decode(base64Url.normalize(v['public_key'] as String));
    expect(
      await client.identityId('alice@example.com', publicKey: pinned),
      v['identity_id'],
    );
    await expectLater(
      client.identityId('alice@example.com', publicKey: key(1)),
      throwsA(isA<VaultClientException>()),
    );
  });

  test('grant claims parse; directory grants are opaque', () {
    final text = 'Scomm/grant/v1\niss=https://pubkey.scomm.ai\n'
        'aud=https://vault.scomm.ai\nkid=g1\npurpose=vault_backup\n'
        'identity_id=${'a' * 64}\nmsk_fingerprint=\namr=otp\nidp=\n'
        'exp=1790000000000\njti=AAAAAAAAAAAAAAAAAAAAAA\n';
    final token = '${_b64(utf8.encode(text))}.sig';
    final claims = parseGrantV1(token)!;
    expect(claims.purpose, 'vault_backup');
    expect(claims.aud, ['https://vault.scomm.ai']);
    expect(parseGrantV1('opaque-directory-token'), isNull);
    expect(VaultAuthorization.otpGrant(token).header, 'OtpGrant $token');
  });
}
