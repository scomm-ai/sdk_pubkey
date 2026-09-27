import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart'
    show PepperKey, VaultContainer, base64urlToBytes, validateContainerShape;
import 'package:dio/dio.dart';

import 'authorization.dart';
import 'errors.dart';
import 'oprf/identity_voprf.dart';
import 'signing.dart';

/// A stored CKVF generation (`record` of a vault read).
class VaultRecord {
  const VaultRecord({
    required this.container,
    required this.mskSignature,
    this.createdAt,
  });

  final VaultContainer container;

  /// Raw 64-byte Ed25519 signature over [vaultRecordsSigningText].
  final Uint8List mskSignature;
  final String? createdAt;

  int get generation => container.generation;
  String get generationHash => container.generationHash;
}

/// Parsed `GET /v1/vault/{vault_id}/current|generation/{n}`.
class VaultRead {
  const VaultRead({
    this.record,
    this.mskPublicKey,
    this.archivedMskPublicKeys = const [],
    this.oprfToken,
  });

  factory VaultRead.fromJson(Map<String, dynamic> body) {
    final raw = body['record'];
    VaultRecord? record;
    if (raw is Map && raw['container'] is Map) {
      final sig = raw['msk_signature'];
      final value = sig is Map ? sig['value'] : null;
      if (value is! String) {
        throw VaultClientException('bad_response', 'record.msk_signature');
      }
      final container = validateContainerShape(
        Map<String, dynamic>.from(raw['container'] as Map),
      );
      if (raw['generation'] != null &&
          raw['generation'] != container.generation) {
        throw VaultClientException('bad_response', 'record.generation');
      }
      record = VaultRecord(
        container: container,
        mskSignature: base64urlToBytes(value, 64),
        createdAt: raw['created_at']?.toString(),
      );
    }
    final msk = body['msk_public_key'];
    final archived = body['archived_msk_public_keys'];
    return VaultRead(
      record: record,
      mskPublicKey: msk is String ? base64urlToBytes(msk, 32) : null,
      archivedMskPublicKeys: archived is List
          ? [for (final k in archived) base64urlToBytes('$k', 32)]
          : const [],
      oprfToken: body['oprf_token'] as String?,
    );
  }

  final VaultRecord? record;

  /// The armed MSK, then archived ones; a record may carry any of them.
  final Uint8List? mskPublicKey;
  final List<Uint8List> archivedMskPublicKeys;
  final String? oprfToken;
}

class PepperKeyInfo {
  const PepperKeyInfo({
    required this.kid,
    required this.publicKey,
    required this.status,
  });

  final String kid;
  final Uint8List publicKey;

  /// `current` or `retired`.
  final String status;

  PepperKey get asPepperKey => PepperKey(kid: kid, publicKey: publicKey);
}

/// `GET /v1/pw-oprf/keys`.
class PepperKeySet {
  const PepperKeySet({required this.currentKid, required this.keys});

  final String currentKid;
  final List<PepperKeyInfo> keys;

  PepperKey get current => byKid(currentKid)!.asPepperKey;

  PepperKeyInfo? byKid(String kid) {
    for (final k in keys) {
      if (k.kid == kid) return k;
    }
    return null;
  }

  /// A slot pinned to [kid] should be rewrapped after unlock.
  bool needsRewrap(String kid) => kid != currentKid;
}

class PepperEvaluation {
  const PepperEvaluation({
    required this.kid,
    required this.evaluated,
    required this.proof,
  });

  final String kid;
  final Uint8List evaluated;
  final Uint8List proof;
}

/// HTTP client for the vault host (ckvf `profiles/vault-host.md`). It moves
/// opaque containers and grants; `package:ckvf` opens them.
class VaultHostClient {
  VaultHostClient(String baseUrl, {Dio? dio})
      : _base = baseUrl.replaceAll(RegExp(r'/+$'), ''),
        _dio = dio ?? Dio();

  final String _base;
  final Dio _dio;

  /// `GET /v1/id/oprf/key`.
  Future<Uint8List> identityOprfKey() async {
    final body = await _get('/v1/id/oprf/key');
    return _bytes(body, 'public_key', 32);
  }

  /// Runs the identity OPRF for [canonicalMailbox] and verifies the proof.
  /// Pass [publicKey] from configuration to pin the host key; otherwise the
  /// key is fetched from the same host.
  Future<String> identityId(
    String canonicalMailbox, {
    List<int>? publicKey,
  }) async {
    final key = publicKey ?? await identityOprfKey();
    final state = identityBlind(utf8.encode(canonicalMailbox));
    final body = await _post('/v1/id/oprf/evaluate', {
      'blind': _b64(state.blinded),
    });
    final out = identityFinalize(
      state,
      _bytes(body, 'evaluation', 32),
      _bytes(body, 'proof', 64),
      key,
    );
    return identityIdFromOutput(out);
  }

  /// `GET /v1/pw-oprf/keys`.
  Future<PepperKeySet> pepperKeys() async {
    final body = await _get('/v1/pw-oprf/keys');
    final keys = body['keys'];
    final current = body['current_kid'];
    if (keys is! List || current is! String) {
      throw VaultClientException('bad_response', 'pw-oprf keys');
    }
    final set = PepperKeySet(
      currentKid: current,
      keys: [
        for (final k in keys.cast<Map<String, dynamic>>())
          PepperKeyInfo(
            kid: '${k['kid']}',
            publicKey: _bytes(k, 'public_key', 32),
            status: '${k['status']}',
          ),
      ],
    );
    if (set.byKid(current) == null) {
      throw VaultClientException('bad_response', 'current_kid is not listed');
    }
    return set;
  }

  /// `POST /v1/pw-oprf/evaluate`. Callers normally use `HostPepperOprf`,
  /// which blinds, calls this, and verifies.
  Future<PepperEvaluation> evaluatePepper({
    required String vaultId,
    required String slotId,
    required String kid,
    required List<int> blinded,
    required VaultAuthorization authorization,
  }) async {
    final body = await _post(
      '/v1/pw-oprf/evaluate',
      {
        'vault_id': vaultId,
        'slot_id': slotId,
        'kid': kid,
        'blind': _b64(blinded),
      },
      authorization: authorization,
    );
    return PepperEvaluation(
      kid: '${body['kid']}',
      evaluated: _bytes(body, 'evaluation', 32),
      proof: _bytes(body, 'proof', 64),
    );
  }

  /// `GET /v1/vault/{vault_id}/current`. A grant-authorized read also
  /// returns `oprf_token`.
  Future<Map<String, dynamic>> current(
    String vaultId,
    VaultAuthorization authorization,
  ) =>
      _get('/v1/vault/$vaultId/current', authorization: authorization);

  /// `GET /v1/vault/{vault_id}/generation/{n}`.
  Future<Map<String, dynamic>> generation(
    String vaultId,
    int n,
    VaultAuthorization authorization,
  ) =>
      _get('/v1/vault/$vaultId/generation/$n', authorization: authorization);

  /// [current], parsed. `record` is null while the host stores no CKVF
  /// container for this vault.
  Future<VaultRead> currentRecord(
    String vaultId,
    VaultAuthorization authorization,
  ) async =>
      VaultRead.fromJson(await current(vaultId, authorization));

  /// [generation], parsed.
  Future<VaultRead> generationRecord(
    String vaultId,
    int n,
    VaultAuthorization authorization,
  ) async =>
      VaultRead.fromJson(await generation(vaultId, n, authorization));

  /// `POST /v1/vault/{vault_id}/records`: stores the next generation.
  /// Throws `generation_conflict` (409) with the stored heads in
  /// [VaultClientException.details] when [container] does not extend them.
  Future<Map<String, dynamic>> putRecord({
    required String identityId,
    required VaultContainer container,
    required MskSigner signer,
    String? licenseDeviceId,
  }) async =>
      _post('/v1/vault/${container.vaultId}/records', {
        'identity_id': identityId,
        'container': container.toJson(),
        'msk_signature': await signer.recordSignature(
          identityId: identityId,
          container: container,
        ),
        if (licenseDeviceId != null) 'license_device_id': licenseDeviceId,
      });

  /// `POST /v1/mutate` with an envelope from [MskSigner.envelope].
  Future<Map<String, dynamic>> mutate(Map<String, dynamic> envelope) =>
      _post('/v1/mutate', envelope);

  /// `GET /v1/vault/{vault_id}/pending-mutations`.
  Future<List<Map<String, dynamic>>> pendingMutations(
    String vaultId,
    VaultAuthorization authorization,
  ) async {
    final body = await _get(
      '/v1/vault/$vaultId/pending-mutations',
      authorization: authorization,
    );
    final list = body['mutations'];
    if (list is! List) return const [];
    return [for (final m in list) Map<String, dynamic>.from(m as Map)];
  }

  /// `POST /v1/pairing/{session_id}` (new device).
  Future<Map<String, dynamic>> createPairing(
    String sessionId,
    Map<String, dynamic> body,
  ) =>
      _post('/v1/pairing/${Uri.encodeComponent(sessionId)}', body);

  /// `GET /v1/pairing/{session_id}`. Only the new device passes
  /// [retrieverDeviceId]; its first read of a responded session consumes it.
  Future<Map<String, dynamic>> getPairing(
    String sessionId, {
    String? retrieverDeviceId,
  }) =>
      _get(
        '/v1/pairing/${Uri.encodeComponent(sessionId)}'
        '${retrieverDeviceId == null ? '' : '?retriever_device_id=${Uri.encodeQueryComponent(retrieverDeviceId)}'}',
      );

  /// `PUT /v1/pairing/{session_id}/response` (approving device).
  Future<Map<String, dynamic>> respondPairing(
    String sessionId,
    Map<String, dynamic> body,
  ) =>
      _send(() => _dio.put<Object?>(
            '$_base/v1/pairing/${Uri.encodeComponent(sessionId)}/response',
            data: body,
            options: _options(null),
          ));

  /// `POST /v1/vault/open` with a `vault_open` grant and an MSK proof built
  /// by the pubkey SDK.
  Future<Map<String, dynamic>> openVault({
    required String identityId,
    required String vaultId,
    required String otpGrant,
    required Map<String, dynamic> msk,
    required Map<String, dynamic> mskProof,
  }) =>
      _post('/v1/vault/open', {
        'identity_id': identityId,
        'vault_id': vaultId,
        'otp_grant': otpGrant,
        'msk': msk,
        'msk_proof': mskProof,
      });

  /// `POST /v1/vault/{vault_id}/msk` with a `replace_msk` vault grant.
  Future<Map<String, dynamic>> rebindMsk({
    required String identityId,
    required String vaultId,
    required String otpGrant,
    required Map<String, dynamic> msk,
    required Map<String, dynamic> mskProof,
  }) =>
      _post('/v1/vault/$vaultId/msk', {
        'identity_id': identityId,
        'otp_grant': otpGrant,
        'msk': msk,
        'msk_proof': mskProof,
      });

  Future<Map<String, dynamic>> _get(
    String path, {
    VaultAuthorization? authorization,
  }) =>
      _send(() => _dio.get<Object?>(
            '$_base$path',
            options: _options(authorization),
          ));

  Future<Map<String, dynamic>> _post(
    String path,
    Map<String, dynamic> body, {
    VaultAuthorization? authorization,
  }) =>
      _send(() => _dio.post<Object?>(
            '$_base$path',
            data: body,
            options: _options(authorization),
          ));

  Options _options(VaultAuthorization? authorization) => Options(
        responseType: ResponseType.json,
        contentType: Headers.jsonContentType,
        headers: {
          if (authorization != null) 'Authorization': authorization.header,
        },
      );

  Future<Map<String, dynamic>> _send(
    Future<Response<Object?>> Function() call,
  ) async {
    try {
      return _json((await call()).data);
    } on DioException catch (e) {
      final res = e.response;
      if (res == null) {
        throw VaultClientException('network_error', e.message);
      }
      final body = res.data is Map ? res.data as Map : const {};
      final error = body['error'] is Map ? body['error'] as Map : body;
      final details = error['details'];
      throw VaultClientException(
        '${error['code'] ?? 'http_${res.statusCode}'}',
        error['message'] as String?,
        res.statusCode,
        details is Map ? Map<String, dynamic>.from(details) : null,
      );
    }
  }
}

Map<String, dynamic> _json(Object? data) {
  final value = data is String ? jsonDecode(data) : data;
  if (value is Map) return Map<String, dynamic>.from(value);
  throw VaultClientException('bad_response', 'expected a JSON object');
}

String _b64(List<int> b) => base64Url.encode(b).replaceAll('=', '');

Uint8List _bytes(Map body, String field, int length) {
  final v = body[field];
  if (v is String) {
    try {
      final b = base64Url.decode(base64Url.normalize(v));
      if (b.length == length) return b;
    } on FormatException {
      // fall through
    }
  }
  throw VaultClientException('bad_response', '$field must be $length bytes');
}
