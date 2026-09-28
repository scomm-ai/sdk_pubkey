import 'dart:convert';
import 'dart:typed_data';

import 'constants.dart';
import 'identity.dart';
import 'jcs.dart';

/// Canonical bytes that an MSK Ed25519 signature covers.
///
///   SComm/Pubkey/{protocol_version}/{operation}\n
///   principal={uuid-v8}\n
///   timestamp={unix_ms}\n
///   nonce={base64url}\n
///   payload_sha256={hex}\n
String domainSeparator(int version, String operation) =>
    '$protocolName/$version/$operation';

String payloadSha256Hex(Object? payload) {
  final jcs = canonicalizeJson(payload ?? const <String, Object?>{});
  return bytesToHex(sha256Bytes(jcs));
}

String canonicalSignedUtf8({
  required int protocolVersion,
  required String operation,
  required String principal,
  required int timestamp,
  required String nonce,
  Object? payload,
}) {
  final payloadHash = payloadSha256Hex(payload);
  return '${domainSeparator(protocolVersion, operation)}\n'
      'principal=$principal\n'
      'timestamp=$timestamp\n'
      'nonce=$nonce\n'
      'payload_sha256=$payloadHash\n';
}

Uint8List canonicalSignedBytes({
  required int protocolVersion,
  required String operation,
  required String principal,
  required int timestamp,
  required String nonce,
  Object? payload,
}) {
  return Uint8List.fromList(
    utf8.encode(
      canonicalSignedUtf8(
        protocolVersion: protocolVersion,
        operation: operation,
        principal: principal,
        timestamp: timestamp,
        nonce: nonce,
        payload: payload,
      ),
    ),
  );
}

/// `msk_signature = Sign(MSK_private, canonical(identity_id,
/// generation, ciphertext_hash, previous_generation_hash, timestamp,
/// nonce))`. Independent of [canonicalSignedUtf8] (the generic mutation
/// envelope signature) — this covers only the VaultRecord's own fields, so
/// any future downloading device can re-verify it from the stored record
/// alone, without needing the original upload request's envelope.
const String vaultRecordOperation = 'vault_record';

String canonicalVaultRecordUtf8({
  required int protocolVersion,
  required String identityId,
  required int generation,
  required List<int> ciphertextHash,
  required List<int>? previousGenerationHash,
  required int timestamp,
  required List<int> nonce,
}) {
  return '${domainSeparator(protocolVersion, vaultRecordOperation)}\n'
      'identity=$identityId\n'
      'generation=$generation\n'
      'ciphertext_hash=${bytesToHex(ciphertextHash)}\n'
      'previous_generation_hash=${previousGenerationHash == null ? 'none' : bytesToHex(previousGenerationHash)}\n'
      'timestamp=$timestamp\n'
      'nonce=${encodeBase64Url(nonce)}\n';
}

Uint8List canonicalVaultRecordBytes({
  required int protocolVersion,
  required String identityId,
  required int generation,
  required List<int> ciphertextHash,
  required List<int>? previousGenerationHash,
  required int timestamp,
  required List<int> nonce,
}) {
  return Uint8List.fromList(
    utf8.encode(
      canonicalVaultRecordUtf8(
        protocolVersion: protocolVersion,
        identityId: identityId,
        generation: generation,
        ciphertextHash: ciphertextHash,
        previousGenerationHash: previousGenerationHash,
        timestamp: timestamp,
        nonce: nonce,
      ),
    ),
  );
}

/// Unpadded base64url.
String encodeBase64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

/// Tolerates the standard base64 alphabet (`+`/`/`) and padding (`=`).
Uint8List decodeBase64Url(String value) {
  var normalized =
      value.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  final pad = (4 - normalized.length % 4) % 4;
  normalized = normalized.padRight(normalized.length + pad, '=');
  try {
    return Uint8List.fromList(base64Url.decode(normalized));
  } on FormatException {
    rethrow;
  }
}
