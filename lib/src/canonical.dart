import 'dart:convert';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart' as ckvf;

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

/// Delegates to `package:ckvf`'s base64url codec instead of duplicating it.
String encodeBase64Url(List<int> bytes) => ckvf.bytesToBase64url(bytes);

/// Historically this function has tolerated the standard base64 alphabet
/// (`+`/`/`) and padding (`=`) in addition to url-safe unpadded input —
/// [encodeBase64Url] itself never produces either, but some callers pass
/// through externally-sourced strings, so both are normalized away before
/// delegating to `ckvf`'s stricter, spec-conformant decoder (which rejects
/// them outright). [FormatException] preserves this package's prior
/// exception contract, where `ckvf` reports malformed input as
/// `CkvfException`.
Uint8List decodeBase64Url(String value) {
  final normalized =
      value.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  try {
    return ckvf.base64urlToBytes(normalized);
  } on ckvf.CkvfException catch (e) {
    throw FormatException(e.message ?? e.code, value);
  }
}
