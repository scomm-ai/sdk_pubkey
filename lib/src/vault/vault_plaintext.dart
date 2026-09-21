import '../canonical.dart';
import '../constants.dart';
import 'vault.dart';

// CKVF VaultPlaintext structure. Converts between the
// internal [VaultEntry] list (kept as-is — every existing lookup/merge/sync
// path in [Vault] depends on it) and the spec's typed openpgp_keys/
// smime_keys/signing_keys arrays on export/import.
//
// Fields beyond what the spec lists (fingerprint, locator, locators,
// algorithm) are carried alongside the spec-required fields so existing
// app functionality (fingerprint-based lookup, locator display, addKey's
// duplicate-fingerprint check) survives an export/import round trip — the
// spec does not forbid extra fields on these entries.
//
// Entries that don't fit any of the three arrays (legacy `family == pq`)
// are preserved in `legacy_entries`. PQC keys under family pgp or smime
// serialize into openpgp_keys / smime_keys.

/// Internal status vocabulary ('retired') vs. spec vocabulary ('historical')
/// for the same concept: a previously-active key kept for decrypt-only.
/// Only the serialized form differs — [VaultEntry.status] keeps using
/// 'retired' everywhere internally (unchanged behavior).
String statusToSpec(String status) => status == 'retired' ? 'historical' : status;

String statusFromSpec(String status) => status == 'historical' ? 'retired' : status;

String _idOf(VaultEntry e) => e.keyId?.toString() ?? e.fingerprint ?? e.locator ?? '';

Map<String, dynamic> _openPgpKeyToJson(VaultEntry e) => {
      'key_id': _idOf(e),
      'type': e.purpose == Purposes.signing ? 'signing' : 'encryption',
      'status': statusToSpec(e.status),
      if (e.createdAt != null) 'created_at': e.createdAt,
      if (e.privateMaterial != null)
        'private_key': encodeBase64Url(e.privateMaterial!),
      if (e.fingerprint != null) 'fingerprint': e.fingerprint,
      if (e.locator != null) 'locator': e.locator,
      if (e.locators != null) 'locators': e.locators,
      if (e.algorithm != null) 'algorithm': e.algorithm,
    };

VaultEntry _openPgpKeyFromJson(Map<String, dynamic> json) {
  final locatorsRaw = json['locators'];
  final priv = json['private_key'];
  return VaultEntry(
    kind: 'content',
    keyId: int.tryParse('${json['key_id']}'),
    family: Families.pgp,
    purpose: json['type'] == 'signing' ? Purposes.signing : Purposes.encryption,
    algorithm: json['algorithm'] as String?,
    fingerprint: json['fingerprint'] as String?,
    locator: json['locator'] as String?,
    locators:
        locatorsRaw is List ? locatorsRaw.map((e) => e.toString()).toList() : null,
    privateMaterial: priv is String ? decodeBase64Url(priv) : null,
    status: statusFromSpec(json['status'] as String? ?? 'active'),
    createdAt: json['created_at'] as int?,
  );
}

Map<String, dynamic> _smimeKeyToJson(VaultEntry e) => {
      'cert_id': _idOf(e),
      'status': statusToSpec(e.status),
      if (e.createdAt != null) 'created_at': e.createdAt,
      if (e.privateMaterial != null)
        'private_key': encodeBase64Url(e.privateMaterial!),
      if (e.certificate != null) 'certificate': encodeBase64Url(e.certificate!),
      if (e.fingerprint != null) 'fingerprint': e.fingerprint,
      if (e.locator != null) 'locator': e.locator,
      if (e.locators != null) 'locators': e.locators,
      if (e.algorithm != null) 'algorithm': e.algorithm,
    };

VaultEntry _smimeKeyFromJson(Map<String, dynamic> json) {
  final locatorsRaw = json['locators'];
  final priv = json['private_key'];
  final cert = json['certificate'];
  return VaultEntry(
    kind: 'content',
    keyId: int.tryParse('${json['cert_id']}'),
    family: Families.smime,
    purpose: Purposes.encryption,
    algorithm: json['algorithm'] as String?,
    fingerprint: json['fingerprint'] as String?,
    locator: json['locator'] as String?,
    locators:
        locatorsRaw is List ? locatorsRaw.map((e) => e.toString()).toList() : null,
    privateMaterial: priv is String ? decodeBase64Url(priv) : null,
    certificate: cert is String ? decodeBase64Url(cert) : null,
    status: statusFromSpec(json['status'] as String? ?? 'active'),
    createdAt: json['created_at'] as int?,
  );
}

Map<String, dynamic> _signingKeyToJson(VaultEntry e) => {
      'key_id': _idOf(e),
      if (e.purpose != null) 'purpose': e.purpose,
      'status': statusToSpec(e.status),
      if (e.privateMaterial != null)
        'private_key': encodeBase64Url(e.privateMaterial!),
      if (e.createdAt != null) 'created_at': e.createdAt,
      if (e.fingerprint != null) 'fingerprint': e.fingerprint,
      if (e.locator != null) 'locator': e.locator,
      if (e.algorithm != null) 'algorithm': e.algorithm,
    };

VaultEntry _signingKeyFromJson(Map<String, dynamic> json) {
  final priv = json['private_key'];
  return VaultEntry(
    kind: 'content',
    keyId: int.tryParse('${json['key_id']}'),
    family: null,
    purpose: json['purpose'] as String?,
    algorithm: json['algorithm'] as String?,
    fingerprint: json['fingerprint'] as String?,
    locator: json['locator'] as String?,
    privateMaterial: priv is String ? decodeBase64Url(priv) : null,
    status: statusFromSpec(json['status'] as String? ?? 'active'),
    createdAt: json['created_at'] as int?,
  );
}

/// Splits [entries] into the CKVF-spec-shaped arrays plus a `legacy_entries`
/// bucket for anything that doesn't map to one of the three (the plaintext
/// schema only defines openpgp/smime/generic-signing keys).
Map<String, List<Map<String, dynamic>>> vaultEntriesToPlaintextArrays(
  List<VaultEntry> entries,
) {
  final openPgpKeys = <Map<String, dynamic>>[];
  final smimeKeys = <Map<String, dynamic>>[];
  final signingKeys = <Map<String, dynamic>>[];
  final legacyEntries = <Map<String, dynamic>>[];
  for (final entry in entries) {
    if (entry.family == Families.pgp) {
      openPgpKeys.add(_openPgpKeyToJson(entry));
    } else if (entry.family == Families.smime) {
      smimeKeys.add(_smimeKeyToJson(entry));
    } else if (entry.family == null && entry.kind == 'content') {
      signingKeys.add(_signingKeyToJson(entry));
    } else {
      // Not one of the three spec arrays, but still uses the spec's status
      // vocabulary for consistency with the rest of this document.
      final json = entry.toPlaintextJson();
      json['status'] = statusToSpec(entry.status);
      legacyEntries.add(json);
    }
  }
  return {
    'openpgp_keys': openPgpKeys,
    'smime_keys': smimeKeys,
    'signing_keys': signingKeys,
    'legacy_entries': legacyEntries,
  };
}

/// Reassembles the internal [VaultEntry] list from the CKVF-spec-shaped
/// plaintext arrays (the inverse of [vaultEntriesToPlaintextArrays]).
List<VaultEntry> vaultEntriesFromPlaintextArrays(Map<String, dynamic> plaintext) {
  final entries = <VaultEntry>[];
  final openPgpKeys = plaintext['openpgp_keys'];
  if (openPgpKeys is List) {
    for (final item in openPgpKeys) {
      if (item is Map) entries.add(_openPgpKeyFromJson(Map<String, dynamic>.from(item)));
    }
  }
  final smimeKeys = plaintext['smime_keys'];
  if (smimeKeys is List) {
    for (final item in smimeKeys) {
      if (item is Map) entries.add(_smimeKeyFromJson(Map<String, dynamic>.from(item)));
    }
  }
  final signingKeys = plaintext['signing_keys'];
  if (signingKeys is List) {
    for (final item in signingKeys) {
      if (item is Map) entries.add(_signingKeyFromJson(Map<String, dynamic>.from(item)));
    }
  }
  final legacyEntries = plaintext['legacy_entries'];
  if (legacyEntries is List) {
    for (final item in legacyEntries) {
      if (item is Map && item['kind'] != 'msk') {
        final map = Map<String, dynamic>.from(item);
        final status = map['status'];
        if (status is String) map['status'] = statusFromSpec(status);
        entries.add(VaultEntry.fromJson(map));
      }
    }
  }
  return entries;
}

/// A registered device inside `metadata.devices`. Structural
/// field only for now — device pairing is what will populate
/// and consume this; today it always round-trips empty.
class DeviceMetadata {
  const DeviceMetadata({
    required this.deviceId,
    required this.name,
    required this.tier,
    required this.addedAt,
    required this.addedBy,
  });

  final String deviceId;
  final String name;

  /// `"full"` or `"limited"`.
  final String tier;
  final int addedAt;
  final String addedBy;

  factory DeviceMetadata.fromJson(Map<String, dynamic> json) => DeviceMetadata(
        deviceId: json['device_id'] as String? ?? '',
        name: json['name'] as String? ?? '',
        tier: json['tier'] as String? ?? 'limited',
        addedAt: json['added_at'] as int? ?? 0,
        addedBy: json['added_by'] as String? ?? '',
      );

  Map<String, dynamic> toJson() => {
        'device_id': deviceId,
        'name': name,
        'tier': tier,
        'added_at': addedAt,
        'added_by': addedBy,
      };
}
