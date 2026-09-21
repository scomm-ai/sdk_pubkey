import 'dart:convert';
import 'dart:typed_data';

import '../canonical.dart';
import '../constants.dart';
import '../crypto/provider.dart';
import '../errors.dart';
import '../locator.dart';
import 'key_hierarchy.dart';
import 'store.dart';
import 'vault_plaintext.dart';

export 'vault_plaintext.dart' show DeviceMetadata;

class VaultEntry {
  VaultEntry({
    required this.kind,
    this.keyId,
    this.family,
    this.purpose,
    this.algorithm,
    this.fingerprint,
    this.locator,
    this.locators,
    this.privateMaterial,
    this.status = 'active',
    this.createdAt,
    this.certificate,
  });

  final String kind;

  /// The server's own id for this key's published artifact — `null` until it
  /// has one (an encryption key is deliberately not published at generation
  /// time, so it sits in the vault unpublished until the user promotes it).
  /// Mutable so [Vault.addKey] can back-fill it when the key is later
  /// published; see that method.
  int? keyId;
  final String? family;
  final String? purpose;
  final String? algorithm;
  final String? fingerprint;
  String? locator;
  List<String>? locators;
  final Uint8List? privateMaterial;
  String status;

  /// Epoch milliseconds. The vault schema requires `created_at` on every
  /// openpgp/smime/signing key entry; entries created before this field
  /// existed may have it as `null`. Set by [Vault.addKey] when absent.
  int? createdAt;

  /// The X.509 certificate bytes (S/MIME only — `smime_keys`).
  final Uint8List? certificate;

  factory VaultEntry.fromJson(Map<String, dynamic> json) {
    final raw = json['private_material'];
    final locatorsRaw = json['locators'];
    final certRaw = json['certificate'];
    return VaultEntry(
      kind: json['kind'] as String,
      keyId: json['key_id'] is int
          ? json['key_id'] as int
          : int.tryParse('${json['key_id']}'),
      family: json['family'] as String?,
      purpose: json['purpose'] as String?,
      algorithm: json['algorithm'] as String?,
      fingerprint: json['fingerprint'] as String?,
      locator: json['locator'] as String?,
      locators: locatorsRaw is List
          ? locatorsRaw.map((e) => e.toString()).toList()
          : null,
      privateMaterial: raw is String
          ? decodeBase64Url(raw)
          : raw is List
              ? Uint8List.fromList(List<int>.from(raw))
              : null,
      status: json['status'] as String? ?? 'active',
      createdAt: json['created_at'] as int?,
      certificate: certRaw is String ? decodeBase64Url(certRaw) : null,
    );
  }

  VaultEntry clone() => VaultEntry(
        kind: kind,
        keyId: keyId,
        family: family,
        purpose: purpose,
        algorithm: algorithm,
        fingerprint: fingerprint,
        locator: locator,
        locators: locators == null ? null : List<String>.from(locators!),
        privateMaterial: privateMaterial == null
            ? null
            : Uint8List.fromList(privateMaterial!),
        status: status,
        createdAt: createdAt,
        certificate:
            certificate == null ? null : Uint8List.fromList(certificate!),
      );

  Map<String, dynamic> toPlaintextJson() {
    return {
      'kind': kind,
      if (keyId != null) 'key_id': keyId,
      if (family != null) 'family': family,
      if (purpose != null) 'purpose': purpose,
      if (algorithm != null) 'algorithm': algorithm,
      if (fingerprint != null) 'fingerprint': fingerprint,
      if (locator != null) 'locator': locator,
      if (locators != null) 'locators': locators,
      if (privateMaterial != null)
        'private_material': encodeBase64Url(privateMaterial!),
      'status': status,
      if (createdAt != null) 'created_at': createdAt,
      if (certificate != null) 'certificate': encodeBase64Url(certificate!),
    };
  }

  Map<String, dynamic> toPublicJson() {
    return {
      'kind': kind,
      if (keyId != null) 'key_id': keyId,
      if (family != null) 'family': family,
      if (purpose != null) 'purpose': purpose,
      if (algorithm != null) 'algorithm': algorithm,
      if (fingerprint != null) 'fingerprint': fingerprint,
      if (locator != null) 'locator': locator,
      if (locators != null) 'locators': locators,
      'status': status,
      if (createdAt != null) 'created_at': createdAt,
    };
  }
}

String _fingerprintOf(VaultEntry entry) => entry.fingerprint ?? '';

/// Low 64 bits of an OpenPGP fingerprint — the key id.
const int _openPgpKeyIdHexLen = 16;

/// Whether two fingerprints name the same key.
///
/// Clients disagree on how much of it to keep: this one stores only the key
/// id (the low 64 bits — see `_normalizeOpenPgpFingerprint` in the host app),
/// the Office add-in stores the full v4 fingerprint. Same key, written two
/// ways. Comparing them as exact strings let both spellings into the vault as
/// separate entries, so one key showed up twice on every client that read it
/// back.
///
/// So: equal after stripping separators and case, or one is a suffix of the
/// other and the shorter is a full key id. Anything shorter is too weak to
/// identify a key and only matches exactly. Non-hex fingerprints (S/MIME
/// digests, test fixtures) normalize to empty and fall back to that exact
/// match, unchanged.
bool _sameFingerprint(String a, String b) {
  if (a == b) return true;
  final left = normalizeHex(a);
  final right = normalizeHex(b);
  final shorter = left.length <= right.length ? left : right;
  // Below a full key id there is not enough here to identify a key, and
  // stripping non-hex characters out of two unrelated labels can easily
  // leave the same few digits behind. Exact string equality only.
  if (shorter.length < _openPgpKeyIdHexLen) return false;
  final longer = identical(shorter, left) ? right : left;
  return longer.endsWith(shorter);
}

bool _samePrivate(VaultEntry a, VaultEntry b) {
  if (a.privateMaterial == null || b.privateMaterial == null) {
    return _fingerprintOf(a) == _fingerprintOf(b);
  }
  if (a.privateMaterial!.length != b.privateMaterial!.length) {
    return false;
  }
  for (var i = 0; i < a.privateMaterial!.length; i++) {
    if (a.privateMaterial![i] != b.privateMaterial![i]) {
      return false;
    }
  }
  return true;
}

VaultEntry _coerceEntry(Object entry) {
  if (entry is VaultEntry) {
    return entry;
  }
  if (entry is Map) {
    return VaultEntry.fromJson(Map<String, dynamic>.from(entry));
  }
  throw ArgumentError('Vault entry must be a VaultEntry or Map');
}

/// Client-side SComm Vault. Never talks to the pubkey HTTP API.
class Vault {
  Vault({
    required this.crypto,
    VaultStore? store,
    this.principal,
  }) : store = store ?? MemoryVaultStore();

  final CryptoProvider crypto;
  final VaultStore store;
  String? principal;
  bool unlocked = false;
  int createdAt = _nowMs();
  int updatedAt = _nowMs();
  List<VaultEntry> entries = [];
  Map<String, dynamic>? mskEnvelope;

  /// SHA-256 of the vault ciphertext this device last knew the server to
  /// have (from a download or a successful upload) — the
  /// `previous_generation_hash` for this device's next upload. `null` means
  /// no generation is known yet (genesis). Not part of [VaultPlaintext]
  /// (the plaintext schema has no such field) — it's local sync-tracking state,
  /// persisted outside the encrypted blob since it needs no confidentiality.
  Uint8List? lastCiphertextHash;

  /// The vault's `generation` — an immutable, versioned vault snapshot
  /// counter. `0` means no generation has been established yet (genesis
  /// is what first sets this to `1`); incrementing it on mutation
  /// is not implemented here.
  int generation = 0;

  /// The vault's `current_signing_key_id` — set only via a normal vault
  /// mutation, not implemented here.
  String? currentSigningKeyId;

  /// The "active encryption key for advertising to new senders"
  /// canonical pointer. Not literally named in the plaintext schema, but
  /// implied by "which key is advertised" language — added the same
  /// way spec-implied-but-unspecified fields were filled in. Mirrors
  /// [currentSigningKeyId]'s field/parse/serialize pattern exactly. This is
  /// the vault's own cross-device record of *intent* — flipping it does
  /// **not** by itself make `GET /v1/keys` return the key; that still
  /// requires the separate, unchanged legacy `set_encryption_key` publish
  /// call (see `PubkeyRuntime`/`KeyManagerController` at the app layer).
  /// Never auto-set on key creation ("do not promote a newly
  /// generated key... the instant it's created") — only via an explicit,
  /// user-confirmed promotion.
  String? currentEncryptionKeyId;

  /// The vault's `metadata.devices`. Structural only for now — device pairing
  /// populates/consumes this; `authorized_devices` remains
  /// the server-side source of truth until that step reconciles the two.
  List<DeviceMetadata> devices = [];

  static int _nowMs() => DateTime.now().millisecondsSinceEpoch;

  Future<Vault> createVault(String principal) async {
    this.principal = principal;
    entries = [];
    mskEnvelope = null;
    generation = 0;
    currentSigningKeyId = null;
    currentEncryptionKeyId = null;
    devices = [];
    lastCiphertextHash = null;
    createdAt = _nowMs();
    updatedAt = createdAt;
    unlocked = true;
    return this;
  }

  /// Parses a decrypted [VaultPlaintext] JSON blob into this Vault's fields.
  /// Reads a canonical key pointer (`current_signing_key_id` /
  /// `current_encryption_key_id`) out of vault plaintext.
  ///
  /// This vault document is shared with other clients, so the field cannot
  /// be hard-cast: the Office add-in wrote these as JSON *numbers* for a
  /// while, and `as String?` on a number throws a raw `TypeError` — not a
  /// [PubkeyException] — out of the middle of [_applyPlaintextBytes], which
  /// left the vault empty and locked with no usable error. Generations are
  /// immutable and never deleted, so such a generation stays current: this
  /// device could then neither read the vault nor upload a replacement.
  /// Accepting either spelling (and normalizing to the string form this
  /// class writes) is what gets those identities unstuck.
  static String? _keyIdPointer(Object? value) {
    if (value == null) return null;
    if (value is String) return value.isEmpty ? null : value;
    if (value is int) return value.toString();
    return null;
  }

  /// Shared by [unlockVault] (local cache) and [applyDownloadedGeneration]
  /// (freshly fetched from the server) — the plaintext shape is identical
  /// either way, only where the ciphertext came from differs.
  void _applyPlaintextBytes(Uint8List plaintext) {
    final parsed = jsonDecode(utf8.decode(plaintext));
    if (parsed is! Map) {
      throw PubkeyException(ErrorCodes.vaultCorrupt, 'Invalid vault plaintext');
    }
    if (parsed['vault_format_version'] != vaultFormatVersion) {
      throw PubkeyException(
        ErrorCodes.protocolVersionMismatch,
        'Unsupported vault format ${parsed['vault_format_version']}',
      );
    }
    principal = parsed['principal'] as String?;
    createdAt = parsed['created_at'] as int? ?? _nowMs();
    updatedAt = parsed['updated_at'] as int? ?? createdAt;
    generation = parsed['generation'] as int? ?? 0;
    currentSigningKeyId = _keyIdPointer(parsed['current_signing_key_id']);
    currentEncryptionKeyId = _keyIdPointer(parsed['current_encryption_key_id']);
    entries = vaultEntriesFromPlaintextArrays(Map<String, dynamic>.from(parsed));
    final metadata = parsed['metadata'];
    final rawDevices = metadata is Map ? metadata['devices'] : null;
    devices = [
      if (rawDevices is List)
        for (final item in rawDevices)
          if (item is Map) DeviceMetadata.fromJson(Map<String, dynamic>.from(item)),
    ];
    final envelope = parsed['msk_envelope'];
    mskEnvelope = envelope is Map
        ? Map<String, dynamic>.from(envelope)
        : null;
  }

  /// Unlocks the vault using the raw VEK (256-bit CSPRNG —
  /// never a human-memorized passphrase; see [WrappedKey] and
  /// [KeyHierarchy.decryptVaultCiphertextWithVek]).
  Future<Vault> unlockVault(Uint8List vek) async {
    final record = await store.load();
    if (record == null) {
      throw PubkeyException(ErrorCodes.vaultCorrupt, 'No vault in store');
    }
    final encryption = record['encryption'] as Map;
    Uint8List plaintext;
    try {
      plaintext = await KeyHierarchy.decryptVaultCiphertextWithVek(
        crypto,
        vek,
        WrappedKey(
          iv: decodeBase64Url(encryption['iv'] as String),
          ciphertext: decodeBase64Url(record['ciphertext'] as String),
        ),
      );
    } on PubkeyException catch (e) {
      if (e.code == ErrorCodes.envelopeAuthenticationFailure) {
        throw PubkeyException(
          ErrorCodes.vaultAuthenticationFailure,
          'Vault authentication failed',
        );
      }
      rethrow;
    }
    _applyPlaintextBytes(plaintext);
    final rawHash = record['last_ciphertext_hash'];
    lastCiphertextHash = rawHash is String ? decodeBase64Url(rawHash) : null;
    unlocked = true;
    return this;
  }

  /// Applies a freshly downloaded generation — the server's
  /// latest [VaultRecord] ciphertext/iv, already integrity- and
  /// signature-verified by the caller (that verification needs the
  /// principal's MSK public key and canonical bytes, which live at the
  /// [PubkeyClient] layer, not here). Updates [lastCiphertextHash] to this
  /// generation's hash and replaces this Vault's in-memory state — callers
  /// must call [persist] afterward to update the local cache.
  Future<void> applyDownloadedGeneration({
    required Uint8List vek,
    required Uint8List iv,
    required Uint8List ciphertext,
    required Uint8List ciphertextHash,
  }) async {
    final plaintext = await KeyHierarchy.decryptVaultCiphertextWithVek(
      crypto,
      vek,
      WrappedKey(iv: iv, ciphertext: ciphertext),
    );
    _applyPlaintextBytes(plaintext);
    lastCiphertextHash = ciphertextHash;
    unlocked = true;
  }

  void lockVault() {
    unlocked = false;
    entries = [];
  }

  void _requireUnlocked() {
    if (!unlocked) {
      throw PubkeyException(ErrorCodes.vaultLocked, 'Vault is locked');
    }
  }

  List<Map<String, dynamic>> listKeys() {
    _requireUnlocked();
    return entries.map((entry) => entry.toPublicJson()).toList();
  }

  VaultEntry? getKey(int? keyId) {
    _requireUnlocked();
    for (final entry in entries) {
      if (entry.keyId == keyId) {
        return entry;
      }
    }
    return null;
  }

  VaultEntry? getKeyByFingerprint(String fingerprint) {
    _requireUnlocked();
    for (final entry in entries) {
      if (_fingerprintOf(entry) == fingerprint) return entry;
    }
    return null;
  }

  /// [getKeyByFingerprint] by key identity rather than by string: finds the
  /// entry whichever client wrote it and whichever spelling it used. See
  /// [_sameFingerprint].
  VaultEntry? findKeyByFingerprint(String fingerprint) {
    _requireUnlocked();
    final exact = getKeyByFingerprint(fingerprint);
    if (exact != null) return exact;
    for (final entry in entries) {
      if (_sameFingerprint(_fingerprintOf(entry), fingerprint)) return entry;
    }
    return null;
  }

  List<VaultEntry> getKeysByLocator(String locator) {
    _requireUnlocked();
    return [
      for (final entry in entries)
        if (entry.locator == locator ||
            (entry.locators?.contains(locator) ?? false))
          entry,
    ];
  }

  VaultEntry? getCurrentKey([String? purpose]) {
    _requireUnlocked();
    final active = entries.where(
      (entry) =>
          entry.kind == 'content' &&
          entry.status == 'active' &&
          (purpose == null || entry.purpose == purpose),
    );
    if (active.isEmpty) {
      return null;
    }
    return active.reduce(
      (best, entry) => (entry.keyId ?? 0) > (best.keyId ?? 0) ? entry : best,
    );
  }

  VaultEntry? getHistoricalKey(int? keyId) => getKey(keyId);

  /// `encrypted_msk_private_key = AEAD_Encrypt(AEK, msk_private_key_bytes)`.
  /// The MSK private key never sits in [mskEnvelope] in raw
  /// form — only this AEK-wrapped ciphertext, which the outer VEK wrap then
  /// covers again. A device holding only VEK (no AEK) cannot reverse this
  /// step (Boundary B4).
  Future<void> setMsk({
    required Uint8List aek,
    required PortablePrivateKey msk,
  }) async {
    _requireUnlocked();
    final wrapped = await KeyHierarchy.wrapMskWithAek(crypto, aek, msk.bytes);
    mskEnvelope = {
      'envelope_version': mskEnvelopeVersion,
      'algorithm': msk.algorithm,
      'public_key':
          msk.publicKey == null ? null : encodeBase64Url(msk.publicKey!),
      'created_at': _nowMs(),
      'iv': encodeBase64Url(wrapped.iv),
      'encrypted_msk': encodeBase64Url(wrapped.ciphertext),
    };
    updatedAt = _nowMs();
  }

  /// Recovers the MSK private key bytes from [mskEnvelope]. Requires AEK —
  /// there is no code path that accepts VEK here (Boundary B4).
  Future<Uint8List> unwrapMsk(Uint8List aek) async {
    _requireUnlocked();
    final envelope = mskEnvelope;
    if (envelope == null) {
      throw PubkeyException(
        ErrorCodes.mskEnvelopeMissing,
        'Vault has no MSK envelope',
      );
    }
    final iv = envelope['iv'];
    final encryptedMsk = envelope['encrypted_msk'];
    if (iv is! String || encryptedMsk is! String) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'MSK envelope is missing iv/encrypted_msk',
      );
    }
    try {
      return await KeyHierarchy.unwrapMskWithAek(
        crypto,
        aek,
        WrappedKey(iv: decodeBase64Url(iv), ciphertext: decodeBase64Url(encryptedMsk)),
      );
    } on PubkeyException catch (e) {
      if (e.code == ErrorCodes.envelopeAuthenticationFailure) {
        throw PubkeyException(
          ErrorCodes.deviceNotAuthorized,
          'This device does not hold authority (AEK) for this identity',
        );
      }
      rethrow;
    }
  }

  VaultEntry addKey(Object entry) {
    _requireUnlocked();
    final incoming = _coerceEntry(entry).clone();
    if (incoming.kind == 'msk') {
      throw PubkeyException(
        ErrorCodes.vaultIntegrity,
        'MSK must be stored in the MSK envelope, not as an ordinary vault key',
      );
    }
    if (incoming.family != null && incoming.locator != null) {
      incoming.locator = formatLocator(incoming.family, incoming.locator);
    }
    incoming.createdAt ??= _nowMs();
    final fp = _fingerprintOf(incoming);
    if (fp.isNotEmpty) {
      for (final existing in entries) {
        if (!_sameFingerprint(_fingerprintOf(existing), fp)) continue;
        if (!_samePrivate(existing, incoming)) {
          throw PubkeyException(
            ErrorCodes.vaultIntegrity,
            'Vault already has different secret material for this fingerprint',
          );
        }
        // Same material, re-added now that it carries facts the stored copy
        // was missing — fill those in rather than discarding them. `keyId`
        // matters most: an encryption key enters the vault unpublished (no
        // server id), and "Make active" publishes it and re-adds it with the
        // id the server just minted. Dropping that id on the floor left the
        // entry unreachable by [getKey], so the later `retireKey(id)` on
        // delete quietly retired nothing and the next sync found the entry
        // still `active` and resurrected the key.
        //
        // `??=`, never overwrite: a *different* id for material already
        // carrying one is a genuine conflict, not new information.
        existing.keyId ??= incoming.keyId;
        existing.locator ??= incoming.locator;
        existing.locators ??= incoming.locators;
        return existing;
      }
    }
    entries.add(incoming);
    updatedAt = _nowMs();
    return incoming;
  }

  /// The single way an entry leaves `'active'`: sets [status] and drops
  /// [currentSigningKeyId]/[currentEncryptionKeyId] if either still names
  /// [entry]. Never deletes the entry — retired/revoked material is kept so
  /// anything it previously protected stays decryptable.
  ///
  /// Those pointers mean "the key this identity advertises *now*", so they
  /// are only meaningful while their target is active —
  /// [PubkeyRuntime.promoteEncryptionKeyPointer]/`rotateSigningKey` both
  /// refuse to point at anything else. Leaving one dangling past its
  /// target's retirement made the key detail screen keep claiming "new
  /// senders currently see this key" about a key whose server-side artifact
  /// had just been retired, so nobody could discover it any more.
  ///
  /// Clearing, never repointing: choosing a replacement to advertise is an
  /// explicit, user-confirmed promotion (see
  /// [PubkeyRuntime.promoteEncryptionKeyPointer]'s doc comment), so silently
  /// electing one here would advertise a key the user never picked.
  VaultEntry? _terminate(VaultEntry? entry, String status) {
    if (entry == null) return null;
    entry.status = status;
    final id = entry.keyId?.toString();
    if (id != null) {
      if (currentSigningKeyId == id) currentSigningKeyId = null;
      if (currentEncryptionKeyId == id) currentEncryptionKeyId = null;
    }
    updatedAt = _nowMs();
    return entry;
  }

  /// Marks [keyId] `'retired'`.
  VaultEntry? retireKey(int keyId) {
    _requireUnlocked();
    return _terminate(getKey(keyId), 'retired');
  }

  /// [retireKey] for an entry that has no server key id to name it by.
  ///
  /// A locally generated or imported key is in the vault long before it is
  /// ever published — an encryption key is deliberately not published until
  /// the user promotes it — so at delete time there may be no key id to
  /// retire it with, only its fingerprint. Skipping the vault in that case
  /// left the entry `active`, and the next sync re-imported the key the user
  /// had just deleted as a live key.
  VaultEntry? retireKeyByFingerprint(String fingerprint) {
    _requireUnlocked();
    return _terminate(findKeyByFingerprint(fingerprint), 'retired');
  }

  /// CKVF's compromise-response table, "Single
  /// PGP/S-MIME/signing key" row: marks [keyId]'s status
  /// `'revoked'` — a genuinely different terminal state from [retireKey]'s
  /// `'retired'` (spec vocabulary: `'historical'`). A retired/historical key
  /// was superseded through ordinary key hygiene (still fine, just no longer
  /// current); a revoked key is one the identity is actively disclaiming
  /// because its private material may be in a third party's hands — the
  /// plaintext schema lists `'revoked'` as its own status value precisely for
  /// this distinction. Never deletes the entry (needed for historical
  /// decrypt of anything it previously protected), mirrors [retireKey]'s
  /// shape exactly otherwise. `'revoked'` round-trips through
  /// [statusToSpec]/[statusFromSpec] unchanged (neither function
  /// special-cases it — both only ever rewrite `'retired'`/`'historical'`),
  /// so no serialization change was needed for this new value.
  VaultEntry? revokeKey(int keyId) {
    _requireUnlocked();
    return _terminate(getKey(keyId), 'revoked');
  }

  Vault merge(Vault other) {
    _requireUnlocked();
    for (final entry in other.entries) {
      addKey(entry);
    }
    return this;
  }

  /// `VaultCiphertext = AEAD_Encrypt(VEK, Serialize(VaultPlaintext))`.
  /// [vek] is the raw 256-bit CSPRNG Vault Encryption Key —
  /// never a human-memorized passphrase (Boundary B1).
  Future<Map<String, dynamic>> exportVault(Uint8List vek) async {
    _requireUnlocked();
    final arrays = vaultEntriesToPlaintextArrays(entries);
    final plaintext = {
      'vault_format_version': vaultFormatVersion,
      'generation': generation,
      'principal': principal,
      'created_at': createdAt,
      'updated_at': updatedAt,
      'current_signing_key_id': currentSigningKeyId,
      'current_encryption_key_id': currentEncryptionKeyId,
      'msk_envelope': mskEnvelope,
      ...arrays,
      'metadata': {
        'devices': [for (final device in devices) device.toJson()],
      },
    };
    final wrapped = await KeyHierarchy.encryptVaultPlaintextWithVek(
      crypto,
      vek,
      utf8.encode(jsonEncode(plaintext)),
    );
    return {
      'vault_format_version': vaultFormatVersion,
      'wrap_version': vaultWrapVersionV1,
      'encryption': {
        'name': vaultAead,
        'iv': encodeBase64Url(wrapped.iv),
      },
      'ciphertext': encodeBase64Url(wrapped.ciphertext),
      if (lastCiphertextHash != null)
        'last_ciphertext_hash': encodeBase64Url(lastCiphertextHash!),
    };
  }

  Future<Map<String, dynamic>> exportKeyPackage(
    String fingerprint,
    String passphrase,
  ) async {
    _requireUnlocked();
    final entry = getKeyByFingerprint(fingerprint);
    if (entry == null || entry.privateMaterial == null) {
      throw PubkeyException(ErrorCodes.keyNotFound, 'No private key for package');
    }
    final plaintext = {
      'kind': keyPackageKind,
      'package_version': keyPackageVersion,
      'entry': {
        ...entry.toPublicJson(),
        'private_material': encodeBase64Url(entry.privateMaterial!),
      },
    };
    final wrapped = await crypto.wrapVault(
      utf8.encode(jsonEncode(plaintext)),
      passphrase,
      iterations: vaultPbkdf2Iterations,
    );
    return {
      'kind': keyPackageKind,
      'package_version': keyPackageVersion,
      'family': entry.family,
      'locator': entry.locator,
      'fingerprint': entry.fingerprint,
      'kdf': {
        'name': vaultKdf,
        'iterations': wrapped.iterations,
        'salt': encodeBase64Url(wrapped.salt),
      },
      'encryption': {
        'name': vaultAead,
        'iv': encodeBase64Url(wrapped.iv),
      },
      'ciphertext': encodeBase64Url(wrapped.ciphertext),
    };
  }

  Future<VaultEntry> importKeyPackage(
    Map<String, dynamic> exported,
    String passphrase,
  ) async {
    _requireUnlocked();
    final kdf = exported['kdf'] as Map;
    final encryption = exported['encryption'] as Map;
    final plaintext = await crypto.unwrapVault(
      decodeBase64Url(exported['ciphertext'] as String),
      passphrase,
      decodeBase64Url(kdf['salt'] as String),
      decodeBase64Url(encryption['iv'] as String),
      kdf['iterations'] as int,
    );
    final parsed = jsonDecode(utf8.decode(plaintext));
    if (parsed is! Map || parsed['kind'] != keyPackageKind) {
      throw PubkeyException(ErrorCodes.vaultCorrupt, 'Not a key package');
    }
    final entry = Map<String, dynamic>.from(parsed['entry'] as Map);
    return addKey(entry);
  }

  Future<Vault> importVault(
    Map<String, dynamic> exported,
    Uint8List vek,
  ) async {
    final previous = await store.load();
    try {
      await store.save(exported);
      return await unlockVault(vek);
    } catch (err) {
      if (previous != null) await store.save(previous);
      rethrow;
    }
  }

  Future<Map<String, dynamic>> backupVault(Uint8List vek) => exportVault(vek);

  Future<Vault> restoreVault(
    Map<String, dynamic> exported,
    Uint8List vek,
  ) =>
      importVault(exported, vek);

  Future<Map<String, dynamic>> persist(Uint8List vek) async {
    final exported = await exportVault(vek);
    final previous = await store.load();
    try {
      await store.save(exported);
    } catch (_) {
      if (previous != null) await store.save(previous);
      rethrow;
    }
    return exported;
  }
}
