import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';

import '../canonical.dart';
import '../client/pubkey_client.dart';
import '../constants.dart';
import '../crypto/dart_crypto.dart';
import '../crypto/provider.dart';
import '../engines/pgp.dart';
import '../engines/smime.dart';
import '../errors.dart';
import '../identity.dart';
import '../vault/device_pairing.dart';
import '../vault/key_hierarchy.dart';
import '../vault/recovery_code.dart';
import '../vault/store.dart';
import '../vault/vault.dart';
import '../vault/vault_export.dart';

/// Handle for an in-progress pairing attempt initiated by [PubkeyRuntime.
/// beginPairingAsNewDevice] (device B).
///
/// [sessionCode] is the mailbox locator (hex [sessionId]). The CPace
/// password is [pairingPassword] / [pairingUri], never this locator.
/// [completed] resolves once B has
/// successfully retrieved and applied A's envelope, or throws a
/// [PubkeyException] if the session expires first (or on tamper/AEAD
/// failure — never a silent fallback, "Client (B) validates").
class PairingSession {
  const PairingSession({
    required this.sessionCode,
    required this.pairingUri,
    required this.pairingPassword,
    required this.expiresAt,
    required this.completed,
    this.typedPassword,
  });

  final String sessionCode;
  final String pairingUri;
  final Uint8List pairingPassword;
  final String? typedPassword;
  final DateTime expiresAt;
  final Future<void> completed;
}

/// A pending pairing request as seen by the existing device (A), fetched by
/// [PubkeyRuntime.fetchPendingPairingRequest]. The UI
/// shows [deviceName]/[requestedTier] to the user and gates the actual
/// approval on whatever local biometric/PIN convention the host app already
/// uses for sensitive actions.
class PendingPairingRequest {
  const PendingPairingRequest({
    required this.sessionId,
    required this.deviceName,
    required this.requestedTier,
    required this.bDeviceId,
    required this.bPakeElement,
  });

  final String sessionId;
  final String deviceName;
  final String requestedTier;
  final String bDeviceId;
  final Uint8List bPakeElement;
}

/// Result of [PubkeyRuntime.confirmPairingRequest] — the new device was
/// both handed its envelope(s) *and* confirmed (via the COMPLETED poll,
/// an ordering decision) to have actually retrieved them before
/// this device registered it in `metadata.devices`.
class PairingConfirmationResult {
  const PairingConfirmationResult({required this.deviceId, required this.tier});

  final String deviceId;
  final String tier;
}

/// Result of [PubkeyRuntime.recoverWithCode]. [deviceRegistered]
/// mirrors the same full/read-only-tier symmetry [confirmPairingRequest]/
/// [importVaultOffline] already enforce: a read-only-scope recovery code
/// unwraps VEK only, so this device has no AEK to sign a device-add mutation
/// with and stays unregistered — see [PubkeyRuntime.recoverWithCode]'s doc
/// comment for the full reasoning.
class RecoveryWithCodeResult {
  const RecoveryWithCodeResult({required this.deviceRegistered, this.deviceId});

  final bool deviceRegistered;
  final String? deviceId;
}

/// Result of [PubkeyRuntime.reimportHistoricalGeneration] — a summary
/// for the UI to show the user what happened, since the
/// merge itself is silent otherwise.
class HistoricalReimportResult {
  const HistoricalReimportResult({
    required this.recoveredCount,
    required this.mergedCount,
    required this.alreadyPresentCount,
  });

  /// Total entries found in the decrypted old generation.
  final int recoveredCount;

  /// How many of those were newly merged into the current vault as
  /// `status: 'retired'` (spec's `'historical'`) entries.
  final int mergedCount;

  /// How many were already present in the current vault (matched by
  /// fingerprint, [Vault.getKeyByFingerprint]) and therefore left untouched.
  final int alreadyPresentCount;
}

/// Per-account Pubkey + Vault runtime. Reconstructs MSK from the Vault.
///
/// Each mailbox account has its own MSK and its own Vault, so a single
/// process-wide instance would sign one account's requests with another
/// account's key. Instances are cached per normalized email so repeated
/// [instance] calls for the same account reuse the same Vault/MSK state.
class PubkeyRuntime {
  PubkeyRuntime._({
    required this.accountEmail,
    required this.crypto,
    required this.vault,
    required this.store,
    required this.client,
  });

  final String accountEmail;
  final DartCryptoProvider crypto;
  final Vault vault;
  final DeviceKeyStore store;
  final PubkeyClient client;

  KeyRef? mskKey;
  KeyRef? pendingMsk;

  /// Serializes every operation that reads or writes [vault]'s sync state
  /// (`generation`/`lastCiphertextHash`) — [mutateAndUpload] and a plain
  /// download both touch these fields, and neither previously excluded the
  /// other. A background auto-sync download landing mid-mutation could
  /// build its upload payload from a `generation`/`lastCiphertextHash`
  /// snapshot that a concurrent download had already changed underneath it
  /// — producing spurious `vault_revision_conflict`s. Every call that
  /// touches vault sync state must run through [_withVaultLock].
  Future<void> _vaultLockTail = Future<void>.value();

  Future<T> _withVaultLock<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    final previous = _vaultLockTail;
    _vaultLockTail = previous.then((_) async {
      try {
        completer.complete(await action());
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  static final Map<String, PubkeyRuntime> _instances = {};

  static String _normalize(String email) => email.trim().toLowerCase();

  /// Builds the runtime for an email not yet cached by [instance]. Host
  /// apps that need their own [DeviceKeyStore] (e.g. platform secure
  /// storage) and pubkey server URLs should override this once at startup;
  /// defaults to [createPubkeyRuntime] (pure-Dart, in-memory store), which
  /// is enough to run standalone — tests, a demo app — without any host
  /// wiring.
  static PubkeyRuntime Function(String email, {Dio? dio}) factory =
      createPubkeyRuntime;

  /// Gets (or lazily creates, via [factory]) the runtime scoped to [email]'s
  /// account. [dio] is only used the first time a runtime is created for
  /// [email] (e.g. to inject a scripted HTTP adapter in tests) — it's
  /// ignored once an instance is already cached.
  static PubkeyRuntime instance({required String email, Dio? dio}) {
    final normalized = _normalize(email);
    return _instances[normalized] ??= factory(normalized, dio: dio);
  }

  /// Drops the cached runtime for [email], e.g. when its account is removed.
  static void clearAccount(String email) {
    _instances.remove(_normalize(email));
  }

  static void resetForTest() {
    _instances.clear();
  }

  /// Finishes a VEK/AEK rotation whose server upload already succeeded but
  /// whose live device envelopes were not updated (crash, disk full).
  Future<void> completePendingEnvelopeRotation() =>
      _withVaultLock(_completePendingEnvelopeRotationUnlocked);

  Future<void> _completePendingEnvelopeRotationUnlocked() async {
    final pending = await store.loadPendingEnvelopeRotation(crypto);
    if (pending == null) return;

    final liveVek = await store.getVek(crypto);
    final pendingVek = pending.vek ?? liveVek;

    if (pendingVek != null && await _localVaultDecryptsWith(pendingVek)) {
      if (!vault.unlocked) {
        await vault.unlockVault(pendingVek);
      }
      if (await _pendingAekUnwrapsUnlockedVault(pending)) {
        await store.commitPendingEnvelopeRotation(crypto);
        return;
      }
    }

    if (pending.vek != null) {
      try {
        await client.downloadCurrentVault(
          email: accountEmail,
          vault: vault,
          vek: pending.vek!,
        );
        if (await _pendingAekUnwrapsUnlockedVault(pending)) {
          await store.commitPendingEnvelopeRotation(crypto);
          return;
        }
      } catch (_) {}
    }

    if (liveVek != null) {
      try {
        await client.downloadCurrentVault(
          email: accountEmail,
          vault: vault,
          vek: liveVek,
        );
        if (await _pendingAekUnwrapsUnlockedVault(pending)) {
          await store.commitPendingEnvelopeRotation(crypto);
        } else {
          await store.discardPendingEnvelopeRotation();
        }
      } catch (_) {}
    }
  }

  Future<bool> _localVaultDecryptsWith(Uint8List vek) async {
    final record = await store.load();
    if (record == null) return false;
    final encryption = record['encryption'];
    final ciphertextRaw = record['ciphertext'];
    if (encryption is! Map || ciphertextRaw is! String) return false;
    final ivRaw = encryption['iv'];
    if (ivRaw is! String) return false;
    try {
      await KeyHierarchy.decryptVaultCiphertextWithVek(
        crypto,
        vek,
        WrappedKey(
          iv: decodeBase64Url(ivRaw),
          ciphertext: decodeBase64Url(ciphertextRaw),
        ),
      );
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<bool> _pendingAekUnwrapsUnlockedVault(
    PendingEnvelopeRotation pending,
  ) async {
    if (pending.aek == null) return true;
    if (!vault.unlocked) return false;
    try {
      await vault.unwrapMsk(pending.aek!);
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> _requireCommittedRotation() async {
    await _completePendingEnvelopeRotationUnlocked();
    if (await store.loadPendingEnvelopeRotation(crypto) != null) {
      throw PubkeyException(
        ErrorCodes.vaultIntegrity,
        'Previous vault key rotation is not committed locally',
      );
    }
  }

  Future<Uint8List?> _resolvedVek() async {
    final pending = await store.loadPendingEnvelopeRotation(crypto);
    return pending?.vek ?? await store.getVek(crypto);
  }

  Future<Uint8List?> _resolvedAek() async {
    final pending = await store.loadPendingEnvelopeRotation(crypto);
    return pending?.aek ?? await store.getAek(crypto);
  }

  Future<KeyRef> requireMsk() async {
    if (mskKey != null) return mskKey!;
    await completePendingEnvelopeRotation();
    return _loadMskFromStore();
  }

  Future<KeyRef> _loadMskFromStore() async {
    if (mskKey != null) return mskKey!;
    if (!vault.unlocked) {
      final vek = await _resolvedVek();
      if (vek == null) {
        throw PubkeyException(
          ErrorCodes.masterKeyNotArmed,
          'Master Identity Key is not armed. Create one on this first device, or restore it from another device.',
        );
      }
      await vault.unlockVault(vek);
    }
    final aek = await _resolvedAek();
    if (aek == null) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'This device holds vault access but not authority (AEK) for this identity.',
      );
    }
    final mskBytes = await vault.unwrapMsk(aek);
    mskKey = await crypto.importPrivateKey(
      PortablePrivateKey(
        algorithm: mskAlgorithm,
        encoding: 'raw-32',
        bytes: mskBytes,
        purpose: Purposes.masterSigning,
      ),
    );
    return mskKey!;
  }

  /// AEK-wraps the MSK private key inside the Vault, then
  /// VEK-wraps the whole Vault for device-local persistence. VEK/AEK
  /// themselves are stored device-locally only as DKEK-wrapped envelopes
  /// — see [DeviceKeyStore]. This is the only device today
  /// (single-device, full-authority); DKEK-wrapped envelope re-wrapping for
  /// additional paired devices is a later step.
  Future<void> persistMsk(KeyRef key, {required String email}) async {
    final portable = await crypto.exportPrivateKey(key);
    if (!vault.unlocked) {
      // A vault that didn't already exist is, by definition, brand new —
      // genesis ("generation: 1"). A future MSK
      // replacement onto an *existing* vault (recovery, not yet
      // implemented) must not hit this branch, since it continues the
      // identity's prior generation counter instead of resetting it.
      await vault.createVault(principalFromEmail(email));
      vault.generation = 1;
    }
    final aek = await store.getAek(crypto) ?? KeyHierarchy.generateAek(crypto);
    await store.setAek(crypto, aek);
    await vault.setMsk(aek: aek, msk: portable);
    mskKey = key;
    pendingMsk = null;
    final vek = await store.getVek(crypto) ?? KeyHierarchy.generateVek(crypto);
    await store.setVek(crypto, vek);
    await vault.persist(vek);
    await client.uploadVault(email: email, mskKey: key, vault: vault, vek: vek);
  }

  /// Applies [mutation] to the vault, persists locally, and uploads as a new
  /// signed generation — call after any vault mutation
  /// (add/import/rotate a key). Local persistence always happens before the
  /// network call, so a failed upload (offline) never loses the local
  /// change.
  ///
  /// On `vault_revision_conflict` (another device's upload won
  /// the race), downloads the real current generation and reapplies
  /// [mutation] on top of *that* state rather than the stale one that lost,
  /// then retries the upload — up to [maxAttempts] times. [mutation] must be
  /// safe to call again on a freshly-downloaded vault (every call site here
  /// uses [Vault.addKey]/merge helpers, which are idempotent per
  /// fingerprint — see `Vault.addKey`). If retries are exhausted,
  /// the `vault_revision_conflict` [PubkeyException] propagates so the
  /// caller can surface a "sync conflict, please retry" message rather than
  /// looping silently forever.
  ///
  /// [mutationKind]/[targetDeviceId] are forwarded verbatim to
  /// [PubkeyClient.uploadVault] on every attempt — see that
  /// method's doc comment for what they mean and when they're required.
  Future<void> mutateAndUpload({
    required String email,
    required FutureOr<void> Function(Vault vault) mutation,
    String? uploadingDevice,
    String? mutationKind,
    String? targetDeviceId,
    int maxAttempts = 3,
  }) => _withVaultLock(() async {
    if (!vault.unlocked) {
      throw PubkeyException(
        ErrorCodes.vaultLocked,
        'Vault must be unlocked to mutate it',
      );
    }
    await _completePendingEnvelopeRotationUnlocked();
    final vek = await _resolvedVek();
    if (vek == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'This device has no Vault Encryption Key',
      );
    }
    final msk = await _loadMskFromStore();
    for (var attempt = 1;; attempt++) {
      await mutation(vault);
      await vault.persist(vek);
      try {
        await client.uploadVault(
          email: email,
          mskKey: msk,
          vault: vault,
          vek: vek,
          uploadingDevice: uploadingDevice,
          mutationKind: mutationKind,
          targetDeviceId: targetDeviceId,
        );
        return;
      } on PubkeyException catch (e) {
        if (e.code != ErrorCodes.vaultRevisionConflict || attempt >= maxAttempts) {
          rethrow;
        }
        final downloaded = await client.downloadCurrentVault(
          email: email,
          vault: vault,
          vek: vek,
        );
        if (downloaded == null) {
          // Server reported a conflict but now has no generation at all —
          // an inconsistent state that reapplying won't resolve.
          rethrow;
        }
        // Loop: reapply `mutation` on top of the freshly downloaded state,
        // then retry the upload.
      }
    }
  });

  /// Unlocks from the locally stored VEK if needed, then [mutateAndUpload].
  ///
  /// No-ops when this device cannot unlock the vault (no VEK) **or** holds no
  /// authority to upload one (no AEK — a limited-tier device from pairing or
  /// an offline import). Both are structural properties of the device, not
  /// failures: a limited device is a read-only client by design, and every
  /// caller here is a best-effort local mirror. Letting [mutateAndUpload]
  /// raise `device_not_authorized` instead crashed the app on such a device,
  /// from `hydrateKeyManagerFromVault` mirroring a key it had *just read out
  /// of the vault* back into the same vault.
  ///
  /// Deliberate mutations still use [mutateAndUpload] directly, which keeps
  /// throwing — a retire or a promotion that silently did not upload would be
  /// a lie. Persist and upload failures likewise still propagate.
  Future<void> mutateUnlockedVault({
    required String email,
    required FutureOr<void> Function(Vault vault) mutation,
    String? uploadingDevice,
    String? mutationKind,
    String? targetDeviceId,
    int maxAttempts = 3,
  }) async {
    if (!vault.unlocked) {
      await completePendingEnvelopeRotation();
      final vek = await _resolvedVek();
      if (vek != null) await vault.unlockVault(vek);
    }
    if (!vault.unlocked) return;
    if (mskKey == null && await _resolvedAek() == null) return;
    await mutateAndUpload(
      email: email,
      mutation: mutation,
      uploadingDevice: uploadingDevice,
      mutationKind: mutationKind,
      targetDeviceId: targetDeviceId,
      maxAttempts: maxAttempts,
    );
  }

  /// A plain pull — same as calling [client.downloadCurrentVault]
  /// directly, except serialized through [_withVaultLock] alongside
  /// [mutateAndUpload] so a sync triggered from one call site can never
  /// interleave with an in-flight mutation from another. Callers that
  /// previously called `runtime.client.downloadCurrentVault(...)` directly
  /// should use this instead whenever the call isn't already itself running
  /// inside another locked operation (e.g. [mutateAndUpload]'s own internal
  /// conflict-retry download, which is already lock-protected by its
  /// enclosing call).
  Future<int?> downloadCurrentVaultLocked({
    required String email,
    required Uint8List vek,
  }) => _withVaultLock(
    () => client.downloadCurrentVault(email: email, vault: vault, vek: vek),
  );

  // ---------------------------------------------------------------------
  // Device pairing.
  // ---------------------------------------------------------------------

  /// Device B's side of pairing. Awaits the
  /// mailbox creation (`POST /v1/pairing/{id}`) so the returned
  /// [PairingSession.sessionCode] is guaranteed to already exist
  /// server-side before the UI hands it to the user; [PairingSession.
  /// completed] is a separate, not-yet-awaited future covering the
  /// subsequent poll-for-response, so the caller
  /// can show the code immediately and await completion separately.
  ///
  /// On success: this device's own permanent DKEK is (re)established,
  /// VEK (and AEK, only if [requestedTier] was granted as `"full"`) are
  /// stored locally, and the current vault generation is pulled
  /// down so this device actually has vault content, not just
  /// the key material to decrypt it.
  ///
  /// Known gap (flagged, not silently worked around): pulling the vault
  /// generation goes through [PubkeyClient.downloadCurrentVault], which
  /// requires an MSK-signed request envelope for
  /// *every* operation, including reads. Producing that signature requires
  /// AEK to unwrap MSK. A `"limited"`-tier device never receives AEK by
  /// design (the read-only tier), so it can complete the
  /// pairing handshake (VEK/DKEK persisted) but cannot complete this final
  /// content sync — it throws [ErrorCodes.deviceNotAuthorized] instead of
  /// silently pretending to succeed.
  Future<PairingSession> beginPairingAsNewDevice({
    required String email,
    required String deviceName,
    required String requestedTier,
    Duration pollInterval = const Duration(seconds: 4),
    int expiresInSeconds = 300,
    PairingSecretMode secretMode = PairingSecretMode.highEntropy,
  }) async {
    if (requestedTier != 'full' && requestedTier != 'limited') {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'requestedTier must be "full" or "limited"',
      );
    }
    final sessionId = DevicePairing.generateSessionId(crypto);
    final Uint8List password;
    String? typedPassword;
    if (secretMode == PairingSecretMode.typed) {
      typedPassword = DevicePairing.generateTypedPassword(crypto);
      password = DevicePairing.typedPasswordBytes(typedPassword);
    } else {
      password = DevicePairing.generateHighEntropyPassword(crypto);
    }
    final locator =
        emailSha256Hex(requireCanonicalEmail(normalizeEmail(email)));
    final sid = DevicePairing.pairingSid(
      sessionId: sessionId,
      identityLocator: locator,
      requestedTier: requestedTier,
    );
    final cpace = await crypto.cpaceStart(
      password: password,
      sid: sid,
      ci: DevicePairing.pairingCi(locator),
    );
    final deviceId = await store.ensureDeviceId(crypto);
    final created = await client.createPairingSession(
      sessionId: sessionId,
      email: email,
      deviceName: deviceName,
      requestedTier: requestedTier,
      bPakeElement: cpace.publicElement,
      deviceId: deviceId,
      expiresIn: expiresInSeconds,
    );
    final expiresAtRaw = created['expires_at'];
    final expiresAt = expiresAtRaw is String
        ? DateTime.parse(expiresAtRaw).toUtc()
        : DateTime.now().toUtc().add(Duration(seconds: expiresInSeconds));

    final completed = _pollForPairingResponse(
      email: email,
      sessionId: sessionId,
      deviceId: deviceId,
      requestedTier: requestedTier,
      locator: locator,
      cpace: cpace,
      password: password,
      expiresAt: expiresAt,
      pollInterval: pollInterval,
    );

    return PairingSession(
      sessionCode: sessionId,
      pairingUri: PairingUri(sessionId: sessionId, password: password)
          .toUriString(),
      pairingPassword: password,
      typedPassword: typedPassword,
      expiresAt: expiresAt,
      completed: completed,
    );
  }

  Future<void> _pollForPairingResponse({
    required String email,
    required String sessionId,
    required String deviceId,
    required String requestedTier,
    required String locator,
    required CPaceSession cpace,
    required Uint8List password,
    required DateTime expiresAt,
    required Duration pollInterval,
  }) async {
    PairingSessionStatus status;
    while (true) {
      status = await client.getPairingSession(
        sessionId: sessionId,
        emailSha256Hex: locator,
        retrieverDeviceId: deviceId,
      );
      if (status.state == PairingSessionState.responded) break;
      if (status.state == PairingSessionState.completed) {
        throw PubkeyException(
          ErrorCodes.pairingSessionAlreadyResponded,
          'Pairing session was already retrieved',
        );
      }
      if (DateTime.now().toUtc().isAfter(expiresAt)) {
        throw PubkeyException(
          ErrorCodes.pairingSessionExpired,
          'Pairing session expired before the other device approved it',
        );
      }
      await Future<void>.delayed(pollInterval);
    }

    final ya = cpace.publicElement;
    final yb = status.aPakeElement;
    final tag = status.confirmationTag;
    final sig = status.mskSignature;
    if (yb == null || tag == null || sig == null || status.vekEnvelope == null) {
      throw PubkeyException(
        ErrorCodes.pairingProtocolUnsupported,
        'Pairing response missing CPace v2 fields',
      );
    }

    final mskPublic = await client.fetchArmedMskPublicKey(email: email);
    final transcript = DevicePairing.canonicalTranscript(
      sessionId: sessionId,
      identityLocator: locator,
      requestedTier: requestedTier,
      ya: ya,
      yb: yb,
      confirmationTag: tag,
    );
    final sigOk = await crypto.verify(mskPublic, transcript, sig);
    if (!sigOk) {
      throw PubkeyException(
        ErrorCodes.pairingSignatureInvalid,
        'Pairing transcript MSK signature is invalid',
      );
    }

    final isk = await crypto.cpaceFinish(cpace, yb);
    final tek = await DevicePairing.deriveTekV2(
      crypto,
      isk,
      sessionId: sessionId,
      ya: ya,
      yb: yb,
      identityLocator: locator,
      requestedTier: requestedTier,
    );
    try {
      await crypto.decryptAead(tek, tag.iv, tag.ciphertext);
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.pairingPasswordMismatch,
        'Pairing confirmation tag failed; wrong password or tampering',
      );
    }

    final transfer = await DevicePairing.unwrapTransfer(
      crypto,
      tek,
      status.vekEnvelope!,
      status.aekEnvelope,
    );

    await store.ensureDkek(crypto);
    await store.setVek(crypto, transfer.vek);
    if (transfer.aek != null) {
      await store.setAek(crypto, transfer.aek!);
    }

    if (!vault.unlocked) {
      await vault.createVault(principalFromEmail(
        requireCanonicalEmail(normalizeEmail(email)),
      ));
    }
    await client.downloadCurrentVault(
      email: email,
      vault: vault,
      vek: transfer.vek,
    );
    await vault.persist(transfer.vek);
  }

  Future<PendingPairingRequest> fetchPendingPairingRequest({
    required String sessionId,
    required String email,
  }) async {
    final emailHash =
        emailSha256Hex(requireCanonicalEmail(normalizeEmail(email)));
    final status = await client.getPairingSession(
      sessionId: sessionId,
      emailSha256Hex: emailHash,
    );
    if (status.state != PairingSessionState.pending) {
      throw PubkeyException(
        ErrorCodes.pairingSessionAlreadyResponded,
        'Pairing session is not awaiting approval (state: ${status.state.name})',
      );
    }
    final ya = status.bPakeElement;
    if (ya == null) {
      throw PubkeyException(
        ErrorCodes.pairingProtocolUnsupported,
        'Pending pairing session has no CPace element',
      );
    }
    return PendingPairingRequest(
      sessionId: sessionId,
      deviceName: status.deviceName ?? '',
      requestedTier: status.requestedTier ?? 'limited',
      bDeviceId: status.deviceId ?? '',
      bPakeElement: ya,
    );
  }

  Future<PairingConfirmationResult> confirmPairingRequest({
    required String email,
    required PendingPairingRequest request,
    required Uint8List pairingPassword,
    Duration pollInterval = const Duration(seconds: 2),
    int completionTimeoutSeconds = 300,
  }) async {
    if (request.requestedTier == 'full' && !(await store.isFullAuthority())) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'This device is limited-tier and cannot grant full authority to another device.',
      );
    }

    final vek = await _resolvedVek();
    if (vek == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'This device has no Vault Encryption Key to share',
      );
    }
    final aek =
        request.requestedTier == 'full' ? await _resolvedAek() : null;
    if (request.requestedTier == 'full' && aek == null) {
      throw PubkeyException(
        ErrorCodes.deviceNotAuthorized,
        'This device is missing its own Authority Envelope',
      );
    }

    final locator =
        emailSha256Hex(requireCanonicalEmail(normalizeEmail(email)));
    final sid = DevicePairing.pairingSid(
      sessionId: request.sessionId,
      identityLocator: locator,
      requestedTier: request.requestedTier,
    );
    final responded = await crypto.cpaceRespond(
      password: pairingPassword,
      sid: sid,
      peerPublicElement: request.bPakeElement,
      ci: DevicePairing.pairingCi(locator),
    );
    final tek = await DevicePairing.deriveTekV2(
      crypto,
      responded.isk,
      sessionId: request.sessionId,
      ya: request.bPakeElement,
      yb: responded.publicElement,
      identityLocator: locator,
      requestedTier: request.requestedTier,
    );
    final tagBox = await crypto.encryptAead(
      tek,
      utf8.encode(pairingConfirmPlaintext),
    );
    final confirmationTag =
        WrappedKey(iv: tagBox.iv, ciphertext: tagBox.ciphertext);
    final envelopes =
        await DevicePairing.wrapForTransfer(crypto, tek, vek, aek);
    final transcript = DevicePairing.canonicalTranscript(
      sessionId: request.sessionId,
      identityLocator: locator,
      requestedTier: request.requestedTier,
      ya: request.bPakeElement,
      yb: responded.publicElement,
      confirmationTag: confirmationTag,
    );
    final msk = await requireMsk();
    final mskSignature = await crypto.sign(msk, transcript);

    await client.respondToPairingSession(
      sessionId: request.sessionId,
      emailSha256Hex: locator,
      aPakeElement: responded.publicElement,
      vekEnvelope: envelopes.vekEnvelope,
      aekEnvelope: envelopes.aekEnvelope,
      confirmationTag: confirmationTag,
      mskSignature: mskSignature,
    );

    final deadline =
        DateTime.now().toUtc().add(Duration(seconds: completionTimeoutSeconds));
    while (true) {
      PairingSessionStatus status;
      try {
        status = await client.getPairingSession(
          sessionId: request.sessionId,
          emailSha256Hex: locator,
        );
      } on PubkeyException catch (e) {
        if (e.code == ErrorCodes.pairingSessionExpired) {
          throw PubkeyException(
            ErrorCodes.pairingSessionExpired,
            'Pairing timed out: the new device never completed retrieval, '
            'so it was not registered.',
          );
        }
        rethrow;
      }
      if (status.state == PairingSessionState.completed) break;
      if (DateTime.now().toUtc().isAfter(deadline)) {
        throw PubkeyException(
          ErrorCodes.pairingSessionExpired,
          'Pairing timed out: the new device never completed retrieval, '
          'so it was not registered.',
        );
      }
      await Future<void>.delayed(pollInterval);
    }

    final addedBy = await store.ensureDeviceId(crypto);
    await mutateAndUpload(
      email: email,
      mutation: (v) => v.devices.add(
        DeviceMetadata(
          deviceId: request.bDeviceId,
          name: request.deviceName,
          tier: request.requestedTier,
          addedAt: DateTime.now().millisecondsSinceEpoch,
          addedBy: addedBy,
        ),
      ),
      mutationKind: HighRiskMutationKinds.deviceAdd,
      targetDeviceId: request.bDeviceId,
    );

    return PairingConfirmationResult(
      deviceId: request.bDeviceId,
      tier: request.requestedTier,
    );
  }

  // ---------------------------------------------------------------------
  // Vault key add/rotation flows — canonical pointers.
  // ---------------------------------------------------------------------

  /// Sets `vault.currentSigningKeyId` — the canonical
  /// pointer to which `signing_keys` entry is this identity's
  /// currently-active one. Setting this pointer is a normal vault mutation,
  /// but *rotating which* signing key is canonical is
  /// exactly the "signing-key rotation" high-risk mutation kind the
  /// grace period protects.
  ///
  /// [newSigningKeyId] must already exist in the vault's `signing_keys`
  /// array (added via [Vault.addKey] with `family: null, kind: 'content'`)
  /// with `status: 'active'` — this method only flips the pointer, it does
  /// not generate or import the key itself.
  Future<void> rotateSigningKey({
    required String email,
    required int newSigningKeyId,
  }) async {
    final target = vault.entries.firstWhere(
      (e) =>
          e.family == null && e.kind == 'content' && e.keyId == newSigningKeyId,
      orElse: () => throw PubkeyException(
        ErrorCodes.keyNotFound,
        'No signing key with id $newSigningKeyId in this vault',
      ),
    );
    if (target.status != 'active') {
      throw PubkeyException(
        ErrorCodes.vaultIntegrity,
        'Cannot make a non-active signing key canonical',
      );
    }
    await mutateAndUpload(
      email: email,
      mutation: (v) => v.currentSigningKeyId = newSigningKeyId.toString(),
      mutationKind: HighRiskMutationKinds.signingKeyRotation,
    );
  }

  /// Sets `vault.currentEncryptionKeyId` — this
  /// identity's own cross-device record of which PGP encryption key
  /// *should* be advertised to new senders. This is a **normal** mutation,
  /// not high-risk/grace-gated — encryption-key
  /// advertising is not among the grace-gated mutation kinds, so `mutationKind` is
  /// intentionally omitted.
  ///
  /// Flipping this pointer alone does **not** make `GET /v1/keys` return the
  /// key to new senders — that requires the separate, unchanged legacy
  /// `set_encryption_key` artifact-proof-of-possession publish call, which
  /// needs the key's full OpenPGP public certificate (UID + self-signature),
  /// not just the raw private scalar this Vault stores. That certificate
  /// only exists in the host app's local key store, so the full promotion
  /// flow (pointer + legacy publish) is orchestrated one layer up — this
  /// method is only the vault-pointer half of it.
  ///
  /// [keyId] must already exist in the vault as an `active` PGP encryption
  /// entry (added via [Vault.addKey]).
  Future<void> promoteEncryptionKeyPointer({
    required String email,
    required int keyId,
  }) async {
    final target = vault.entries.firstWhere(
      (e) =>
          e.family == Families.pgp &&
          e.purpose == Purposes.encryption &&
          e.keyId == keyId,
      orElse: () => throw PubkeyException(
        ErrorCodes.keyNotFound,
        'No active PGP encryption key with id $keyId in this vault',
      ),
    );
    if (target.status != 'active') {
      throw PubkeyException(
        ErrorCodes.vaultIntegrity,
        'Cannot advertise a non-active encryption key',
      );
    }
    await mutateAndUpload(
      email: email,
      mutation: (v) => v.currentEncryptionKeyId = keyId.toString(),
    );
  }

  // ---------------------------------------------------------------------
  // Grace period for high-risk mutations.
  // ---------------------------------------------------------------------

  /// Fetches the identity's currently-pending high-risk mutations —
  /// the no-push-infra design means any device discovers these by
  /// polling, typically alongside the vault's own sync cadence.
  Future<List<PendingHighRiskMutation>> fetchPendingHighRiskMutations({
    required String email,
  }) {
    return client.fetchPendingHighRiskMutations(email: email);
  }

  /// Cancels a still-pending high-risk mutation. Any
  /// currently-authorized device may call this, not just the device that
  /// originated the mutation — [requireMsk] just needs *this* device's own
  /// AEK to sign the request, which any full-authority device already has.
  ///
  /// For a device-add mutation, the server also revokes the target device
  /// as part of the same call (a revocation carve-out) — the UI
  /// call site should warn the user about this before calling.
  Future<Map<String, dynamic>> cancelHighRiskMutation({
    required String email,
    required String mutationId,
  }) async {
    final msk = await requireMsk();
    return client.cancelHighRiskMutation(
      email: email,
      mutationId: mutationId,
      mskKey: msk,
    );
  }

  // ---------------------------------------------------------------------
  // Vault export/import (offline, no live pairing).
  // ---------------------------------------------------------------------

  /// Device A's side of export. Pulls the freshest generation
  /// down from the server first, then returns the export file's JSON
  /// structure — writing it to a file is a UI/IO concern, not this method's
  /// (return data, let the call site touch `dart:io`).
  ///
  /// [passphrase] controls whether the bundled VEK (and AEK, for a `"full"`
  /// export) are actually included:
  /// - Non-empty: unwraps this device's own VEK (and AEK, only if [tier] is
  ///   `"full"`), derives a fresh-salt EEK from it, and bundles the
  ///   password-wrapped envelopes alongside the ciphertext — this file can
  ///   be imported standalone with just the passphrase.
  /// - `null`/empty: a vault-only export — only the (still VEK-encrypted)
  ///   ciphertext is included, no VEK/AEK envelope at all. This file alone
  ///   cannot be decrypted; the importing device must separately obtain VEK
  ///   (e.g. via pairing) to ever read it.
  ///
  /// Freshness note: this re-fetches the current generation via
  /// [PubkeyClient.downloadCurrentVault] so the export
  /// reflects the latest content, then re-encrypts the now-current plaintext
  /// locally (`Vault.exportVault`) to produce the bundled ciphertext bytes —
  /// it does not reuse the server's own raw ciphertext bytes verbatim (VEK
  /// didn't change, so this is content-equivalent). One consequence: this
  /// bundle's own `ciphertext_hash` will not match the server's stored hash
  /// for that generation, so `previous_generation_hash` is deliberately
  /// omitted (see [VaultExport.buildExportFile]'s doc comment) — this is
  /// harmless because the importing device's very first future mutation
  /// self-heals via the existing conflict-retry path
  /// ([mutateAndUpload] already downloads-and-reapplies on a hash mismatch).
  ///
  /// Throws [ErrorCodes.masterKeyNotArmed] if this device has no VEK, or
  /// [ErrorCodes.deviceNotAuthorized] if [tier] is `"full"` but this device
  /// itself is limited-tier (a device can only export the authority it
  /// actually holds — same rule pairing already enforces for
  /// granting full tier to a new device).
  Future<Map<String, dynamic>> exportVaultOffline({
    required String email,
    String? passphrase,
    required String tier,
  }) async {
    if (tier != 'full' && tier != 'limited') {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'tier must be "full" or "limited"',
      );
    }
    final protect = passphrase != null && passphrase.isNotEmpty;
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final vek = await _resolvedVek();
    if (vek == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'This device has no Vault Encryption Key to export',
      );
    }
    // Checked before touching the vault at all — a device can only export
    // the authority it actually holds. Only meaningful when actually
    // bundling secrets: a vault-only export doesn't touch AEK at all, so
    // tier is purely descriptive header metadata in that case.
    Uint8List? aek;
    if (protect && tier == 'full') {
      aek = await _resolvedAek();
      if (aek == null) {
        throw PubkeyException(
          ErrorCodes.deviceNotAuthorized,
          'This device is limited-tier and cannot export full authority',
        );
      }
    }
    if (!vault.unlocked) {
      await vault.unlockVault(vek);
    }

    // Pull the latest generation down first so the export
    // reflects current content, not a stale local cache. `downloadCurrentVault`
    // is designed around a device that's either brand new or exactly one
    // generation behind (it rejects anything else as a
    // `vault_revision_conflict`) — it has no "I'm already exactly current"
    // case. Since the exporting device commonly *is* already current, that
    // specific conflict is treated here as "nothing newer to fetch," not a
    // real error; any other exception still propagates. This is a
    // best-effort freshness step, not a security boundary — the bundled
    // ciphertext's own AEAD tag and the importer's
    // conflict-retry still hold regardless of which generation actually got
    // exported.
    try {
      await client.downloadCurrentVault(email: email, vault: vault, vek: vek);
    } on PubkeyException catch (e) {
      if (e.code != ErrorCodes.vaultRevisionConflict) rethrow;
    }

    // One Argon2id derivation per export (not one per secret) — EEK is then
    // reused to AEAD-wrap both VEK and AEK, each with its own independently
    // random IV (safe, standard single-key/multiple-message AEAD usage; the
    // salt is still recorded on the AEK envelope too, for header
    // self-description, even though it's the same salt as the VEK
    // envelope's — see `ExportEnvelope.toJson`). Skipped entirely for a
    // vault-only (unprotected) export.
    ExportEnvelope? vekEnvelope;
    ExportEnvelope? aekEnvelope;
    if (protect) {
      final salt = crypto.random(eekSaltBytes);
      final eek = await VaultExport.deriveEek(crypto, passphrase, salt);
      vekEnvelope = await VaultExport.wrapWithEek(crypto, eek, vek, salt: salt);
      if (aek != null) {
        aekEnvelope =
            await VaultExport.wrapWithEek(crypto, eek, aek, salt: salt);
      }
    }

    final exported = await vault.exportVault(vek);
    final encryption = exported['encryption'] as Map;
    final ciphertext = decodeBase64Url(exported['ciphertext'] as String);
    final nonce = decodeBase64Url(encryption['iv'] as String);
    final ciphertextHash = sha256Bytes(ciphertext);

    return VaultExport.buildExportFile(
      identity: canonical,
      tier: tier,
      createdAt: DateTime.now().millisecondsSinceEpoch,
      vekEnvelope: vekEnvelope,
      aekEnvelope: aekEnvelope,
      generation: vault.generation,
      ciphertext: ciphertext,
      nonce: nonce,
      ciphertextHash: ciphertextHash,
    );
  }

  /// Device B's side of import — this device has never talked
  /// to the server before and has no live pairing session; it only has the
  /// export file and the out-of-band passphrase.
  ///
  /// Derives EEK from the file's own salt/kdf params, unwraps VEK (and AEK,
  /// if the file is `tier: "full"`), decrypts the bundled vault ciphertext
  /// into a fresh local [Vault], generates this device's own permanent DKEK,
  /// and persists DKEK-wrapped envelopes locally — mirroring
  /// [beginPairingAsNewDevice]'s pattern closely.
  ///
  /// A **limited**-tier import does **not** register this device in
  /// `metadata.devices` at all — it stays a pure read-only client,
  /// structurally identical to a limited-tier *paired* device
  /// never getting a device-add mutation. Only a **full**-tier import
  /// (VEK+AEK) performs a normal device-add mutation, tagged `mutationKind:
  /// HighRiskMutationKinds.deviceAdd` — same as [confirmPairingRequest]'s
  /// call site — so the grace period applies uniformly to every
  /// way a device can be added.
  Future<void> importVaultOffline({
    required String email,
    required String passphrase,
    required Map<String, dynamic> exportedFile,
    required String deviceName,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final parsed = VaultExport.parseExportFile(exportedFile);
    if (parsed.identity != canonical) {
      throw PubkeyException(
        ErrorCodes.principalMismatch,
        'This vault export file belongs to a different identity',
      );
    }
    if (!parsed.hasSecrets) {
      // Caller should have checked `hasSecrets` first and offered
      // pairing instead — this is a defensive backstop, not the normal
      // path.
      throw PubkeyException(
        ErrorCodes.vaultExportFormatUnsupported,
        'This backup has no encrypted secrets to import — sync from '
        'another device instead',
      );
    }

    final vek = await VaultExport.unwrapWithEek(
      crypto,
      passphrase,
      parsed.vekEnvelope!,
    );
    Uint8List? aek;
    if (parsed.aekEnvelope != null) {
      aek = await VaultExport.unwrapWithEek(
        crypto,
        passphrase,
        parsed.aekEnvelope!,
      );
    }

    if (!vault.unlocked) {
      await vault.createVault(principalFromEmail(canonical));
    }
    final ciphertextHash = sha256Bytes(parsed.ciphertext);
    await vault.applyDownloadedGeneration(
      vek: vek,
      iv: parsed.nonce,
      ciphertext: parsed.ciphertext,
      ciphertextHash: ciphertextHash,
    );

    await store.ensureDkek(crypto);
    await store.setVek(crypto, vek);
    if (aek != null) {
      await store.setAek(crypto, aek);
    }
    await vault.persist(vek);

    if (aek == null) {
      // Limited tier: a pure read-only client, per the design note above.
      return;
    }

    final deviceId = await store.ensureDeviceId(crypto);
    await mutateAndUpload(
      email: email,
      mutation: (v) => v.devices.add(
        DeviceMetadata(
          deviceId: deviceId,
          name: deviceName,
          tier: 'full',
          addedAt: DateTime.now().millisecondsSinceEpoch,
          addedBy: deviceId,
        ),
      ),
      mutationKind: HighRiskMutationKinds.deviceAdd,
      targetDeviceId: deviceId,
    );
  }

  // ---------------------------------------------------------------------
  // Historical key retention & re-import.
  // ---------------------------------------------------------------------

  /// Historical key retention & re-import.
  ///
  /// Scenario: this device went offline before an OTP-only
  /// recovery happened elsewhere. It still holds its OLD [DeviceKeyStore]
  /// state (unchanged since it went offline), referencing
  /// the OLD VEK/AEK, which can still decrypt the OLD vault generation
  /// chain, but is now cryptographically disconnected from the CURRENT
  /// identity (a new MSK is armed, a new VEK exists elsewhere). This method
  /// lets it recover whatever old keys it can from that specific old
  /// [generation] and merge them into the CURRENT vault as `status:
  /// 'retired'` (spec's `'historical'`, see [statusToSpec]) entries — for
  /// read/reference purposes only, never regaining any authority.
  ///
  /// [oldVek] is the OLD generation's VEK. This device already holds it
  /// locally — it is never derived, fetched, or
  /// reconstructed here (the invariant: proof of current identity
  /// control must never, by itself, unlock a previous generation; this
  /// method only works at all because the *caller* already separately holds
  /// this specific old secret from before the discontinuity happened).
  ///
  /// **Enforced precondition**: this
  /// device must *itself* already hold CURRENT-generation VEK and AEK. This
  /// is checked first, via [requireMsk] (which unlocks the current vault and
  /// requires AEK to be present), before any old-generation network fetch or
  /// decrypt is attempted — so a device that isn't itself current-authority
  /// fails cleanly with **no** partial merge.
  ///
  /// Recovered keys are merged via a single, normal vault mutation
  /// against the CURRENT generation, signed by the CURRENT MSK — the
  /// old MSK/VEK/AEK never sign anything as "the current identity" again.
  /// No `mutationKind` is declared: this is not one of
  /// the high-risk mutation kinds — merging a read-only historical
  /// entry grants no new authority and adds no device.
  ///
  /// Deduplication reuses [Vault]'s own fingerprint-based uniqueness check
  /// ([Vault.getKeyByFingerprint] to decide what's already present, then
  /// [Vault.addKey] itself). An old entry whose fingerprint already exists
  /// in the current vault is left untouched — not duplicated, and not
  /// "downgraded" to `retired` if it's currently `active`; the current
  /// vault's own copy stays authoritative.
  ///
  /// All newly-recovered entries are merged in a **single** mutation/upload,
  /// not one upload per key — one atomic generation bump covers the whole
  /// re-import.
  Future<HistoricalReimportResult> reimportHistoricalGeneration({
    required String email,
    required int generation,
    required Uint8List oldVek,
  }) async {
    // See the enforced-precondition note above: fail before touching the old
    // generation at all if this device isn't itself current-authority.
    await requireMsk();

    final recovered = await client.downloadVaultGeneration(
      email: email,
      generation: generation,
      vek: oldVek,
    );
    if (recovered == null) {
      // The server has no record at all for this generation number —
      // distinct from "found it, but it happened to be empty" below.
      throw PubkeyException(
        ErrorCodes.vaultGenerationNotFound,
        'No such vault generation exists for this identity',
      );
    }
    if (recovered.isEmpty) {
      return const HistoricalReimportResult(
        recoveredCount: 0,
        mergedCount: 0,
        alreadyPresentCount: 0,
      );
    }

    final toImport = <VaultEntry>[];
    var alreadyPresent = 0;
    for (final entry in recovered) {
      final fingerprint = entry.fingerprint;
      if (fingerprint == null ||
          fingerprint.isEmpty ||
          vault.getKeyByFingerprint(fingerprint) != null) {
        alreadyPresent++;
        continue;
      }
      toImport.add(entry);
    }

    if (toImport.isEmpty) {
      return HistoricalReimportResult(
        recoveredCount: recovered.length,
        mergedCount: 0,
        alreadyPresentCount: alreadyPresent,
      );
    }

    await mutateAndUpload(
      email: email,
      mutation: (v) {
        for (final entry in toImport) {
          final imported = entry.clone();
          imported.status = 'retired';
          v.addKey(imported);
        }
      },
    );

    return HistoricalReimportResult(
      recoveredCount: recovered.length,
      mergedCount: toImport.length,
      alreadyPresentCount: alreadyPresent,
    );
  }

  // ---------------------------------------------------------------------
  // Recovery via recovery code.
  // ---------------------------------------------------------------------

  /// The setup half: the user chooses [format] (`bip39`/`random`)
  /// and [scope] (`full`/`read-only`) at setup time; setup is
  /// optional/user-initiated, never mandatory.
  ///
  /// Requires this device to actually hold the authority it's being asked to
  /// back up — same early check [exportVaultOffline]/[confirmPairingRequest]
  /// already use: [ErrorCodes.masterKeyNotArmed] if this device has no VEK
  /// at all, [ErrorCodes.deviceNotAuthorized] if [scope] is
  /// [RecoveryScopes.full] but this device is itself limited-tier (no AEK).
  ///
  /// Returns the plaintext recovery code **exactly once** — the caller must
  /// show it to the user immediately (with a clear "write this down, we
  /// never store it" warning) and then discard it; this method itself never
  /// persists or logs it (Boundary B2's spirit — treated with the same care
  /// as raw key material even though it isn't VEK/AEK itself).
  Future<String> setupRecoveryCode({
    required String email,
    required String format,
    required String scope,
  }) async {
    if (format != RecoveryCodeFormats.bip39 && format != RecoveryCodeFormats.random) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'format must be "bip39" or "random"',
      );
    }
    if (scope != RecoveryScopes.full && scope != RecoveryScopes.readOnly) {
      throw PubkeyException(
        ErrorCodes.capabilityMismatch,
        'scope must be "full" or "read-only"',
      );
    }
    final vek = await _resolvedVek();
    if (vek == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'This device has no Vault Encryption Key to back up',
      );
    }
    Uint8List? aek;
    if (scope == RecoveryScopes.full) {
      aek = await _resolvedAek();
      if (aek == null) {
        throw PubkeyException(
          ErrorCodes.deviceNotAuthorized,
          'This device is limited-tier and cannot set up a full-authority recovery code',
        );
      }
    }

    final recoveryCode = format == RecoveryCodeFormats.bip39
        ? RecoveryCode.generateBip39Words(crypto)
        : RecoveryCode.generateRandomCode(crypto);

    // One Argon2id derivation, reused to wrap both VEK and AEK (each with
    // its own independently random IV) — same reasoning as
    // `exportVaultOffline`'s single-EEK-derivation comment.
    final salt = crypto.random(eekSaltBytes);
    final rek = await RecoveryCode.deriveRek(crypto, recoveryCode, salt);
    final vekEnvelope = await RecoveryCode.wrapForRecovery(crypto, rek, vek, salt: salt);
    ExportEnvelope? aekEnvelope;
    if (aek != null) {
      aekEnvelope = await RecoveryCode.wrapForRecovery(crypto, rek, aek, salt: salt);
    }

    final msk = await requireMsk();
    await client.setRecoveryEnvelope(
      email: email,
      mskKey: msk,
      vekEnvelope: vekEnvelope,
      aekEnvelope: aekEnvelope,
    );

    return recoveryCode;
  }

  /// The OTP-request half: emails a fresh OTP that
  /// [recoverWithCode] will need. Does not itself require any local
  /// key material — this is meant to be callable from a brand-new device
  /// that hasn't recovered anything yet.
  Future<void> requestRecoveryCodeOtp({required String email}) {
    return client.requestRecoveryEnvelopeOtp(email: email);
  }

  /// Recovery via recovery code — preserves the old
  /// vault, unlike OTP-only recovery.
  ///
  /// Fetches the OTP-gated recovery envelope, derives REK from
  /// [recoveryCode] entirely locally (the code itself never leaves this
  /// device), unwraps VEK (and AEK, if this recovery code was set
  /// up with [RecoveryScopes.full] scope), and uses VEK to decrypt the
  /// **existing, current** vault generation directly via
  /// [PubkeyClient.downloadCurrentVault] — deliberately **not**
  /// [Vault.createVault]/genesis, and no new generation is created for this
  /// step (a critical distinction from OTP-only recovery).
  ///
  /// Registers this device in `metadata.devices` (a normal device-add
  /// mutation, tagged for the grace period) **only
  /// if** the recovered scope included AEK — a read-only-scope recovery
  /// leaves this device unregistered, structurally unable to sign, exactly
  /// symmetric with the limited-tier pairing and the
  /// limited-tier offline import.
  Future<RecoveryWithCodeResult> recoverWithCode({
    required String email,
    required String otp,
    required String recoveryCode,
    required String deviceName,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final bundle = await client.fetchRecoveryEnvelope(email: email, otp: otp);

    final vek = await RecoveryCode.unwrapRecovery(crypto, recoveryCode, bundle.vekEnvelope);
    Uint8List? aek;
    if (bundle.aekEnvelope != null) {
      aek = await RecoveryCode.unwrapRecovery(crypto, recoveryCode, bundle.aekEnvelope!);
    }

    if (!vault.unlocked) {
      await vault.createVault(principalFromEmail(canonical));
    }
    final generation =
        await client.downloadCurrentVault(email: email, vault: vault, vek: vek);
    if (generation == null) {
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'No vault generation exists yet for this identity',
      );
    }

    await store.ensureDkek(crypto);
    await store.setVek(crypto, vek);
    if (aek != null) {
      await store.setAek(crypto, aek);
    }

    if (aek == null) {
      // Read-only scope: stays unregistered, per the doc comment above.
      return const RecoveryWithCodeResult(deviceRegistered: false);
    }

    final deviceId = await store.ensureDeviceId(crypto);
    await mutateAndUpload(
      email: email,
      mutation: (v) => v.devices.add(
        DeviceMetadata(
          deviceId: deviceId,
          name: deviceName,
          tier: 'full',
          addedAt: DateTime.now().millisecondsSinceEpoch,
          addedBy: deviceId,
        ),
      ),
      mutationKind: HighRiskMutationKinds.deviceAdd,
      targetDeviceId: deviceId,
    );
    return RecoveryWithCodeResult(deviceRegistered: true, deviceId: deviceId);
  }

  // ---------------------------------------------------------------------
  // OTP-only identity recovery — last-resort recovery when no
  // device and no recovery code survive. Structurally almost
  // identical to genesis at a later generation number, with a
  // brand-new, fully independent VEK/AEK/MSK/DKEK (the invariant:
  // OTP proof must never unlock the old vault).
  // ---------------------------------------------------------------------

  /// Completes OTP-only identity recovery, called *after*
  /// [PubkeyClient.replaceMasterSigningKey] (`verifyReplace`) has already
  /// succeeded server-side for [newMskKey] — that call is what OTP-authorized
  /// the new MSK generation to become armed in the first place. Everything
  /// this method does is downstream of that: a normal,
  /// unmodified MSK-signed [PubkeyClient.uploadVault] call now naturally
  /// satisfies that requirement, since the new MSK is already legitimately
  /// armed.
  ///
  /// Generates a brand-new `VEK2`/`AEK2` and a fresh local `DKEK`
  /// ("OTP verification alone must never result in the old vault's ciphertext
  /// becoming decryptable" — these are CSPRNG values with no relationship to
  /// the old generation's keys, never derived from OTP, email, or anything
  /// the server could reconstruct), builds a fresh, minimal
  /// [Vault] (empty key arrays, same as genesis) at the *next* generation
  /// number — fetched via [PubkeyClient.fetchCurrentVaultGenerationInfo].
  /// The actual authority discontinuity is expressed by the signature
  /// switching to [newMskKey] and by the new `AuthorityTransition` record
  /// the server creates — not by breaking the hash chain.
  ///
  /// This device adds itself directly into the fresh vault's
  /// `metadata.devices` at creation (like genesis — it's establishing a new
  /// epoch, not joining an existing one via pairing) and the upload carries
  /// **no** `mutationKind` — the grace period protects additions to
  /// an existing, live authority against a single-signature compromise; it
  /// has no meaning for an identity's first post-recovery upload, exactly as
  /// genesis's own first upload is never grace-gated either.
  Future<void> completeOtpOnlyRecovery({
    required String email,
    required KeyRef newMskKey,
    required String deviceName,
  }) async {
    final canonical = requireCanonicalEmail(normalizeEmail(email));
    final principal = principalFromEmail(canonical);

    final oldGeneration =
        await client.fetchCurrentVaultGenerationInfo(email: email);

    // Brand-new cryptographic material, fully independent of the old
    // generation (the security invariant).
    final vek2 = KeyHierarchy.generateVek(crypto);
    final aek2 = KeyHierarchy.generateAek(crypto);

    await vault.createVault(principal);
    if (oldGeneration != null) {
      // Chains from the OLD current generation's hash even though the new
      // content is unrelated (see this method's doc comment) —
      // `uploadVault`'s existing "already-known lastCiphertextHash" branch
      // then sends `oldGeneration.generation + 1`.
      vault.generation = oldGeneration.generation;
      vault.lastCiphertextHash = oldGeneration.ciphertextHash;
    } else {
      // No prior generation exists at all — treated the same as genesis
      // ("generation: 1").
      vault.generation = 1;
    }

    final mskPortable = await crypto.exportPrivateKey(newMskKey);
    await vault.setMsk(aek: aek2, msk: mskPortable);

    await store.ensureDkek(crypto);
    await store.setVek(crypto, vek2);
    await store.setAek(crypto, aek2);
    final deviceId = await store.ensureDeviceId(crypto);
    vault.devices = [
      DeviceMetadata(
        deviceId: deviceId,
        name: deviceName,
        tier: 'full',
        addedAt: DateTime.now().millisecondsSinceEpoch,
        addedBy: deviceId,
      ),
    ];

    mskKey = newMskKey;
    pendingMsk = null;

    await vault.persist(vek2);
    await client.uploadVault(
      email: email,
      mskKey: newMskKey,
      vault: vault,
      vek: vek2,
      uploadingDevice: deviceId,
    );
  }

  // ---------------------------------------------------------------------
  // Compromise response flows.
  //
  // ARCHITECTURAL NOTE — read before touching any of the six methods below.
  // Several rows say "rotate VEK, re-wrap for all
  // remaining devices." Under this codebase's CKVF model a device's DKEK
  // never leaves that device (Boundary B3) — there is no server-side relay
  // that can hand a fresh VEK/AEK envelope to an arbitrary *other* device
  // without that device's own DKEK doing the wrapping locally. The only
  // built mechanism that delivers VEK/AEK to a specific other device is
  // the live pairing handshake (`beginPairingAsNewDevice`/
  // `confirmPairingRequest`) — one device at a time, requiring the user to
  // physically interact with both devices. There is no broadcast/relay
  // primitive.
  //
  // So every rotation method below does only the part that does NOT require
  // live interaction with other devices: generate new VEK(+AEK), re-wrap
  // *this* (the acting/surviving) device's own local envelope, upload the
  // new vault generation encrypted under the new key(s), and (where the row
  // calls for it) revoke the compromised device immediately (the
  // revocation exemption — no grace period). They do **not** silently claim
  // full propagation happened — the caller (UI) must be told, explicitly,
  // that every other still-trusted device now needs to be re-paired
  // (the pairing flow, run again per device) to receive the fresh envelope.
  // ---------------------------------------------------------------------

  /// Best-effort device revocation shared by the limited-tier and full-tier
  /// compromise flows below. An explicit exemption: revocation itself is never delayed by
  /// a grace period, so this is a direct [PubkeyClient.revokeDevice] call,
  /// not [mutateAndUpload]. Tolerates [ErrorCodes.deviceNotAuthorized] — a
  /// pairing-added device that was never actually present in
  /// `authorized_devices` makes this op frequently a no-op against the one
  /// case it most needs to protect. The real backstop is the VEK/AEK
  /// rotation the caller performs immediately after this — see the
  /// architectural note above.
  Future<void> _bestEffortRevokeDevice({
    required String email,
    required String deviceId,
    required KeyRef msk,
  }) async {
    try {
      await client.revokeDevice(email: email, deviceId: deviceId, mskKey: msk);
    } on PubkeyException catch (e) {
      if (e.code != ErrorCodes.deviceNotAuthorized) rethrow;
    }
  }

  /// Generates a fresh CSPRNG VEK, stages it locally, uploads a new vault
  /// generation encrypted under it, then commits the staged envelope over
  /// the live slot. Staging first means a crash after the server accepts
  /// the upload cannot lose the only copy of the new VEK. A failed upload
  /// leaves the live slot unchanged; leftover pending state is reconciled
  /// by [completePendingEnvelopeRotation] (discarded if the server still
  /// decrypts under the old VEK).
  Future<void> _rotateVek({required String email, required KeyRef msk}) {
    return _withVaultLock(() async {
      if (!vault.unlocked) {
        throw PubkeyException(
          ErrorCodes.vaultLocked,
          'Vault must be unlocked to rotate VEK',
        );
      }
      await _requireCommittedRotation();
      final newVek = KeyHierarchy.generateVek(crypto);
      await store.stagePendingEnvelopeRotation(crypto, vek: newVek);
      vault.updatedAt = DateTime.now().millisecondsSinceEpoch;
      await client.uploadVault(
        email: email,
        mskKey: msk,
        vault: vault,
        vek: newVek,
      );
      await store.commitPendingEnvelopeRotation(crypto);
    });
  }

  /// Generates a fresh CSPRNG AEK, re-wraps the *current* MSK private key
  /// under it inside the vault (the MSK bytes themselves are
  /// unchanged, only the key that wraps them), and uploads under [vek]
  /// (unchanged — this rotates AEK only, not VEK). The new AEK is staged
  /// before upload so a persist failure after the server accepts cannot
  /// drop it. On upload failure, the in-memory `mskEnvelope` re-wrap is
  /// rolled back to the old AEK.
  Future<void> _rotateAek({
    required String email,
    required KeyRef msk,
    required Uint8List vek,
  }) {
    return _withVaultLock(() async {
      await _requireCommittedRotation();
      final newAek = KeyHierarchy.generateAek(crypto);
      final portable = await crypto.exportPrivateKey(msk);
      final oldAek = await store.getAek(crypto);
      await store.stagePendingEnvelopeRotation(crypto, aek: newAek);
      await vault.setMsk(aek: newAek, msk: portable);
      vault.updatedAt = DateTime.now().millisecondsSinceEpoch;
      try {
        await client.uploadVault(
          email: email,
          mskKey: msk,
          vault: vault,
          vek: vek,
        );
      } catch (_) {
        if (oldAek != null) {
          await vault.setMsk(aek: oldAek, msk: portable);
        }
        rethrow;
      }
      await store.commitPendingEnvelopeRotation(crypto);
    });
  }

  /// Rotates both VEK and AEK together as a single atomic upload (one new
  /// generation), for row 2's "rotate both" case. Both new envelopes are
  /// staged as one pending record so they cannot split across a crash.
  Future<void> _rotateVekAndAek({
    required String email,
    required KeyRef msk,
  }) {
    return _withVaultLock(() async {
      if (!vault.unlocked) {
        throw PubkeyException(
          ErrorCodes.vaultLocked,
          'Vault must be unlocked to rotate VEK/AEK',
        );
      }
      await _requireCommittedRotation();
      final newVek = KeyHierarchy.generateVek(crypto);
      final newAek = KeyHierarchy.generateAek(crypto);
      final portable = await crypto.exportPrivateKey(msk);
      final oldAek = await store.getAek(crypto);
      await store.stagePendingEnvelopeRotation(
        crypto,
        vek: newVek,
        aek: newAek,
      );
      await vault.setMsk(aek: newAek, msk: portable);
      vault.updatedAt = DateTime.now().millisecondsSinceEpoch;
      try {
        await client.uploadVault(
          email: email,
          mskKey: msk,
          vault: vault,
          vek: newVek,
        );
      } catch (_) {
        if (oldAek != null) {
          await vault.setMsk(aek: oldAek, msk: portable);
        }
        rethrow;
      }
      await store.commitPendingEnvelopeRotation(crypto);
    });
  }

  /// "One device, limited tier (VEK only)."
  /// Revokes [compromisedDeviceId] immediately (an exemption, best
  /// effort per the note above), rotates VEK, and — only if this identity
  /// actually has a recovery envelope set up — regenerates it
  /// under the new VEK, since the old recovery envelope wrapped the now-
  /// retired VEK and is exactly as compromised as the device that leaked it.
  ///
  /// The regenerated recovery code uses [RecoveryCodeFormats.random] and a
  /// scope matching this acting device's own authority ([RecoveryScopes.full]
  /// if it holds AEK, [RecoveryScopes.readOnly] otherwise) — there is no
  /// server-side record of the *original* setup's format/scope choice (only
  /// existence is queryable, [PubkeyClient.hasRecoveryEnvelope]), so this is
  /// a documented, reasonable default rather than a preserved exact match.
  /// Returns the new plaintext recovery code (via [setupRecoveryCode]'s own
  /// "exactly once, never persisted here" contract) only when a regeneration
  /// actually happened; `null` when this identity never had one.
  Future<LimitedDeviceCompromiseResult> respondToLimitedDeviceCompromise({
    required String email,
    required String compromisedDeviceId,
  }) async {
    final msk = await requireMsk();
    await _bestEffortRevokeDevice(email: email, deviceId: compromisedDeviceId, msk: msk);
    await _rotateVek(email: email, msk: msk);

    String? newRecoveryCode;
    if (await client.hasRecoveryEnvelope(email: email)) {
      final scope =
          await store.isFullAuthority() ? RecoveryScopes.full : RecoveryScopes.readOnly;
      newRecoveryCode = await setupRecoveryCode(
        email: email,
        format: RecoveryCodeFormats.random,
        scope: scope,
      );
    }
    return LimitedDeviceCompromiseResult(newRecoveryCode: newRecoveryCode);
  }

  /// "One device, full tier (VEK + AEK)."
  /// Revokes [compromisedDeviceId] immediately (same best-effort revocation
  /// as row 1), then branches on whether any *other* full-tier device is
  /// still registered in `vault.devices`:
  ///
  /// - If one exists: this acting device (necessarily full-tier itself,
  ///   since [requireMsk] requires AEK) rotates both VEK and AEK
  ///   ([_rotateVekAndAek]) and the result reports
  ///   [FullDeviceCompromiseAction.rotated]. This does not perform the
  ///   spec's literal "AuthorityTransition.type: CONTINUITY" MSK-replacement
  ///   protocol — that mechanism doesn't exist as a built primitive in this
  ///   codebase (only the OTP/RECOVERY path does); flagged as an explicitly
  ///   out-of-scope follow-up.
  /// - If none exists (this was the identity's only full-tier device): no
  ///   rotation is attempted — there is no other authority-holding device to
  ///   rotate *for*, and the MSK itself must be treated as compromised (a
  ///   full-tier device holds both VEK and AEK, i.e. everything needed to
  ///   extract the raw MSK). The result reports
  ///   [FullDeviceCompromiseAction.requiresOtpOnlyRecovery] with a
  ///   human-readable [FullDeviceCompromiseResult.message] — the caller must
  ///   route the user through the existing OTP-only recovery UI
  ///   ([completeOtpOnlyRecovery]), which this method does not invoke
  ///   directly since it needs a [KeyRef] produced by a live OTP-verify step
  ///   only the host app's UI/bootstrap layer can obtain.
  Future<FullDeviceCompromiseResult> respondToFullDeviceCompromise({
    required String email,
    required String compromisedDeviceId,
  }) async {
    final msk = await requireMsk();
    await _bestEffortRevokeDevice(email: email, deviceId: compromisedDeviceId, msk: msk);

    final otherFullDevices = vault.devices.where(
      (d) => d.tier == 'full' && d.deviceId != compromisedDeviceId,
    );
    if (otherFullDevices.isEmpty) {
      return const FullDeviceCompromiseResult(
        action: FullDeviceCompromiseAction.requiresOtpOnlyRecovery,
        message: 'This was the identity\'s only full-authority device. '
            'VEK/AEK rotation alone cannot restore trust in the Master '
            'Signing Key itself — the device was revoked, but you must now '
            'complete OTP-only identity recovery to '
            'establish a fresh, uncompromised MSK generation.',
      );
    }

    await _rotateVekAndAek(email: email, msk: msk);
    return const FullDeviceCompromiseResult(action: FullDeviceCompromiseAction.rotated);
  }

  /// "VEK only (raw key leaked some other way,
  /// devices intact)." Rotates VEK ([rotateVekOnly]) and separately revokes
  /// and replaces every entry in [exposedKeyReplacements] (key id -> the
  /// pre-built `active` replacement entry) via [revokeAndReplaceKey] — the
  /// spec's "treat any individual keys that were plaintext-visible during
  /// the exposure window as separately compromised... mark old ones
  /// `revoked` not `historical`." An empty map is valid (VEK-only exposure
  /// with no specific key known to have been read).
  Future<void> respondToLeakedVek({
    required String email,
    Map<int, VaultEntry> exposedKeyReplacements = const {},
  }) async {
    await rotateVekOnly(email: email);
    for (final exposed in exposedKeyReplacements.entries) {
      await revokeAndReplaceKey(
        email: email,
        compromisedKeyId: exposed.key,
        replacement: exposed.value,
      );
    }
  }

  /// Shared VEK-only rotation core, used directly by row 3
  /// ([respondToLeakedVek]) and row 5 ([rotateVekForServerBreach]) — both
  /// rows require nothing beyond "rotate VEK, re-wrap for this device, all
  /// other devices must re-pair" (see the architectural note above). Not
  /// grace-gated (VEK rotation is not among the high-risk
  /// mutation kinds — mirrors `rotateSigningKey`'s precedent of only
  /// declaring `mutationKind` for kinds that are actually listed).
  Future<void> rotateVekOnly({required String email}) async {
    final msk = await requireMsk();
    await _rotateVek(email: email, msk: msk);
  }

  /// "AEK (identity impersonation risk)."
  /// [requireMsk] itself already requires this acting device to hold AEK, so
  /// the `if (!isFullAuthority())` branch below is structurally unreachable
  /// from this call path — it is kept anyway, matching row 4's own literal
  /// "if a trusted full-tier device remains... if none remains" wording.
  ///
  /// **Same narrower interpretation as row 2, for the same reason**: the
  /// spec's literal remedy requires a CONTINUITY/REVOCATION-signed
  /// MSK-replacement primitive that does not exist in this codebase (only
  /// the OTP/RECOVERY path does). This method rotates AEK only — re-wrapping
  /// the *existing* MSK under a fresh AEK, which invalidates every
  /// previously-exfiltrated AEK envelope's usefulness against future vault
  /// generations — and does **not** attempt to build a new MSK-replacement
  /// protocol. Flagged as an explicitly out-of-scope follow-up, exactly like
  /// row 2.
  Future<AekCompromiseResult> respondToAekCompromise({required String email}) async {
    final msk = await requireMsk();
    if (!(await store.isFullAuthority())) {
      return const AekCompromiseResult(
        action: AekCompromiseAction.requiresOtpOnlyRecovery,
        message: 'No trusted full-authority device remains to sign a new '
            'AEK. Complete OTP-only identity recovery '
            'instead.',
      );
    }
    final vek = await store.getVek(crypto);
    if (vek == null) {
      throw PubkeyException(
        ErrorCodes.masterKeyNotArmed,
        'This device has no Vault Encryption Key',
      );
    }
    await _rotateAek(email: email, msk: msk, vek: vek);
    return const AekCompromiseResult(action: AekCompromiseAction.rotated);
  }

  /// "Server data breach." Implements only the
  /// precautionary VEK-rotation mechanic — the "mandatory audit of
  /// signature-verification code paths" deliverable is a process/review
  /// artifact, not code. A thin, separately-named wrapper around
  /// [rotateVekOnly] so this row still has its own explicit, separately
  /// testable entry point, even though its mechanics are identical to row
  /// 3's.
  Future<void> rotateVekForServerBreach({required String email}) {
    return rotateVekOnly(email: email);
  }

  /// "Single PGP/S-MIME/signing key." Marks
  /// [compromisedKeyId] `status: 'revoked'` (via [Vault.revokeKey] — a
  /// genuinely different terminal state from [Vault.retireKey]'s
  /// `'retired'`/spec-`'historical'`), then adds [replacement] (forced to
  /// `status: 'active'`) through the normal vault-mediated
  /// [mutateAndUpload] path — never a direct server-side pointer update, per
  /// the spec's own closing clause for this row.
  ///
  /// Deliberately does **not** advertise [replacement] to new senders:
  /// the policy ("never automatic, only after explicit user
  /// confirmation") is not overridden by this row — advertising a PGP
  /// encryption replacement still requires the separate
  /// [promoteEncryptionKeyPointer]/host-app confirmation step, called by the
  /// UI afterward if/when the user chooses to.
  Future<void> revokeAndReplaceKey({
    required String email,
    required int compromisedKeyId,
    required VaultEntry replacement,
  }) async {
    replacement.status = 'active';
    await mutateAndUpload(
      email: email,
      mutation: (v) {
        final revoked = v.revokeKey(compromisedKeyId);
        if (revoked == null) {
          throw PubkeyException(
            ErrorCodes.keyNotFound,
            'No key with id $compromisedKeyId in this vault',
          );
        }
        v.addKey(replacement);
      },
    );
  }
}

/// Result of [PubkeyRuntime.respondToLimitedDeviceCompromise].
class LimitedDeviceCompromiseResult {
  const LimitedDeviceCompromiseResult({this.newRecoveryCode});

  /// The freshly regenerated recovery code, shown to the user exactly once
  /// (same contract as [PubkeyRuntime.setupRecoveryCode]) — `null` when this
  /// identity had no recovery envelope to begin with (nothing regenerated).
  final String? newRecoveryCode;
}

/// What [PubkeyRuntime.respondToFullDeviceCompromise]
/// actually did — see that method's doc comment for the full reasoning
/// behind each branch.
enum FullDeviceCompromiseAction { rotated, requiresOtpOnlyRecovery }

class FullDeviceCompromiseResult {
  const FullDeviceCompromiseResult({required this.action, this.message});

  final FullDeviceCompromiseAction action;

  /// Human-readable explanation, only set for
  /// [FullDeviceCompromiseAction.requiresOtpOnlyRecovery] — the UI should
  /// show this and route to the existing OTP-only recovery flow.
  final String? message;
}

/// What [PubkeyRuntime.respondToAekCompromise] actually
/// did — see that method's doc comment for the full reasoning.
enum AekCompromiseAction { rotated, requiresOtpOnlyRecovery }

class AekCompromiseResult {
  const AekCompromiseResult({required this.action, this.message});

  final AekCompromiseAction action;
  final String? message;
}

/// Builds a [PubkeyRuntime] for [email]. [store] defaults to a pure-Dart,
/// in-memory [MemoryDeviceKeyStore] — enough to run standalone (tests, a
/// demo app). A host app that needs persistent, platform-backed storage
/// (e.g. secure storage) should provide its own [DeviceKeyStore] here, or
/// override [PubkeyRuntime.factory] once at startup so every call to
/// [PubkeyRuntime.instance] picks it up automatically.
///
/// [readBaseUrl]/[writeBaseUrl] use [PubkeyConfig]'s compile-time hosts when
/// omitted. Missing hosts fail closed (no default live origin).
PubkeyRuntime createPubkeyRuntime(
  String email, {
  Dio? dio,
  DeviceKeyStore? store,
  String? readBaseUrl,
  String? writeBaseUrl,
  bool rfc9980Ready = true,
}) {
  final crypto = DartCryptoProvider();
  final resolvedStore = store ?? MemoryDeviceKeyStore();
  final vault = Vault(crypto: crypto, store: resolvedStore);
  final pgp = DelegatingPgpEngine(
    advertisedAlgorithms: OpenPgpAlgorithms.advertised(
      rfc9980Ready: rfc9980Ready,
    ),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final smime = DelegatingSmimeEngine(
    advertisedAlgorithms: SmimeAlgorithms.advertised(pqcReady: rfc9980Ready),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final client = PubkeyClient(
    crypto: crypto,
    vault: vault,
    pgpEngine: pgp,
    smimeEngine: smime,
    readBaseUrl: readBaseUrl,
    writeBaseUrl: writeBaseUrl,
    dio: dio,
  );
  return PubkeyRuntime._(
    accountEmail: email,
    crypto: crypto,
    vault: vault,
    store: resolvedStore,
    client: client,
  );
}

Never _engineUnused() {
  throw PubkeyException(
    ErrorCodes.unsupportedAlgorithm,
    'Mail encrypt/decrypt uses a dedicated OpenPGP engine, not the Pubkey engine facade',
  );
}

Future<List<int>> _unsupportedEncrypt({
  required List<int> plaintext,
  required List<int> recipientPublicKey,
  String? algorithm,
}) async =>
    _engineUnused();

Future<List<int>> _unsupportedDecrypt({
  required List<int> ciphertext,
  required List<int> privateKey,
  String? algorithm,
}) async =>
    _engineUnused();

/// Builds a [PubkeyClient] wired to [email]'s cached [PubkeyRuntime].
PubkeyClient createPubkeyClient(String email) =>
    PubkeyRuntime.instance(email: email).client;

/// Builds an account-agnostic [PubkeyClient] for read-only directory lookups
/// (e.g. looking up a recipient's public key). Never sign or publish with
/// this client — it has no Vault/MSK, so use [createPubkeyClient] for any
/// operation scoped to the signed-in account's own identity.
PubkeyClient createDiscoveryPubkeyClient({
  String? readBaseUrl,
  String? writeBaseUrl,
  bool rfc9980Ready = true,
}) {
  final crypto = DartCryptoProvider();
  final pgp = DelegatingPgpEngine(
    advertisedAlgorithms: OpenPgpAlgorithms.advertised(
      rfc9980Ready: rfc9980Ready,
    ),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  final smime = DelegatingSmimeEngine(
    advertisedAlgorithms: SmimeAlgorithms.advertised(pqcReady: rfc9980Ready),
    encrypt: _unsupportedEncrypt,
    decrypt: _unsupportedDecrypt,
  );
  return PubkeyClient(
    crypto: crypto,
    pgpEngine: pgp,
    smimeEngine: smime,
    readBaseUrl: readBaseUrl,
    writeBaseUrl: writeBaseUrl,
  );
}
