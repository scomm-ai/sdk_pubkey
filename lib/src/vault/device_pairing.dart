import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import '../canonical.dart';
import '../crypto/provider.dart';
import '../errors.dart';
import '../identity.dart';
import 'key_hierarchy.dart';

const String pairingCpaceSidInfo = 'SComm/Pubkey/pairing/cpace/v2';
const String pairingTekHkdfInfoV1 = 'SComm/Pubkey/pairing/tek/v1';
const String pairingTekHkdfInfoV2 = 'SComm/Pubkey/pairing/tek/v2';
const String pairingTranscriptHeader = 'SComm/Pubkey/pairing/transcript/v2';
const String pairingConfirmPlaintext = 'SComm/Pubkey/pairing/confirm/v2';
const String pairingUriScheme = 'scomm-pair';
const String pairingUriVersion = 'v2';

const int pairingSessionIdBytes = 16;
const int pairingHighEntropyPasswordBytes = 16;
const int pairingTypedPasswordLength = 16;
const int pairingPakeElementBytes = 32;

const String _crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

enum PairingSecretMode { highEntropy, typed }

class PairingTransfer {
  const PairingTransfer({required this.vek, this.aek});

  final Uint8List vek;
  final Uint8List? aek;
}

class PairingTransferEnvelopes {
  const PairingTransferEnvelopes({required this.vekEnvelope, this.aekEnvelope});

  final WrappedKey vekEnvelope;
  final WrappedKey? aekEnvelope;
}

enum PairingSessionState { pending, responded, completed }

PairingSessionState _stateFromWire(String? value) {
  switch (value) {
    case 'PENDING':
      return PairingSessionState.pending;
    case 'RESPONDED':
      return PairingSessionState.responded;
    case 'COMPLETED':
      return PairingSessionState.completed;
    default:
      throw PubkeyException(
        ErrorCodes.vaultCorrupt,
        'Unknown pairing session state: $value',
      );
  }
}

class PairingSessionStatus {
  const PairingSessionStatus({
    required this.sessionId,
    required this.state,
    this.deviceName,
    this.requestedTier,
    this.bPakeElement,
    this.deviceId,
    this.aPakeElement,
    this.vekEnvelope,
    this.aekEnvelope,
    this.confirmationTag,
    this.mskSignature,
  });

  final String sessionId;
  final PairingSessionState state;
  final String? deviceName;
  final String? requestedTier;
  final Uint8List? bPakeElement;
  final String? deviceId;
  final Uint8List? aPakeElement;
  final WrappedKey? vekEnvelope;
  final WrappedKey? aekEnvelope;
  final WrappedKey? confirmationTag;
  final Uint8List? mskSignature;

  factory PairingSessionStatus.fromJson(Map<String, dynamic> json) {
    if (json.containsKey('b_ephemeral_public_key') ||
        json.containsKey('a_ephemeral_public_key')) {
      throw PubkeyException(
        ErrorCodes.pairingProtocolUnsupported,
        'Pairing mailbox spoke v1 ECDH fields; current clients require CPace v2',
      );
    }
    final state = _stateFromWire(json['state'] as String?);
    final bKey = json['b_pake_element'];
    final aKey = json['a_pake_element'];
    final vekEnvelopeRaw = json['vek_envelope'];
    final aekEnvelopeRaw = json['aek_envelope'];
    final tagRaw = json['confirmation_tag'];
    final sigRaw = json['msk_signature'];
    return PairingSessionStatus(
      sessionId: json['session_id'] as String,
      state: state,
      deviceName: json['device_name'] as String?,
      requestedTier: json['requested_tier'] as String?,
      bPakeElement: bKey is String ? decodeBase64Url(bKey) : null,
      deviceId: json['device_id'] as String?,
      aPakeElement: aKey is String ? decodeBase64Url(aKey) : null,
      vekEnvelope: vekEnvelopeRaw is Map
          ? WrappedKey.fromJson(Map<String, dynamic>.from(vekEnvelopeRaw))
          : null,
      aekEnvelope: aekEnvelopeRaw is Map
          ? WrappedKey.fromJson(Map<String, dynamic>.from(aekEnvelopeRaw))
          : null,
      confirmationTag: tagRaw is Map
          ? WrappedKey.fromJson(Map<String, dynamic>.from(tagRaw))
          : null,
      mskSignature: sigRaw is String ? decodeBase64Url(sigRaw) : null,
    );
  }
}

class PairingUri {
  const PairingUri({required this.sessionId, required this.password});

  final String sessionId;
  final Uint8List password;

  String toUriString() =>
      '$pairingUriScheme:$pairingUriVersion?sid=${Uri.encodeQueryComponent(sessionId)}'
      '&pw=${Uri.encodeQueryComponent(encodeBase64Url(password))}';

  static PairingUri? tryParse(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty) return null;
    final uri = Uri.parse(trimmed);
    if (uri.scheme != pairingUriScheme) return null;
    if (uri.path != pairingUriVersion && uri.host != pairingUriVersion) {
      final version = uri.path.isNotEmpty ? uri.path : uri.host;
      if (version != pairingUriVersion) return null;
    }
    final sid = uri.queryParameters['sid'];
    final pw = uri.queryParameters['pw'];
    if (sid == null || sid.isEmpty || pw == null || pw.isEmpty) return null;
    final password = decodeBase64Url(pw);
    if (password.length < pairingHighEntropyPasswordBytes) return null;
    return PairingUri(sessionId: sid, password: password);
  }
}

abstract final class DevicePairing {
  static String generateSessionId(CryptoProvider crypto) {
    return bytesToHex(crypto.random(pairingSessionIdBytes));
  }

  /// @Deprecated 8-character locator is not a CPace password.
  static String generateSessionCode(CryptoProvider crypto) {
    return _crockford(crypto.random(5), 8);
  }

  static Uint8List generateHighEntropyPassword(CryptoProvider crypto) {
    return crypto.random(pairingHighEntropyPasswordBytes);
  }

  static String generateTypedPassword(CryptoProvider crypto) {
    return _crockford(crypto.random(10), pairingTypedPasswordLength);
  }

  static Uint8List typedPasswordBytes(String typed) {
    final normalized = typed.trim().toUpperCase();
    if (normalized.length != pairingTypedPasswordLength) {
      throw PubkeyException(
        ErrorCodes.pairingPasswordMismatch,
        'Typed pairing password must be $pairingTypedPasswordLength Crockford characters',
      );
    }
    for (final ch in normalized.split('')) {
      if (!_crockfordAlphabet.contains(ch)) {
        throw PubkeyException(
          ErrorCodes.pairingPasswordMismatch,
          'Typed pairing password uses invalid characters',
        );
      }
    }
    return Uint8List.fromList(utf8.encode(normalized));
  }

  static Uint8List pairingSid({
    required String sessionId,
    required String identityLocator,
    required String requestedTier,
  }) {
    final material = BytesBuilder(copy: false)
      ..add(utf8.encode(pairingCpaceSidInfo))
      ..addByte(0)
      ..add(utf8.encode(sessionId))
      ..addByte(0)
      ..add(utf8.encode(identityLocator))
      ..addByte(0)
      ..add(utf8.encode(requestedTier));
    return Uint8List.fromList(crypto.sha256.convert(material.toBytes()).bytes);
  }

  static Uint8List pairingCi(String identityLocator) =>
      Uint8List.fromList(utf8.encode(identityLocator));

  static Uint8List tekHkdfInfo({
    required String sessionId,
    required Uint8List ya,
    required Uint8List yb,
    required String identityLocator,
    required String requestedTier,
  }) {
    return Uint8List.fromList([
      ...utf8.encode(pairingTekHkdfInfoV2),
      ...utf8.encode(sessionId),
      ...ya,
      ...yb,
      ...utf8.encode(identityLocator),
      ...utf8.encode(requestedTier),
      ...utf8.encode('v2'),
    ]);
  }

  static Future<Uint8List> deriveTekV2(
    CryptoProvider crypto,
    Uint8List isk, {
    required String sessionId,
    required Uint8List ya,
    required Uint8List yb,
    required String identityLocator,
    required String requestedTier,
  }) {
    return crypto.hkdfSha256(
      isk,
      tekHkdfInfo(
        sessionId: sessionId,
        ya: ya,
        yb: yb,
        identityLocator: identityLocator,
        requestedTier: requestedTier,
      ),
      length: dkekKeyLengthBytes,
    );
  }

  static Never refuseV1Tek() {
    throw PubkeyException(
      ErrorCodes.pairingProtocolUnsupported,
      'Unauthenticated ECDH pairing (tek/v1) is not supported',
    );
  }

  static String confirmationTagWire(WrappedKey tag) =>
      encodeBase64Url(Uint8List.fromList([...tag.iv, ...tag.ciphertext]));

  static Uint8List canonicalTranscript({
    required String sessionId,
    required String identityLocator,
    required String requestedTier,
    required Uint8List ya,
    required Uint8List yb,
    required WrappedKey confirmationTag,
  }) {
    return Uint8List.fromList(utf8.encode(
      '$pairingTranscriptHeader\n'
      'session_id=$sessionId\n'
      'identity=$identityLocator\n'
      'requested_tier=$requestedTier\n'
      'ya=${encodeBase64Url(ya)}\n'
      'yb=${encodeBase64Url(yb)}\n'
      'confirmation_tag=${confirmationTagWire(confirmationTag)}\n',
    ));
  }

  static Future<PairingTransferEnvelopes> wrapForTransfer(
    CryptoProvider crypto,
    Uint8List tek,
    Uint8List vek, [
    Uint8List? aek,
  ]) async {
    final wrappedVek = await crypto.encryptAead(tek, vek);
    WrappedKey? wrappedAek;
    if (aek != null) {
      final w = await crypto.encryptAead(tek, aek);
      wrappedAek = WrappedKey(iv: w.iv, ciphertext: w.ciphertext);
    }
    return PairingTransferEnvelopes(
      vekEnvelope:
          WrappedKey(iv: wrappedVek.iv, ciphertext: wrappedVek.ciphertext),
      aekEnvelope: wrappedAek,
    );
  }

  static Future<PairingTransfer> unwrapTransfer(
    CryptoProvider crypto,
    Uint8List tek,
    WrappedKey vekEnvelope, [
    WrappedKey? aekEnvelope,
  ]) async {
    Uint8List vek;
    try {
      vek = await crypto.decryptAead(
        tek,
        vekEnvelope.iv,
        vekEnvelope.ciphertext,
      );
    } catch (_) {
      throw PubkeyException(
        ErrorCodes.envelopeAuthenticationFailure,
        'Failed to unwrap pairing transfer envelope (VEK): wrong TEK or tampering',
      );
    }
    Uint8List? aek;
    if (aekEnvelope != null) {
      try {
        aek = await crypto.decryptAead(
          tek,
          aekEnvelope.iv,
          aekEnvelope.ciphertext,
        );
      } catch (_) {
        throw PubkeyException(
          ErrorCodes.envelopeAuthenticationFailure,
          'Failed to unwrap pairing transfer envelope (AEK): wrong TEK or tampering',
        );
      }
    }
    return PairingTransfer(vek: vek, aek: aek);
  }

  static String _crockford(Uint8List bytes, int length) {
    var bitBuffer = 0;
    var bitsInBuffer = 0;
    var byteIndex = 0;
    final buffer = StringBuffer();
    while (buffer.length < length) {
      if (bitsInBuffer < 5) {
        bitBuffer = (bitBuffer << 8) | bytes[byteIndex++];
        bitsInBuffer += 8;
      }
      final shift = bitsInBuffer - 5;
      final index = (bitBuffer >> shift) & 0x1f;
      buffer.write(_crockfordAlphabet[index]);
      bitsInBuffer -= 5;
    }
    return buffer.toString();
  }
}
