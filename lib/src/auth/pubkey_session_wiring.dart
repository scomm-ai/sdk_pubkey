import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';

import '../models/key_list_item.dart';
import 'pubkey_session.dart';

/// Session helpers after OTP, list, or upload.
extension PubkeySessionWiring on PubkeySession {
  /// Picks an active signing key from [keys] for signed HTTP auth.
  PubkeySession withSigningKeyFromList(
    List<KeyListItem> keys, {
    String? preferKeyId,
  }) {
    if (keys.isEmpty) return this;

    KeyListItem? pick;
    if (preferKeyId != null) {
      for (final k in keys) {
        if (k.keyId == preferKeyId && _isSigningCandidate(k)) {
          pick = k;
          break;
        }
      }
    }
    pick ??= keys.firstWhere(
      (k) => k.isPreferred && _isSigningCandidate(k),
      orElse: () => keys.firstWhere(
        _isSigningCandidate,
        orElse: () => keys.first,
      ),
    );

    return copyWith(
      signingKeyId: pick.keyId,
      sigFamily: PubkeyKeyMapper.sigFamilyForCatalog(pick.algorithm),
    );
  }

  PubkeySession applyUploadResult(Map<String, dynamic> result) {
    final keyId = result['keyId']?.toString();
    if (keyId == null || keyId.isEmpty) return this;
    return copyWith(signingKeyId: keyId);
  }
}

bool _isSigningCandidate(KeyListItem item) {
  if (item.status != 'active') return false;
  return PubkeyAlgorithmCatalog.supportsSelfSignatureUpload(item.algorithm) ||
      item.algorithm.startsWith('openpgp-') ||
      item.algorithm.startsWith('pqc-') ||
      item.algorithm == PubkeyAlgorithmNames.smimeRsaSha256;
}
