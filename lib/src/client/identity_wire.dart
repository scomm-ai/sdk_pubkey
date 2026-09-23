import '../errors.dart';

/// Cached OPRF identity and random vault locator. Never includes a mailbox.
class IdentityBinding {
  const IdentityBinding({this.identityId, this.vaultId});

  final String? identityId;
  final String? vaultId;

  bool get hasIdentity => identityId != null && identityId!.length == 64;
}

/// Throws when a pubkey request would carry a mailbox address or an
/// unsalted email digest.
void assertPubkeyWireHasNoMailbox({
  required String url,
  Object? body,
}) {
  if (url.contains('@')) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'Pubkey URL must not contain a mailbox address',
    );
  }
  if (body is! Map) return;
  const denied = {
    'email',
    'address',
    'mailbox',
    'rfc5322',
    'email_sha256',
    'sha256',
  };
  for (final key in denied) {
    if (body.containsKey(key)) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Pubkey request must not include $key',
      );
    }
  }
}

final _identityIdPattern = RegExp(r'^[0-9a-f]{64}$');

void requireIdentityId(String identityId) {
  if (!_identityIdPattern.hasMatch(identityId)) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'identity_id must be 64 lowercase hex characters',
    );
  }
}
