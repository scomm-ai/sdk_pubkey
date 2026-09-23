import '../errors.dart';

/// Cached OPRF identity and random vault locator. Never includes a mailbox.
class IdentityBinding {
  const IdentityBinding({this.identityId, this.vaultId});

  final String? identityId;
  final String? vaultId;

  bool get hasIdentity => identityId != null && identityId!.length == 64;
}

void assertNoMailboxAddress({required String url, Object? body}) {
  if (url.contains('@')) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'Pubkey URL must not contain a mailbox address',
    );
  }
  if (body is! Map) return;
  for (final key in const {'email', 'address', 'mailbox', 'rfc5322'}) {
    if (body.containsKey(key)) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Pubkey request must not include $key',
      );
    }
  }
}

/// Discovery may carry `sha256`. It must not carry an address.
void assertDiscoveryWire({required String url, Object? body}) {
  assertNoMailboxAddress(url: url, body: body);
}

/// Vault/MSK/pairing must not carry an address or a directory hash.
void assertVaultWire({required String url, Object? body}) {
  assertNoMailboxAddress(url: url, body: body);
  if (body is! Map) return;
  for (final key in const {'sha256', 'email_sha256', 'mailboxSha256'}) {
    if (body.containsKey(key)) {
      throw PubkeyException(
        ErrorCodes.invalidRequest,
        'Vault request must not include $key',
      );
    }
  }
}

/// @deprecated Use [assertDiscoveryWire] or [assertVaultWire].
void assertPubkeyWireHasNoMailbox({required String url, Object? body}) {
  assertNoMailboxAddress(url: url, body: body);
}

final _hex64 = RegExp(r'^[0-9a-f]{64}$');

void requireIdentityId(String identityId) {
  if (!_hex64.hasMatch(identityId)) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'identity_id must be 64 lowercase hex characters',
    );
  }
}

void requireMailboxSha256(String sha256) {
  if (!_hex64.hasMatch(sha256)) {
    throw PubkeyException(
      ErrorCodes.invalidRequest,
      'mailboxSha256 must be 64 lowercase hex characters',
    );
  }
}
