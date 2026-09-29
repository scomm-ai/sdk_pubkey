import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Vault principal: lowercase hex SHA-256 of the canonical mailbox.
/// Callers pass the same canonical form Discovery uses.
String mailboxIdentityId(String canonicalMailbox) {
  return sha256.convert(utf8.encode(canonicalMailbox)).toString();
}
