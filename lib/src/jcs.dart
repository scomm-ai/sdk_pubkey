import 'dart:convert';

import 'native_vault.dart';

/// RFC 8785 JSON Canonicalization Scheme for protocol payloads.
///
/// The CKVF Rust library performs the canonicalization. Callers still see
/// [ArgumentError] when the value cannot be encoded.
String canonicalizeJson(Object? value) {
  try {
    return ScommVault.jcs(jsonEncode(value));
  } on ArgumentError {
    rethrow;
  } catch (e) {
    throw ArgumentError(e.toString());
  }
}
