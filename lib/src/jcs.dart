import 'package:ckvf/ckvf.dart' as ckvf;

/// RFC 8785 JSON Canonicalization Scheme for protocol payloads.
///
/// Delegates to `package:ckvf`'s spec-conformant implementation instead of
/// duplicating it, while preserving this package's own exception contract:
/// callers here have always expected [ArgumentError] on malformed input,
/// where `ckvf` reports it as `CkvfException`.
String canonicalizeJson(Object? value) {
  try {
    return ckvf.jcs(value);
  } on ckvf.CkvfException catch (e) {
    throw ArgumentError(e.message ?? e.code);
  }
}
