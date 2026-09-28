import 'package:ckvf/ckvf.dart';

/// RFC 8785 JSON Canonicalization Scheme for protocol payloads.
///
/// Callers still see [ArgumentError] when the value cannot be encoded.
String canonicalizeJson(Object? value) {
  try {
    return jcs(value);
  } on CkvfException catch (e) {
    throw ArgumentError(e.toString());
  }
}
