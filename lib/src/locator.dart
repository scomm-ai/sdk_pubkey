const int openPgpLocatorHexLen = 16;
const String keyPackageKind = 'scomm-key-package';
const int keyPackageVersion = 1;
const int vaultWrapVersionV1 = 1;

String normalizeHex(String? value) {
  return (value ?? '')
      .replaceFirst(RegExp(r'^0x', caseSensitive: false), '')
      .replaceAll(RegExp(r'[^0-9A-Fa-f]'), '')
      .toUpperCase();
}

/// OpenPGP 64-bit Key-ID display: AB12-CD34-EF56-7890.
String formatOpenPgpLocator(String? value) {
  var hex = normalizeHex(value);
  if (hex.length > openPgpLocatorHexLen) {
    hex = hex.substring(hex.length - openPgpLocatorHexLen);
  }
  if (hex.length != openPgpLocatorHexLen) return hex;
  return [
    hex.substring(0, 4),
    hex.substring(4, 8),
    hex.substring(8, 12),
    hex.substring(12, 16),
  ].join('-');
}

String formatSmimeLocator(String? value) => normalizeHex(value);

String formatLocator(String? family, String? value) {
  if (family == 'pgp') return formatOpenPgpLocator(value);
  return formatSmimeLocator(value);
}
