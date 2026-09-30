import 'constants.dart';

/// Operation capabilities derived from lifecycle and whether private material
/// is still present. These are not a single usable flag.
class KeyCapabilities {
  const KeyCapabilities({
    required this.canSignNow,
    required this.canVerify,
    required this.canEncryptNow,
    required this.canDecrypt,
  });

  final bool canSignNow;
  final bool canVerify;
  final bool canEncryptNow;
  final bool canDecrypt;
}

/// [purpose] is `signing` or `encryption`. [lifecycle] is `created`, `active`,
/// `retired`, or `revoked`. CKVF `compromised` is treated as `revoked`.
KeyCapabilities keyCapabilities({
  required String purpose,
  required String lifecycle,
  required bool hasPrivateMaterial,
  required bool hasPublicMaterial,
}) {
  final life = lifecycle == 'compromised'
      ? KeyGenerationStatus.revoked
      : lifecycle;
  final signing = purpose == 'signing' || purpose == 'sign' || purpose == 'verify';
  if (signing) {
    return KeyCapabilities(
      canSignNow: life == KeyGenerationStatus.active && hasPrivateMaterial,
      canVerify: hasPublicMaterial && life != KeyGenerationStatus.created,
      canEncryptNow: false,
      canDecrypt: false,
    );
  }
  final operational = life == KeyGenerationStatus.active ||
      life == KeyGenerationStatus.retired ||
      life == KeyGenerationStatus.revoked;
  return KeyCapabilities(
    canSignNow: false,
    canVerify: false,
    canEncryptNow: life == KeyGenerationStatus.active && hasPublicMaterial,
    canDecrypt: operational && hasPrivateMaterial,
  );
}
