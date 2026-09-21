import '../constants.dart';
import '../errors.dart';
import 'dart_crypto.dart';
import 'provider.dart';

/// Central provider discovery. Protocol code must not branch on platform names.
class CryptoProviderRegistry {
  CryptoProviderRegistry([Iterable<CryptoProvider> providers = const []])
      : _providers = [...providers];

  final List<CryptoProvider> _providers;

  void register(CryptoProvider provider) => _providers.add(provider);

  List<CryptoProvider> discover() => List<CryptoProvider>.from(_providers);

  Future<List<CryptoCapabilities>> capabilities() {
    return Future.wait(_providers.map((provider) => provider.capabilities()));
  }

  CryptoProvider _prefer(List<CryptoProvider> providers) {
    return providers.firstWhere(
      (provider) => provider.kind == 'platform',
      orElse: () => providers.first,
    );
  }

  Future<CryptoProvider> select({
    required String operation,
    required String algorithm,
    String? protection,
    bool? extractable,
    String? purpose,
    String protectionLevel = RequirementLevels.preferred,
  }) async {
    final matching = <CryptoProvider>[];
    for (final provider in _providers) {
      if (await provider.supports(
        operation,
        algorithm,
        extractable: extractable,
        protection: protection,
        purpose: purpose,
      )) {
        matching.add(provider);
      }
    }
    if (matching.isNotEmpty) {
      return _prefer(matching);
    }

    if (protection != null && protectionLevel == RequirementLevels.required) {
      final hardware = protection == KeyProtection.hardwareBacked ||
          protection == KeyProtection.osProtected;
      throw PubkeyException(
        hardware
            ? ErrorCodes.hardwareProtectionUnavailable
            : ErrorCodes.providerUnavailable,
        'No provider satisfies $operation/$algorithm with $protection',
      );
    }

    if (protection != null) {
      final relaxed = <CryptoProvider>[];
      for (final provider in _providers) {
        if (await provider.supports(
          operation,
          algorithm,
          extractable: extractable,
          purpose: purpose,
        )) {
          relaxed.add(provider);
        }
      }
      if (relaxed.isNotEmpty) {
        return _prefer(relaxed);
      }
    }

    throw PubkeyException(
      ErrorCodes.providerUnavailable,
      'No provider supports $operation/$algorithm',
    );
  }
}

/// Software fallback only. Hosts register a [NativeCryptoProvider] when one exists.
CryptoProviderRegistry createDefaultDartRegistry([
  List<CryptoProvider>? providers,
]) {
  return CryptoProviderRegistry(providers ?? [DartCryptoProvider()]);
}
