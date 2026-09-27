import 'dart:math';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart' show PepperOprf;

import 'authorization.dart';
import 'errors.dart';
import 'oprf/poprf.dart';
import 'vault_host_client.dart';

/// `PepperOprf` for `package:ckvf` slot APIs, backed by
/// `POST /v1/pw-oprf/evaluate` with proof verification.
class HostPepperOprf implements PepperOprf {
  HostPepperOprf(this.client, this.authorization, {Random? random})
      : _random = random;

  final VaultHostClient client;

  /// Read authorization for the vault (usually an `oprf_token`).
  final VaultAuthorization authorization;
  final Random? _random;

  @override
  Future<Uint8List> finalize({
    required String vaultId,
    required String slotId,
    required String kid,
    required Uint8List publicKey,
    required Uint8List secret,
  }) async {
    final state = poprfBlind(
      secret,
      pepperInfo(vaultId, slotId),
      publicKey,
      random: _random,
    );
    final evaluation = await client.evaluatePepper(
      vaultId: vaultId,
      slotId: slotId,
      kid: kid,
      blinded: state.blinded,
      authorization: authorization,
    );
    if (evaluation.kid != kid) {
      throw VaultClientException(
        'invalid_evaluation',
        'the vault host answered with kid ${evaluation.kid}, not $kid',
      );
    }
    return poprfFinalize(state, evaluation.evaluated, evaluation.proof);
  }
}
