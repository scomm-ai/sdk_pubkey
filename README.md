# secmail_pubkey_sdk

High-level Dart SDK for the [scomm-ai/pubkey](https://github.com/scomm-ai/pubkey) server API.

Cryptographic operations (sign, encrypt, keygen) are delegated to **`secmail_crypto_sdk`** (`../../fl-start/crypto`). This package owns all **dio** HTTP traffic.

## Hosts (compile-time)

| Define | Default | Server role |
|--------|---------|-------------|
| `PUBKEY_READ_BASE_URL` | `https://pubkey.scomm.ai` | `npm run start:read` (GET) |
| `PUBKEY_WRITE_BASE_URL` | `https://api.pubkey.scomm.ai` | `npm run start:write` (POST/…) |

```bash
dart run --define=PUBKEY_READ_BASE_URL=http://localhost:3001 \
         --define=PUBKEY_WRITE_BASE_URL=http://localhost:3002 \
         example/health_check.dart
```

## Quick start

```dart
import 'package:secmail_crypto_sdk/secmail_crypto_sdk.dart';
import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';

Future<void> main() async {
  final crypto = CryptoSdk.initialize();
  final pubkey = PubkeyClient(crypto: crypto);

  final check = await pubkey.checkAccount('alice@example.com');
  print(check.known);

  await pubkey.sendOtp('alice@example.com');
  await pubkey.verifyOtp(email: 'alice@example.com', otp: '123456');
}
```

## Layout

- `PubkeyReadClient` — read host (GET, blob fetch, recoverable list)
- `PubkeyWriteClient` — write host (OTP, upload, rotate, lifecycle)
- `PubkeyClient` — facade (orchestration, session wiring, upload helpers)
- `SignedRequestExecutor` — generic signed PATCH/POST/DELETE

## Related repo

See `ARCHITECTURE.md` in `fl-start/crypto`.
