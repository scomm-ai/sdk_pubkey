import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ckvf/ckvf.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

void main() {
  setUpAll(() {
    VaultDigest.install(
      sha256: (data) => Uint8List.fromList(crypto.sha256.convert(data).bytes),
      sha512: (data) => Uint8List.fromList(crypto.sha512.convert(data).bytes),
      hmacSha256: (key, data) => Uint8List.fromList(
        crypto.Hmac(crypto.sha256, key).convert(data).bytes,
      ),
    );
  });
  test('folder pairing transfers the vault without a host', () async {
    final root = Directory.systemTemp.createTempSync('ckvf-pair');
    final crypto = SoftwareCkvfCrypto();
    final vault = KeyVault(MemoryLocalVaultStore(), crypto: crypto);
    await vault.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'd1', name: 'Laptop'),
    );
    final channel = FolderPairingChannel(root);
    final offer = await startFolderPairing(
      channel: channel,
      identityId: vault.vault.payload.identity.identityId,
      deviceName: 'Phone',
      deviceId: 'd2',
      requestedTier: 'full',
      crypto: crypto,
      pollInterval: const Duration(milliseconds: 20),
    );
    final opened = offer.completed;
    final request = fetchFolderPairing(channel, offer.sessionId);
    final approved = approveFolderPairing(
      channel: channel,
      vault: vault,
      request: request,
      password: offer.password,
      pollInterval: const Duration(milliseconds: 20),
    );
    final result = await opened;
    await approved;
    expect(result.container.vaultId, vault.vaultId);
    final left = File('${root.path}/pair/${offer.sessionId}.json');
    expect(left.readAsStringSync(), contains('COMPLETED'));
    root.deleteSync(recursive: true);
  });

  test('webdav compare-and-swap rejects a stale head', () async {
    final files = <String, String>{};
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((request) async {
      final path = request.uri.path;
      if (request.method == 'GET') {
        final body = files[path];
        if (body == null) {
          request.response.statusCode = 404;
        } else {
          request.response.statusCode = 200;
          request.response.write(body);
        }
        await request.response.close();
        return;
      }
      if (request.method != 'PUT') {
        request.response.statusCode = 405;
        await request.response.close();
        return;
      }
      final body = await utf8.decoder.bind(request).join();
      final ifNone = request.headers.value(HttpHeaders.ifNoneMatchHeader);
      final ifMatch = request.headers.value(HttpHeaders.ifMatchHeader);
      if (ifNone == '*' && files.containsKey(path)) {
        request.response.statusCode = 412;
        await request.response.close();
        return;
      }
      if (ifMatch != null) {
        final current = files[path];
        final head = current == null ? null : VaultHead.parse(current);
        if (head == null || ifMatch != '"${head.generationHash}"') {
          request.response.statusCode = 412;
          await request.response.close();
          return;
        }
      }
      final created = !files.containsKey(path);
      files[path] = body;
      request.response.statusCode = created ? 201 : 204;
      await request.response.close();
    });

    final sync = WebDavVaultSync(
      Uri.parse('http://127.0.0.1:${server.port}/sync/'),
    );
    final crypto = SoftwareCkvfCrypto();
    final vault = KeyVault(MemoryLocalVaultStore(), crypto: crypto)
      ..syncStore = sync;
    await vault.create(
      email: 'alice@example.com',
      device: const VaultDevice(deviceId: 'd1', name: 'Laptop'),
    );
    await vault.push();
    expect((await sync.getHead(vault.vaultId))?.generation, 1);

    final pair = await crypto.ed25519Generate();
    await vault.importKey(
      family: 'smime',
      encoding: 'pkcs8',
      algorithm: 'Ed25519',
      purpose: const ['sign'],
      privateKey: buildPkcs8Ed25519(pair.privateKey, pair.publicKey),
      publicKey: buildSpkiEd25519(pair.publicKey),
    );
    await vault.push();
    final head = await sync.getHead(vault.vaultId);
    expect(head!.generation, greaterThan(1));

    final gen1 = await sync.getGeneration(vault.vaultId, 1);
    final parsed = jsonDecode(gen1!) as Map<String, dynamic>;
    final hash = parsed['generation_hash'] as String;
    final headPath = '/sync/${vault.vaultId}/head.json';
    files[headPath] = jsonEncode({
      'format': 'CKVF-HEAD',
      'version': '1',
      'vault_id': vault.vaultId,
      'generation': 1,
      'generation_hash': hash,
    });
    await expectLater(
      vault.pull(),
      throwsA(
        isA<VaultClientException>().having(
          (e) => e.code,
          'code',
          'generation_rollback',
        ),
      ),
    );
    await server.close(force: true);
  });
}
