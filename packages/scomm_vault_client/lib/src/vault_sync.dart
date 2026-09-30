import 'dart:convert';
import 'dart:io';

import 'package:ckvf/ckvf.dart';

import 'errors.dart';

/// Pointer at the generation other devices should treat as current.
class VaultHead {
  const VaultHead({
    required this.vaultId,
    required this.generation,
    required this.generationHash,
  });

  final String vaultId;
  final int generation;
  final String generationHash;

  Map<String, dynamic> toJson() => {
        'format': 'CKVF-HEAD',
        'version': '1',
        'vault_id': vaultId,
        'generation': generation,
        'generation_hash': generationHash,
      };

  static VaultHead? parse(String? raw) {
    if (raw == null || raw.isEmpty) return null;
    final json = jsonDecode(raw);
    if (json is! Map) {
      throw VaultClientException('sync_head', 'head is not an object');
    }
    if (json['format'] != 'CKVF-HEAD') {
      throw VaultClientException('sync_head', 'unrecognized head');
    }
    final generation = json['generation'];
    final hash = json['generation_hash'];
    final vaultId = json['vault_id'];
    if (generation is! int || hash is! String || vaultId is! String) {
      throw VaultClientException('sync_head', 'head fields');
    }
    return VaultHead(
      vaultId: vaultId,
      generation: generation,
      generationHash: hash,
    );
  }
}

/// Untrusted storage of immutable CKVF generations. The engine does not
/// learn which product is behind the adapter.
abstract class VaultSyncStore {
  Future<VaultHead?> getHead(String vaultId);

  Future<String?> getGeneration(String vaultId, int generation);

  /// Writes the container only when that generation file is absent.
  /// Different bytes at the same name are tampering.
  Future<void> putIfAbsent(String vaultId, int generation, String containerJson);

  /// Replaces the head only when [expectedHash] is the current head hash,
  /// or when the head is absent and [expectedHash] is null.
  Future<bool> compareAndSwapHead({
    required VaultHead next,
    required String? expectedHash,
  });
}

/// `{root}/{vault_id}/head.json` and `{root}/{vault_id}/g/{generation}.json`.
class FolderVaultSync implements VaultSyncStore {
  FolderVaultSync(this.root);

  final Directory root;

  Directory _dir(String vaultId) {
    final safe = vaultId.replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '');
    if (safe.isEmpty || safe != vaultId) {
      throw VaultClientException('sync_path', 'vault id');
    }
    return Directory('${root.path}/$safe');
  }

  File _head(String vaultId) => File('${_dir(vaultId).path}/head.json');

  File _generation(String vaultId, int generation) =>
      File('${_dir(vaultId).path}/g/$generation.json');

  @override
  Future<VaultHead?> getHead(String vaultId) async {
    final file = _head(vaultId);
    if (!file.existsSync()) return null;
    return VaultHead.parse(file.readAsStringSync());
  }

  @override
  Future<String?> getGeneration(String vaultId, int generation) async {
    final file = _generation(vaultId, generation);
    if (!file.existsSync()) return null;
    return file.readAsStringSync();
  }

  @override
  Future<void> putIfAbsent(
    String vaultId,
    int generation,
    String containerJson,
  ) async {
    final file = _generation(vaultId, generation);
    file.parent.createSync(recursive: true);
    if (file.existsSync()) {
      final existing = file.readAsStringSync();
      if (existing != containerJson) {
        throw VaultClientException(
          'sync_tamper',
          'generation $generation already has different bytes',
        );
      }
      return;
    }
    final tmp = File('${file.path}.tmp');
    tmp.writeAsStringSync(containerJson, flush: true);
    tmp.renameSync(file.path);
  }

  @override
  Future<bool> compareAndSwapHead({
    required VaultHead next,
    required String? expectedHash,
  }) async {
    final file = _head(next.vaultId);
    file.parent.createSync(recursive: true);
    final current = file.existsSync() ? VaultHead.parse(file.readAsStringSync()) : null;
    final currentHash = current?.generationHash;
    if (currentHash != expectedHash) return false;
    if (current != null && current.vaultId != next.vaultId) return false;
    final tmp = File('${file.path}.tmp');
    tmp.writeAsStringSync(jsonEncode(next.toJson()), flush: true);
    tmp.renameSync(file.path);
    return true;
  }
}

/// Confirms a container file matches the head it claims.
Future<VaultContainer> containerFromSyncObject(String json) {
  return parseContainer(json);
}

Future<VaultContainer> parseContainer(String json) async {
  final value = jsonDecode(json);
  if (value is! Map) {
    throw VaultClientException('sync_object', 'container is not an object');
  }
  return VaultContainer.fromJson(Map<String, dynamic>.from(value));
}

/// WebDAV (or any HTTP server that honors `If-None-Match` and `If-Match`)
/// for the same generation objects as [FolderVaultSync].
class WebDavVaultSync implements VaultSyncStore {
  WebDavVaultSync(
    Uri base, {
    this.headers = const {},
    HttpClient? client,
  })  : _root = _withSlash(base),
        _client = client ?? HttpClient();

  final Uri _root;
  final Map<String, String> headers;
  final HttpClient _client;

  static Uri _withSlash(Uri base) {
    final text = base.toString();
    return Uri.parse(text.endsWith('/') ? text : '$text/');
  }

  String _safe(String vaultId) {
    final safe = vaultId.replaceAll(RegExp(r'[^A-Za-z0-9_-]'), '');
    if (safe.isEmpty || safe != vaultId) {
      throw VaultClientException('sync_path', 'vault id');
    }
    return safe;
  }

  Uri _uri(String vaultId, String name) => _root.resolve('${_safe(vaultId)}/$name');

  Future<HttpClientResponse> _send(
    String method,
    Uri uri, {
    String? body,
    Map<String, String> extra = const {},
  }) async {
    final request = await _client.openUrl(method, uri);
    headers.forEach(request.headers.set);
    extra.forEach(request.headers.set);
    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.add(utf8.encode(body));
    }
    return request.close();
  }

  Future<String> _readBody(HttpClientResponse response) {
    return response.transform(utf8.decoder).join();
  }

  @override
  Future<VaultHead?> getHead(String vaultId) async {
    final response = await _send('GET', _uri(vaultId, 'head.json'));
    if (response.statusCode == 404) {
      await response.drain<void>();
      return null;
    }
    final body = await _readBody(response);
    if (response.statusCode != 200) {
      throw VaultClientException('sync_head', 'head HTTP ${response.statusCode}');
    }
    return VaultHead.parse(body);
  }

  @override
  Future<String?> getGeneration(String vaultId, int generation) async {
    final response = await _send('GET', _uri(vaultId, 'g/$generation.json'));
    if (response.statusCode == 404) {
      await response.drain<void>();
      return null;
    }
    final body = await _readBody(response);
    if (response.statusCode != 200) {
      throw VaultClientException(
        'sync_object',
        'generation HTTP ${response.statusCode}',
      );
    }
    return body;
  }

  @override
  Future<void> putIfAbsent(
    String vaultId,
    int generation,
    String containerJson,
  ) async {
    final uri = _uri(vaultId, 'g/$generation.json');
    final response = await _send(
      'PUT',
      uri,
      body: containerJson,
      extra: {HttpHeaders.ifNoneMatchHeader: '*'},
    );
    if (response.statusCode == 201 || response.statusCode == 204) {
      await response.drain<void>();
      return;
    }
    await response.drain<void>();
    if (response.statusCode != 412) {
      throw VaultClientException(
        'sync_object',
        'put generation HTTP ${response.statusCode}',
      );
    }
    final existing = await getGeneration(vaultId, generation);
    if (existing != containerJson) {
      throw VaultClientException(
        'sync_tamper',
        'generation $generation already has different bytes',
      );
    }
  }

  @override
  Future<bool> compareAndSwapHead({
    required VaultHead next,
    required String? expectedHash,
  }) async {
    final current = await getHead(next.vaultId);
    if (current?.generationHash != expectedHash) return false;
    if (current != null && current.vaultId != next.vaultId) return false;
    final extra = <String, String>{
      if (expectedHash == null)
        HttpHeaders.ifNoneMatchHeader: '*'
      else
        HttpHeaders.ifMatchHeader: '"$expectedHash"',
    };
    final response = await _send(
      'PUT',
      _uri(next.vaultId, 'head.json'),
      body: jsonEncode(next.toJson()),
      extra: extra,
    );
    final ok = response.statusCode == 200 ||
        response.statusCode == 201 ||
        response.statusCode == 204;
    await response.drain<void>();
    if (response.statusCode == 412) return false;
    if (!ok) {
      throw VaultClientException(
        'sync_head',
        'cas head HTTP ${response.statusCode}',
      );
    }
    return true;
  }
}
