/// Parsed Discovery Document (core schema 1.0).
///
/// Unknown optional fields and extensions are preserved in [raw].
class DiscoveryDocument {
  DiscoveryDocument({
    required this.schemaVersion,
    required this.mailbox,
    this.schema,
    this.capabilities = const {},
    this.extensions = const {},
    required this.raw,
  });

  final String schemaVersion;
  final String mailbox;
  final String? schema;
  final Map<String, dynamic> capabilities;
  final Map<String, dynamic> extensions;

  /// Full JSON map as returned by the server (unknown fields survive).
  final Map<String, dynamic> raw;

  factory DiscoveryDocument.fromJson(Map<String, dynamic> json) {
    final caps = json['capabilities'];
    final ext = json['extensions'];
    return DiscoveryDocument(
      schemaVersion: json['schemaVersion']?.toString() ?? '',
      mailbox: json['mailbox']?.toString() ?? '',
      schema: json[r'$schema']?.toString(),
      capabilities: caps is Map
          ? Map<String, dynamic>.from(caps)
          : const <String, dynamic>{},
      extensions: ext is Map
          ? Map<String, dynamic>.from(ext)
          : const <String, dynamic>{},
      raw: Map<String, dynamic>.from(json),
    );
  }

  Map<String, dynamic>? get crypto {
    final c = capabilities['crypto'];
    return c is Map ? Map<String, dynamic>.from(c) : null;
  }

  List<Map<String, dynamic>> encryptionKeys() {
    final enc = crypto?['encryption'];
    if (enc is! Map) return const [];
    final keys = enc['keys'];
    if (keys is! List) return const [];
    return [
      for (final k in keys)
        if (k is Map) Map<String, dynamic>.from(k),
    ];
  }

  List<Map<String, dynamic>> verificationKeys() {
    final ver = crypto?['verification'];
    if (ver is! Map) return const [];
    final keys = ver['keys'];
    if (keys is! List) return const [];
    return [
      for (final k in keys)
        if (k is Map) Map<String, dynamic>.from(k),
    ];
  }

  List<String> preferredLanguages() {
    final prefs = capabilities['preferences'];
    if (prefs is! Map) return const [];
    final languages = prefs['languages'];
    if (languages is! List) return const [];
    return [for (final l in languages) l.toString()];
  }
}

/// Management resource envelope (authenticated or public list).
class DiscoveryResource {
  DiscoveryResource({
    required this.id,
    required this.type,
    required this.schemaVersion,
    required this.value,
    this.visibility,
    this.metadata = const {},
    required this.raw,
  });

  final String id;
  final String type;
  final String schemaVersion;
  final Map<String, dynamic> value;
  final String? visibility;
  final Map<String, dynamic> metadata;
  final Map<String, dynamic> raw;

  factory DiscoveryResource.fromJson(Map<String, dynamic> json) {
    final value = json['value'];
    final metadata = json['metadata'];
    return DiscoveryResource(
      id: json['id']?.toString() ?? '',
      type: json['type']?.toString() ?? '',
      schemaVersion: json['schemaVersion']?.toString() ?? '',
      value: value is Map
          ? Map<String, dynamic>.from(value)
          : <String, dynamic>{},
      visibility: json['visibility']?.toString(),
      metadata: metadata is Map
          ? Map<String, dynamic>.from(metadata)
          : const <String, dynamic>{},
      raw: Map<String, dynamic>.from(json),
    );
  }
}

/// Challenge status returned by the generic challenge API.
class DiscoveryChallenge {
  DiscoveryChallenge({
    required this.id,
    required this.type,
    required this.status,
    this.purpose,
    this.expiresAt,
    this.attemptsRemaining,
    this.proof,
    required this.raw,
  });

  final String id;
  final String type;
  final String status;
  final String? purpose;
  final String? expiresAt;
  final int? attemptsRemaining;

  /// Short-lived purpose-bound proof after a successful response (if returned).
  final String? proof;
  final Map<String, dynamic> raw;

  factory DiscoveryChallenge.fromJson(Map<String, dynamic> json) {
    return DiscoveryChallenge(
      id: json['id']?.toString() ?? '',
      type: json['type']?.toString() ?? '',
      status: json['status']?.toString() ?? '',
      purpose: json['purpose']?.toString(),
      expiresAt: json['expiresAt']?.toString(),
      attemptsRemaining: json['attemptsRemaining'] is int
          ? json['attemptsRemaining'] as int
          : int.tryParse('${json['attemptsRemaining'] ?? ''}'),
      proof: json['proof']?.toString(),
      raw: Map<String, dynamic>.from(json),
    );
  }
}
