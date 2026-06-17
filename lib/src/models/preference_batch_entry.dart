class PreferenceBatchEntry {
  const PreferenceBatchEntry({
    required this.email,
    required this.found,
    this.keyId,
    this.algorithm,
    this.publicKey,
    this.label,
  });

  factory PreferenceBatchEntry.fromJson(Map<String, dynamic> json) {
    return PreferenceBatchEntry(
      email: json['email']?.toString() ?? '',
      found: json['found'] as bool? ?? false,
      keyId: json['keyId']?.toString(),
      algorithm: json['algorithm']?.toString(),
      publicKey: json['publicKey']?.toString(),
      label: json['label']?.toString(),
    );
  }

  final String email;
  final bool found;
  final String? keyId;
  final String? algorithm;
  final String? publicKey;
  final String? label;
}
