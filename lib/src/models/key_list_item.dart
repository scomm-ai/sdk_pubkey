class KeyListItem {
  const KeyListItem({
    required this.keyId,
    required this.algorithm,
    required this.status,
    required this.isPreferred,
    required this.discoverable,
    required this.hasRecoveryPhrase,
    required this.hasBlob,
    this.label,
    this.createdAt,
    this.expiresAt,
  });

  factory KeyListItem.fromJson(Map<String, dynamic> json) {
    return KeyListItem(
      keyId: json['keyId'] as String,
      algorithm: json['algorithm'] as String,
      status: json['status'] as String? ?? 'deleted',
      isPreferred: json['isPreferred'] as bool? ?? false,
      discoverable: json['discoverable'] as bool? ?? false,
      hasRecoveryPhrase: json['hasRecoveryPhrase'] as bool? ?? false,
      hasBlob: json['hasBlob'] as bool? ?? false,
      label: json['label'] as String?,
      createdAt: json['createdAt'] as String?,
      expiresAt: json['expiresAt'] as String?,
    );
  }

  final String keyId;
  final String algorithm;
  final String status;
  final bool isPreferred;
  final bool discoverable;
  final bool hasRecoveryPhrase;
  final bool hasBlob;
  final String? label;
  final String? createdAt;
  final String? expiresAt;
}
