class AccountCheckResult {
  const AccountCheckResult({
    required this.known,
    this.hasKeys,
    this.algorithms = const [],
  });

  factory AccountCheckResult.fromJson(Map<String, dynamic> json) {
    return AccountCheckResult(
      known: json['known'] as bool? ?? false,
      hasKeys: json['hasKeys'] as bool?,
      algorithms: (json['algorithms'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          const [],
    );
  }

  final bool known;
  final bool? hasKeys;
  final List<String> algorithms;
}
