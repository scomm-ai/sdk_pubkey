import 'dart:convert';
import 'dart:io';

Map<String, dynamic> loadFixture(String name) {
  final candidates = [
    File('conformance/fixtures/$name'),
    File('../conformance/fixtures/$name'),
  ];
  for (final file in candidates) {
    if (file.existsSync()) {
      return jsonDecode(file.readAsStringSync()) as Map<String, dynamic>;
    }
  }
  throw StateError('Missing conformance fixture: $name');
}
