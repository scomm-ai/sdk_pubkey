import 'dart:convert';

/// Zone value holding a `List<PubkeyHttpExchange>` for the in-flight lookup.
const pubkeyHttpTraceZoneKey = #pubkeyHttpTrace;

/// One completed Discovery HTTP exchange, safe to show in a debug toast.
class PubkeyHttpExchange {
  const PubkeyHttpExchange({
    required this.method,
    required this.url,
    required this.requestHeaders,
    this.requestBody,
    this.statusCode,
    this.responseHeaders = const {},
    this.responseBody,
    this.errorMessage,
  });

  final String method;
  final String url;
  final Map<String, String> requestHeaders;
  final Object? requestBody;
  final int? statusCode;
  final Map<String, String> responseHeaders;
  final Object? responseBody;
  final String? errorMessage;

  String describe() {
    final request = StringBuffer()
      ..writeln('$method $url')
      ..writeln(_formatHeaders(requestHeaders));
    final body = _formatBody(requestBody);
    if (body != null) {
      request
        ..writeln()
        ..write(body);
    }

    final response = StringBuffer();
    if (statusCode != null) {
      response.writeln('HTTP $statusCode');
    }
    if (responseHeaders.isNotEmpty) {
      response.writeln(_formatHeaders(responseHeaders));
    }
    final responseText = _formatBody(responseBody);
    if (responseText != null) {
      if (response.isNotEmpty) response.writeln();
      response.write(responseText);
    }
    if (errorMessage != null && errorMessage!.isNotEmpty) {
      if (response.isNotEmpty) response.writeln();
      response.write(errorMessage);
    }

    return '--- request ---\n$request\n--- response ---\n$response';
  }
}

const _redactedHeaderNames = {
  'authorization',
  'cookie',
  'set-cookie',
  'proxy-authorization',
};

const _maxBodyChars = 16000;

String _formatHeaders(Map<String, String> headers) {
  final lines = <String>[];
  for (final entry in headers.entries) {
    final value = _redactedHeaderNames.contains(entry.key.toLowerCase())
        ? '***'
        : entry.value;
    lines.add('${entry.key}: $value');
  }
  lines.sort();
  return lines.join('\n');
}

String? _formatBody(Object? body) {
  if (body == null) return null;
  String text;
  if (body is String) {
    text = body;
  } else {
    try {
      text = const JsonEncoder.withIndent('  ').convert(body);
    } catch (_) {
      text = body.toString();
    }
  }
  if (text.length <= _maxBodyChars) return text;
  return '${text.substring(0, _maxBodyChars)}\n… truncated';
}

Map<String, String> normalizeHeaderMap(Map<dynamic, dynamic> headers) {
  final out = <String, String>{};
  headers.forEach((key, value) {
    if (value is List) {
      out['$key'] = value.join(', ');
    } else if (value != null) {
      out['$key'] = '$value';
    }
  });
  return out;
}
