import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

typedef _OpNative = Int32 Function(
  Pointer<Uint8> input,
  IntPtr inputLen,
  Pointer<Pointer<Uint8>> outPtr,
  Pointer<IntPtr> outLen,
);
typedef _Op = int Function(
  Pointer<Uint8> input,
  int inputLen,
  Pointer<Pointer<Uint8>> outPtr,
  Pointer<IntPtr> outLen,
);
typedef _FreeNative = Void Function(Pointer<Uint8> ptr, IntPtr len);
typedef _Free = void Function(Pointer<Uint8> ptr, int len);

/// Loads `scomm_vault` from the CKVF Rust crate.
void ensureScommVault() => ScommVault.ensure();

class ScommVault {
  static DynamicLibrary? _lib;
  static late _Op _jcs;
  static late _Op _b64Encode;
  static late _Op _b64Decode;
  static late _Free _free;

  static void ensure() {
    if (_lib != null) return;
    final path = _libraryPath();
    final lib = DynamicLibrary.open(path);
    _jcs = lib.lookupFunction<_OpNative, _Op>('scomm_vault_jcs');
    _b64Encode = lib.lookupFunction<_OpNative, _Op>('scomm_vault_b64_encode');
    _b64Decode = lib.lookupFunction<_OpNative, _Op>('scomm_vault_b64_decode');
    _free = lib.lookupFunction<_FreeNative, _Free>('scomm_vault_free');
    _lib = lib;
  }

  static String jcs(String json) => utf8.decode(_call(_jcs, utf8.encode(json)));

  static String b64Encode(List<int> bytes) => utf8.decode(_call(_b64Encode, bytes));

  static Uint8List b64Decode(String value) => _call(_b64Decode, utf8.encode(value));

  static Uint8List _call(_Op op, List<int> input) {
    ensure();
    final inPtr = input.isEmpty ? Pointer<Uint8>.fromAddress(0) : malloc<Uint8>(input.length);
    final outPtr = malloc<Pointer<Uint8>>();
    final outLen = malloc<IntPtr>();
    try {
      if (input.isNotEmpty) {
        inPtr.asTypedList(input.length).setAll(0, input);
      }
      final rc = op(inPtr, input.length, outPtr, outLen);
      if (rc != 0) {
        throw ArgumentError('scomm_vault call failed ($rc)');
      }
      final len = outLen.value;
      final copy = Uint8List.fromList(outPtr.value.asTypedList(len));
      _free(outPtr.value, len);
      return copy;
    } finally {
      if (input.isNotEmpty) malloc.free(inPtr);
      malloc.free(outPtr);
      malloc.free(outLen);
    }
  }

  static String _libraryPath() {
    final name = Platform.isWindows
        ? 'scomm_vault.dll'
        : Platform.isMacOS
            ? 'libscomm_vault.dylib'
            : 'libscomm_vault.so';
    final candidates = <String>[];
    final override = Platform.environment['SCOMM_VAULT_LIB'];
    if (override != null && override.isNotEmpty) candidates.add(override);
    var dir = Directory.current;
    for (var i = 0; i < 8; i++) {
      candidates.add('${dir.path}${Platform.pathSeparator}native${Platform.pathSeparator}$name');
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
    candidates.add(
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$name',
    );
    for (final path in candidates) {
      if (File(path).existsSync()) return path;
    }
    throw StateError(
      'scomm_vault library was not found. Looked for $name in: ${candidates.join(', ')}',
    );
  }
}
