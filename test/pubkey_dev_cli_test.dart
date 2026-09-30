import 'package:test/test.dart';

import '../bin/pubkey_dev_debug.dart';
import '../bin/pubkey_dev_release.dart';

void main() {
  test('release builds keep only the omission message', () {
    expect(
      pubkeyDevReleaseMessage,
      contains('omitted from release builds'),
    );
  });

  test('debug args require a loopback directory', () {
    expect(
      () => parseDevArgs([
        '--url',
        'https://discovery.scomm.ai',
        '--email',
        'a@example.com',
        'fetch',
        '--key-id',
        '30FA-9DE6',
      ]),
      throwsA(isA<DevUsage>()),
    );
  });

  test('sign-pgp requires the armed MSK seed', () {
    expect(
      () => parseDevArgs([
        '--url',
        'http://127.0.0.1:3000',
        '--email',
        'a@example.com',
        'sign-pgp',
      ]),
      throwsA(isA<DevUsage>()),
    );
    final args = parseDevArgs([
      '--url',
      'http://127.0.0.1:3000',
      '--email',
      'a@example.com',
      '--msk',
      'msk.seed',
      'sign-pgp',
    ]);
    expect(args.command, 'sign-pgp');
  });

  test('sign-pqc requires the armed MSK seed', () {
    expect(
      () => parseDevArgs([
        '--url',
        'http://127.0.0.1:3000',
        '--email',
        'a@example.com',
        'sign-pqc',
      ]),
      throwsA(isA<DevUsage>()),
    );
    final args = parseDevArgs([
      '--url',
      'http://127.0.0.1:3000',
      '--email',
      'a@example.com',
      '--msk',
      'msk.seed',
      'sign-pqc',
    ]);
    expect(args.command, 'sign-pqc');
  });

  test('encrypt-pgp-pqc requires the armed MSK seed', () {
    expect(
      () => parseDevArgs([
        '--url',
        'http://127.0.0.1:3000',
        '--email',
        'a@example.com',
        'encrypt-pgp-pqc',
      ]),
      throwsA(isA<DevUsage>()),
    );
    final args = parseDevArgs([
      '--url',
      'http://127.0.0.1:3000',
      '--email',
      'a@example.com',
      '--msk',
      'msk.seed',
      'encrypt-pgp-pqc',
    ]);
    expect(args.command, 'encrypt-pgp-pqc');
  });

  test('fetch-pgp-pqc does not require a key id', () {
    final args = parseDevArgs([
      '--url',
      'http://127.0.0.1:3000',
      '--email',
      'a@example.com',
      'fetch-pgp-pqc',
    ]);
    expect(args.command, 'fetch-pgp-pqc');
  });

  test('enroll requires an OTP and a seed output path', () {
    DevArgs parse() => parseDevArgs([
          '--url',
          'http://127.0.0.1:3000',
          '--email',
          'a@example.com',
          '--otp',
          '0123456789A',
          '--msk-out',
          'msk.seed',
          'enroll',
        ]);
    final args = parse();
    expect(args.command, 'enroll');
    expect(args.otp, '0123456789A');
    expect(
      () => parseDevArgs([
        '--url',
        'http://127.0.0.1:3000',
        '--email',
        'a@example.com',
        'enroll',
      ]),
      throwsA(isA<DevUsage>()),
    );
  });
}
