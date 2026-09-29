import 'package:scomm_vault_client/scomm_vault_client.dart';
import 'package:test/test.dart';

void main() {
  test('mailbox identity is 32-byte sha256 hex', () {
    final id = mailboxIdentityId('alice@example.com');
    expect(id, hasLength(64));
    expect(id, matches(RegExp(r'^[0-9a-f]{64}$')));
    expect(id, mailboxIdentityId('alice@example.com'));
    expect(id, isNot(mailboxIdentityId('bob@example.com')));
  });
}
