import 'package:secmail_pubkey_sdk/secmail_pubkey_sdk.dart';
import 'package:test/test.dart';

void main() {
  test('mailbox OTP is 11-character Base62 and strips separators', () {
    expect(MailboxOtp.length, 11);
    expect(MailboxOtp.bits, 64);
    expect(MailboxOtp.publicProductName, 'Scomm.AI');
    expect(MailboxOtp.fromDisplayName, 'SComm.AI NoReply OTP');
    expect(MailboxOtp.normalize('AbC1-2DeF-345'), 'AbC12DeF345');
    expect(MailboxOtp.normalize('123456'), '');
  });
}
