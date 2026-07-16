// Regression tests: PACE nonce decryption must use the cipher size the
// protocol dictates (AES-256 passports previously hit a hardcoded AES-128
// cipher and failed step 1), and the 192-bit selector must not return a
// 128-bit cipher.

import 'dart:typed_data';

import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/src/proto/dba_key.dart';
import 'package:dmrtd/src/proto/pace.dart';
import 'package:test/test.dart';

OIEPaceProtocol protocol(String name, List<int> oidTail) => OIEPaceProtocol(
    identifierString: '0.4.0.127.0.7.2.2.4.${oidTail.join('.')}',
    readableName: name,
    identifier: [0, 4, 0, 127, 0, 7, 2, 2, 4, ...oidTail]);

void main() {
  final key = DBAKey('AB1234567', DateTime(1995, 12, 2), DateTime(2028, 11, 27));
  final nonce = Uint8List.fromList(List.generate(16, (i) => i));

  test('decryptNonce works for every AES key length', () {
    for (final (name, tail) in [
      ('id-PACE-ECDH-GM-AES-CBC-CMAC-128', [2, 2]),
      ('id-PACE-ECDH-GM-AES-CBC-CMAC-192', [2, 3]),
      ('id-PACE-ECDH-GM-AES-CBC-CMAC-256', [2, 4]),
      ('id-PACE-ECDH-CAM-AES-CBC-CMAC-256', [6, 4]),
    ]) {
      final decrypted = PACE.decryptNonce(
          paceProtocol: protocol(name, tail), nonce: nonce, accessKey: key);
      expect(decrypted.length, 16, reason: name);
    }
  });

  test('AESChiperSelector returns matching cipher sizes', () {
    expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s128).size, 16);
    expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s192).size, 24);
    expect(AESChiperSelector.getChiper(size: KEY_LENGTH.s256).size, 32);
  });
}
