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

  // NIST SP 800-38B AES-128 CMAC vector, truncated to the 64-bit MAC dmrtd
  // uses. Guards the direct AESEngine instantiation in calculateCMAC — the
  // registry lookup BlockCipher('AES') broke with pointycastle 4.0.0.
  test('calculateCMAC matches NIST SP 800-38B vector (64-bit truncation)', () {
    final mac = AESCipher(size: KEY_LENGTH.s128).calculateCMAC(
        data: '6bc1bee22e409f96e93d7e117393172a'.bytes,
        key: '2b7e151628aed2a6abf7158809cf4f3c'.bytes);
    expect(mac, '070a16b46b4d4144'.bytes);
  });
}

extension on String {
  Uint8List get bytes => Uint8List.fromList(List.generate(
      length ~/ 2, (i) => int.parse(substring(i * 2, i * 2 + 2), radix: 16)));
}
