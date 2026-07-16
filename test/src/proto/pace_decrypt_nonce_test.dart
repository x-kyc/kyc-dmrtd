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

  // NIST SP 800-38B CMAC vectors, truncated to the 64-bit MAC dmrtd uses.
  // Guards the hand-rolled CMAC in AESCipher — pointycastle's CMac breaks
  // for AES-192/256 keys (zero IV sized to key length instead of block size).
  test('calculateCMAC matches NIST SP 800-38B vectors (64-bit truncation)', () {
    const k128 = '2b7e151628aed2a6abf7158809cf4f3c';
    const k256 =
        '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
    const m16 = '6bc1bee22e409f96e93d7e117393172a';
    const m40 = '6bc1bee22e409f96e93d7e117393172a'
        'ae2d8a571e03ac9c9eb76fac45af8e51'
        '30c81c46a35ce411';
    final cipher = AESCipher(size: KEY_LENGTH.s128);

    // empty message (k2/padding path)
    expect(cipher.calculateCMAC(data: Uint8List(0), key: k128.bytes),
        'bb1d6929e9593728'.bytes);
    // single complete block (k1 path)
    expect(cipher.calculateCMAC(data: m16.bytes, key: k128.bytes),
        '070a16b46b4d4144'.bytes);
    // multi-block with partial last block (k2 path)
    expect(cipher.calculateCMAC(data: m40.bytes, key: k128.bytes),
        'dfa66747de9ae630'.bytes);
    // AES-256 key — the case pointycastle's CMac throws on
    expect(cipher.calculateCMAC(data: m16.bytes, key: k256.bytes),
        '28a7023f452e8f82'.bytes);
  });
}

extension on String {
  Uint8List get bytes => Uint8List.fromList(List.generate(
      length ~/ 2, (i) => int.parse(substring(i * 2, i * 2 + 2), radix: 16)));
}
