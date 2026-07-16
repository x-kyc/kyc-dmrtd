// Tests for PACE-CAM support: OID registration, EF.CardAccess SecurityInfo
// selection, and step-4 response parsing with encrypted chip auth data (0x8A).

import 'dart:typed_data';

import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/src/lds/efcard_access.dart';
import 'package:dmrtd/src/proto/pace.dart';
import 'package:test/test.dart';

// DER-encoded PACEInfo: SEQUENCE { OID, INTEGER 2, INTEGER paramId }
Uint8List paceInfoSeq(List<int> oidSuffix, int paramId) {
  // OID 0.4.0.127.0.7.2.2.4.x.y encodes to 04 00 7F 00 07 02 02 04 x y
  final oid = [0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, ...oidSuffix];
  final content = [...oid, 0x02, 0x01, 0x02, 0x02, 0x01, paramId];
  return Uint8List.fromList([0x30, content.length, ...content]);
}

Uint8List cardAccess(List<Uint8List> infos) {
  final content = infos.expand((e) => e).toList();
  return Uint8List.fromList([0x31, content.length, ...content]);
}

void main() {
  final camOid = [6, 2]; // id-PACE-ECDH-CAM-AES-CBC-CMAC-128
  final gmOid = [2, 2]; // id-PACE-ECDH-GM-AES-CBC-CMAC-128

  test('CAM OID parses with correct params', () {
    final ef = EfCardAccess.fromBytes(cardAccess([paceInfoSeq(camOid, 12)]));
    final p = ef.paceInfo!.protocol;
    expect(p.mappingType, MAPPING_TYPE.CAM);
    expect(p.tokenAgreementAlgorithm, TOKEN_AGREEMENT_ALGO.ECDH);
    expect(p.cipherAlgoritm, CipherAlgorithm.AES);
    expect(p.keyLength, KEY_LENGTH.s128);
    expect(ef.paceInfo!.isPaceDomainParameterSupported, isTrue);
  });

  test('GM preferred when both GM and CAM advertised (any order)', () {
    for (final infos in [
      [paceInfoSeq(camOid, 12), paceInfoSeq(gmOid, 12)],
      [paceInfoSeq(gmOid, 12), paceInfoSeq(camOid, 12)],
    ]) {
      final ef = EfCardAccess.fromBytes(cardAccess(infos));
      expect(ef.paceInfo!.protocol.mappingType, MAPPING_TYPE.GM);
    }
  });

  test('unknown SecurityInfo is skipped, CAM still found', () {
    // A SecurityInfo with an unrelated OID (2.5.4.3) that must be ignored.
    final junk = Uint8List.fromList([0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x02, 0x01, 0x02]);
    final ef = EfCardAccess.fromBytes(cardAccess([junk, paceInfoSeq(camOid, 12)]));
    expect(ef.paceInfo!.protocol.mappingType, MAPPING_TYPE.CAM);
  });

  test('step-4 response with 0x8A chip auth data parses', () {
    final token = List<int>.filled(8, 0xAA);
    final camData = List<int>.filled(16, 0xBB);
    final data = Uint8List.fromList([
      0x7C, 2 + token.length + 2 + camData.length,
      0x86, token.length, ...token,
      0x8A, camData.length, ...camData,
    ]);
    final resp = ResponseAPDUStep4Pace(data);
    resp.parse();
    expect(resp.authToken, Uint8List.fromList(token));
    expect(resp.encryptedChipAuthenticationData, Uint8List.fromList(camData));
  });

  test('step-4 response without auth token throws', () {
    final data = Uint8List.fromList([0x7C, 0x04, 0x8A, 0x02, 0x01, 0x02]);
    expect(() => ResponseAPDUStep4Pace(data).parse(),
        throwsA(isA<ResponseAPDUStep4PaceError>()));
  });
}
