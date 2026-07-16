// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: constant_identifier_names

import 'dart:typed_data';

import 'package:dmrtd/extensions.dart';
import "package:dmrtd/src/lds/df1/dg.dart";
import "package:dmrtd/src/extension/logging_apis.dart";
import 'package:logging/logging.dart';
import 'package:pointycastle/asn1.dart';

import 'ef.dart';
import 'asn1ObjectIdentifiers.dart';
import 'substruct/pace_info.dart';

class EfCardAccess extends ElementaryFile {
  static const FID = 0x011C;
  static const SFI = 0x1C;
  static const TAG = DgTag(0x6C);

  PaceInfo? paceInfo;

  bool get isPaceInfoSet => paceInfo != null;

  final _log = Logger("EfCardAccess");

  EfCardAccess.fromBytes(Uint8List data) : super.fromBytes(data);

  @override
  int get fid => FID;

  @override
  int get sfi => SFI;

  @override
  void parse(Uint8List content) {
    _log.sdVerbose("Parsing EF.CardAccess" + content.hex());

    var parser = ASN1Parser(content);
    if (!parser.hasNext()) {
      _log.error("Invalid structure of EF.CardAccess. No data to parse.");
      throw EfParseError("Invalid structure of EF.CardAccess. No data to parse.");
    }

    ASN1Set set = parser.nextObject() as ASN1Set;

    // there are 2 structures of EF.CardAccess but second one is not required
    // - PaceInfo
    // - PACEDomainParameterInfo

    if (set.elements == null || set.elements!.length < 1) {
      _log.error("Invalid structure of EF.CardAccess. No elements in set.");
      throw EfParseError("Invalid structure of EF.CardAccess. No elements in set.");
    }

    // EF.CardAccess is a SET of SecurityInfos: possibly several PACEInfos
    // (e.g. GM and CAM), PACEDomainParameterInfo, CardInfo, ... Parse every
    // element that is a valid PACEInfo and skip the rest.
    final paceInfos = <PaceInfo>[];
    for (final element in set.elements!) {
      if (element is! ASN1Sequence) continue;
      try {
        paceInfos.add(PaceInfo(content: element));
      } catch (e) {
        _log.debug("Skipping non-PACEInfo/unsupported SecurityInfo: $e");
      }
    }

    if (paceInfos.isEmpty) {
      _log.error("No supported PACEInfo found in EF.CardAccess.");
      throw EfParseError("No supported PACEInfo found in EF.CardAccess.");
    }

    // Prefer a PACEInfo with supported domain parameters; among those prefer
    // GM (battle-tested here), then CAM (same steps 1-4 on our side, extra
    // data in step 4 response). IM mapping is not implemented, so it's last.
    bool supported(PaceInfo pi, MAPPING_TYPE type) =>
        pi.isPaceDomainParameterSupported && pi.protocol.mappingType == type;
    paceInfo = paceInfos.firstWhere((pi) => supported(pi, MAPPING_TYPE.GM),
        orElse: () => paceInfos.firstWhere(
            (pi) => supported(pi, MAPPING_TYPE.CAM),
            orElse: () => paceInfos.first));

    _log.info("PaceInfo parsed.");
    _log.sdDebug("Selected PaceInfo: $paceInfo (of ${paceInfos.length} found)");


    //TODO: parse PACEDomainParameterInfo(9303 p11, 9.2.1)
    /*
      PACEDomainParameterInfo ::= SEQUENCE {
        protocol OBJECT IDENTIFIER(
        id-PACE-DH-GM |
        id-PACE-ECDH-GM |
        id-PACE-DH-IM |
        id-PACE-ECDH-IM |
        id-PACE-ECDH-CAM),
        domainParameter AlgorithmIdentifier,
        parameterId INTEGER OPTIONAL
      }
     */


    /*String paceOID = "id-PACE-ECDH-GM-AES-CBC-CMAC-128"; //0.4.0.127.0.7.2.2.4.2.2
    int parameterSpec = 2;
    PaceMappingType paceMappingType = PaceMappingType.GM;
    String aggrementAlgorithm = "ECDH";
    String cipherAlgorithm = "AES";
    String digestAlgorithm = "SHA-1";
    int keyLength = 128;
    String mrzKey = "PB1777140590020743305304";

    //List<int> buf = utf8.encode(mrzKey);
    Uint8List buf = Uint8List.fromList(utf8.encode(mrzKey));
    Digest sha1 = Digest("SHA-1");
    List<int> sha1Bytes = sha1.process(buf);
    String sha1Hex = sha1Bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

    var smskg = SecureMessagingSessionKeyGenerator();
    var key = await smskg.deriveKey(keySeed: hash, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: null, mode: SecureMessagingSessionKeyDerivationMode.PACE_MODE, paceKeyReference: paceKeyType);
    return key;*/
  }
}