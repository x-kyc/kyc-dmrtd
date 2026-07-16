import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/internal.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

class _QueuedProvider extends ComProvider {
  final List<Object> responses;
  final List<Uint8List> commands = [];

  _QueuedProvider(this.responses) : super(Logger('resumable-read-test'));

  @override
  Future<void> connect() async {}

  @override
  Future<void> disconnect() async {}

  @override
  bool isConnected() => true;

  @override
  Future<Uint8List> transceive(Uint8List data) async {
    commands.add(Uint8List.fromList(data));
    final response = responses.removeAt(0);
    if (response is Exception) throw response;
    return response as Uint8List;
  }
}

Uint8List _response(List<int> data) =>
    Uint8List.fromList([...data, 0x90, 0x00]);

void main() {
  test('resumes an SFI read from the first unfinished byte', () async {
    final content = List<int>.generate(300, (index) => index % 256);
    final file = Uint8List.fromList([0x61, 0x82, 0x01, 0x2c, ...content]);
    var checkpoint = Uint8List(0);

    final firstProvider = _QueuedProvider([
      _response(file.sublist(0, 8)),
      _response(file.sublist(8, 264)),
      const ComProviderError('Tag was lost'),
    ]);

    await expectLater(
      MrtdApi(firstProvider).readFileBySFI(
        0x02,
        onChunk: (chunk, offset, totalLength) {
          expect(offset, checkpoint.length);
          expect(totalLength, file.length);
          checkpoint = Uint8List.fromList(checkpoint + chunk);
        },
      ),
      throwsA(isA<ComProviderError>()),
    );
    expect(checkpoint.length, 264);

    final resumedChunks = <Uint8List>[];
    final secondProvider = _QueuedProvider([
      _response(file.sublist(0, 8)),
      _response(file.sublist(264)),
    ]);
    final result = await MrtdApi(secondProvider).readFileBySFI(
      0x02,
      resumeData: checkpoint,
      onChunk: (chunk, offset, totalLength) {
        expect(offset, checkpoint.length);
        expect(totalLength, file.length);
        resumedChunks.add(chunk);
      },
    );

    expect(result, file);
    expect(resumedChunks, hasLength(1));
    expect(resumedChunks.single, file.sublist(264));
    expect(
      secondProvider.commands[1].sublist(0, 4),
      [0x00, 0xb0, 0x01, 0x08],
    );
  });

  test('rejects resume data from a different file', () async {
    final file = [0x61, 0x03, 0x01, 0x02, 0x03];
    final provider = _QueuedProvider([_response(file)]);

    await expectLater(
      MrtdApi(provider).readFileBySFI(
        0x02,
        resumeData: Uint8List.fromList([0x62]),
      ),
      throwsA(isA<MrtdApiError>()),
    );
  });
}
