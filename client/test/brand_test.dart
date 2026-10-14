import 'dart:ui' as ui;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test(
    'ByteLocker logo preserves transparent background and visible artwork',
    () async {
      final asset = await rootBundle.load('assets/brand/bytelocker.png');
      final codec = await ui.instantiateImageCodec(asset.buffer.asUint8List());
      final frame = await codec.getNextFrame();
      try {
        final pixels = (await frame.image.toByteData(
          format: ui.ImageByteFormat.rawRgba,
        ))!;
        final width = frame.image.width, height = frame.image.height;
        for (final index in [
          0,
          width - 1,
          width * (height - 1),
          width * height - 1,
        ]) {
          expect(pixels.getUint8(index * 4 + 3), 0);
        }
        var visible = 0;
        for (var index = 3; index < pixels.lengthInBytes; index += 4) {
          if (pixels.getUint8(index) > 0) visible++;
        }
        expect(visible, greaterThan(width * height ~/ 4));
        expect(visible, lessThan(width * height * 3 ~/ 4));
      } finally {
        frame.image.dispose();
        codec.dispose();
      }
    },
  );
}
