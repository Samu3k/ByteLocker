import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'bitwarden_csv.dart';

class TransferFiles {
  const TransferFiles();
  static const channel = MethodChannel('bytelocker/files');
  Future<Uint8List?> readCsv({bool Function()? isAllowed}) async {
    if (isAllowed?.call() == false) return null;
    final selected = await channel.invokeMethod<String>('chooseCsvImport');
    if (selected == null || isAllowed?.call() == false) return null;
    if (Platform.isAndroid)
      return channel.invokeMethod<Uint8List>('readCsvImport', selected);
    final file = File(selected);
    if (await file.length() > maxTransferBytes) throw const TransferFailure();
    if (isAllowed?.call() == false) return null;
    final builder = BytesBuilder(copy: false);
    var length = 0;
    await for (final chunk in file.openRead()) {
      if (isAllowed?.call() == false) {
        final partial = builder.takeBytes();
        partial.fillRange(0, partial.length, 0);
        return null;
      }
      length += chunk.length;
      if (length > maxTransferBytes) throw const TransferFailure();
      builder.add(chunk);
    }
    return builder.takeBytes();
  }

  Future<String?> chooseExport() async {
    if (Platform.isAndroid)
      return channel.invokeMethod<String>('chooseCsvExport');
    return channel.invokeMethod<String>('chooseCsvExport');
  }

  Future<void> write(String destination, Uint8List bytes) async {
    if (Platform.isAndroid) {
      await channel.invokeMethod('writeCsvExport', {
        'destination': destination,
        'bytes': bytes,
      });
    } else {
      await File(destination).writeAsBytes(bytes, flush: true);
    }
  }
}
