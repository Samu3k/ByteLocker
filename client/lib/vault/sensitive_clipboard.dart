import 'package:flutter/services.dart';

/// Native ownership tracking prevents clearing newer clipboard contents.
abstract final class SensitiveClipboard {
  static const channel = MethodChannel('bytelocker/clipboard');
  static Future<void> copy(String text) =>
      channel.invokeMethod<void>('copy', text);
  static Future<void> clear() async {
    try {
      await channel.invokeMethod<void>('clear');
    } on PlatformException {
      /* Cleanup is best effort when the OS is unavailable. */
    } on MissingPluginException {
      /* No native clipboard in headless widget tests. */
    }
  }
}
