import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter/services.dart';

import 'update_manifest.dart';

class UpdateController extends ChangeNotifier {
  bool get supported => Platform.isWindows || Platform.isAndroid;
  bool get automaticRestart => Platform.isWindows;
  UpdateManifest? available;
  bool checking = false, installing = false, _alive = true;
  String? message;
  Future<bool> Function()? prepareInstall;
  bool Function()? vaultCanRestart;
  static const native = MethodChannel('bytelocker/files');
  String get _platform => Platform.isWindows ? 'windows-x64' : 'android-arm64';
  void _changed() {
    if (_alive) notifyListeners();
  }

  void dismiss() {
    available = null;
    message = null;
    _changed();
  }

  @override
  void dispose() {
    _alive = false;
    super.dispose();
  }

  Future<HttpClientResponse> _get(HttpClient client, Uri uri) async {
    for (var i = 0; i < 6; i++) {
      if (uri.scheme != 'https' ||
          uri.userInfo.isNotEmpty ||
          uri.hasPort ||
          ![
            'raw.githubusercontent.com',
            'github.com',
            'release-assets.githubusercontent.com',
            'objects.githubusercontent.com',
          ].contains(uri.host))
        throw const UpdateFailure();
      final request = await client
          .getUrl(uri)
          .timeout(const Duration(seconds: 20));
      request.followRedirects = false;
      request.headers.set(
        HttpHeaders.userAgentHeader,
        'ByteLocker/$clientVersion',
      );
      final response = await request.close().timeout(
        const Duration(seconds: 30),
      );
      if ([301, 302, 303, 307, 308].contains(response.statusCode)) {
        final location = response.headers.value(HttpHeaders.locationHeader);
        await response.drain<void>();
        if (location == null) throw const UpdateFailure();
        uri = uri.resolve(location);
        continue;
      }
      return response;
    }
    throw const UpdateFailure();
  }

  Future<void> check({bool manual = false}) async {
    if (!supported || checking || installing) return;
    checking = true;
    message = null;
    _changed();
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 20);
    try {
      final response = await _get(
        client,
        Uri.parse(
          'https://raw.githubusercontent.com/Samu3k/ByteLocker/main/updates/$_platform.json',
        ),
      );
      if (response.statusCode != 200) throw const UpdateFailure();
      final builder = BytesBuilder(copy: false);
      var count = 0;
      await for (final chunk in response.timeout(const Duration(seconds: 30))) {
        count += chunk.length;
        if (count > maxManifestBytes) throw const UpdateFailure();
        builder.add(chunk);
      }
      final manifest = await UpdateManifest.verify(
        builder.takeBytes(),
        platform: _platform,
      );
      if (!_alive) return;
      available = manifest.build > clientBuild ? manifest : null;
      if (manual && available == null)
        message = 'Stai usando l’ultima versione disponibile.';
    } catch (_) {
      if (manual)
        message = 'Controllo aggiornamenti non riuscito. Riprova più tardi.';
    } finally {
      client.close(force: true);
      checking = false;
      _changed();
    }
  }

  Future<void> install() async {
    final manifest = available;
    if (manifest == null || installing || !supported) return;
    installing = true;
    message = null;
    _changed();
    Directory? stage;
    final client = HttpClient();
    var handedOff = false, helperStarted = false;
    try {
      stage = await Directory.systemTemp.createTemp('bytelocker-update-');
      final archive = File(
        '${stage.path}/${Platform.isWindows ? 'update.zip' : 'update.apk'}',
      );
      final response = await _get(client, manifest.url);
      if (response.statusCode != 200) throw const UpdateFailure();
      var count = 0;
      final sink = archive.openWrite();
      try {
        await for (final chunk in response.timeout(
          const Duration(seconds: 30),
        )) {
          count += chunk.length;
          if (count > manifest.size) throw const UpdateFailure();
          sink.add(chunk);
        }
      } finally {
        await sink.close();
      }
      if (count != manifest.size) throw const UpdateFailure();
      final digest = (await Sha256().hash(await archive.readAsBytes())).bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      if (digest != manifest.sha256) throw const UpdateFailure();
      if (!_alive ||
          vaultCanRestart?.call() == false ||
          !(await (prepareInstall?.call() ?? Future.value(true)))) {
        message = 'Salva o annulla le modifiche e completa le operazioni in attesa prima di aggiornare.';
        return;
      }
      if (Platform.isAndroid) {
        await native.invokeMethod('installUpdate', archive.path);
        message = 'Conferma l’aggiornamento nella schermata Android. Poi riapri ByteLocker.';
      } else {
        final installDir = File(Platform.resolvedExecutable).parent;
        final existing = File('${installDir.path}/ByteLockerUpdater.exe');
        if (!await existing.exists()) throw const UpdateFailure();
        final helper = await existing.copy(
          '${stage.path}/ByteLockerUpdater.exe',
        );
        final signed = File('${stage.path}/manifest.json');
        await signed.writeAsBytes(manifest.signedBytes, flush: true);
        final nonce = List<int>.generate(
          16,
          (_) => Random.secure().nextInt(256),
        ).map((v) => v.toRadixString(16).padLeft(2, '0')).join();
        final ready = File('${stage.path}/ready');
        await Process.start(
          helper.path,
          [
            '--target',
            installDir.path,
            '--archive',
            archive.path,
            '--manifest',
            signed.path,
            '--parent-pid',
            '$pid',
            '--current-build',
            '$clientBuild',
            '--ready',
            ready.path,
            '--nonce',
            nonce,
          ],
          mode: ProcessStartMode.detached,
          workingDirectory: stage.path,
        );
        helperStarted = true;
        var accepted = false;
        for (var i = 0; i < 600; i++) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
          if (await ready.exists() && await ready.readAsString() == nonce) {
            accepted = true;
            break;
          }
        }
        if (!accepted) throw const UpdateFailure();
        handedOff = true;
        exit(0);
      }
    } catch (error) {
      message = error is PlatformException && error.code == 'INSTALL_PERMISSION'
          ? 'Consenti gli aggiornamenti da ByteLocker nelle impostazioni Android, poi torna qui e riprova.'
          : 'Aggiornamento non completato. L’installazione attuale e il profilo sono conservati. Puoi usare il pacchetto su GitHub.';
    } finally {
      client.close(force: true);
      if (stage != null && !handedOff) {
        if (helperStarted)
          await File('${stage.path}/cancel').writeAsString('cancel');
        for (final name in [
          'update.zip',
          'update.apk',
          'manifest.json',
          'ready',
        ]) {
          final file = File('${stage.path}/$name');
          if (await file.exists())
            try {
              await file.delete();
            } catch (_) {}
        }
        try {
          await stage.delete();
        } catch (_) {}
      }
      installing = false;
      _changed();
    }
  }
}

class UpdateScope extends InheritedNotifier<UpdateController> {
  const UpdateScope({
    super.key,
    required UpdateController updates,
    required super.child,
  }) : super(notifier: updates);
  static UpdateController? maybeOf(BuildContext context) =>
      context.dependOnInheritedWidgetOfExactType<UpdateScope>()?.notifier;
}
