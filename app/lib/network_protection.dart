import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import 'nethelper_client.dart';
import 'settings_store.dart';
import 'vpn_backend.dart';

class NetworkProtectionResult {
  const NetworkProtectionResult({required this.ok, this.error = ''});
  final bool ok;
  final String error;
}

abstract class NetworkProtectionController {
  Future<NetworkProtectionResult> engage({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    List<String> dns = kDefaultCustomDns,
    String transport = '',
    String token = '',
  });
  Future<void> disengage();

  Future<NetHelperResult> status();
}

class DefaultNetworkProtectionController
    implements NetworkProtectionController {
  @override
  Future<NetworkProtectionResult> engage({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    List<String> dns = kDefaultCustomDns,
    String transport = '',
    String token = '',
  }) => NetworkProtection.enable(
    mode: mode,
    server: server,
    pbk: pbk,
    sni: sni,
    sid: sid,
    dns: dns,
    transport: transport,
    token: token,
  );

  @override
  Future<void> disengage() async {
    await NetworkProtection.disable();
  }

  @override
  Future<NetHelperResult> status() => NetworkProtection._helper.ping();
}

class AndroidNetworkProtectionController
    implements NetworkProtectionController {
  static const _channel = MethodChannel('chimera/vpn');
  final VpnBackend _backend = VpnBackend.forPlatform();

  @override
  Future<NetworkProtectionResult> engage({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    List<String> dns = kDefaultCustomDns,
    String transport = '',
    String token = '',
  }) async {
    final r = await _backend.start(
      server: server,
      pbk: pbk,
      mode: mode == NetworkProtectionMode.killswitch
          ? 'killswitch'
          : 'dnsLeakGuard',
      sni: sni,
      sid: sid,
      dns: dns,
      transport: transport,
      token: token,
    );
    return NetworkProtectionResult(ok: r.ok, error: r.error);
  }

  @override
  Future<void> disengage() async {
    await _backend.stop();
  }

  @override
  Future<NetHelperResult> status() async {
    try {
      final raw = await _channel.invokeMethod<String>('status') ?? '{}';
      final json = jsonDecode(raw) as Map<String, dynamic>;

      final apiState = json['state'] as String? ?? 'disconnected';
      return NetHelperResult(
        ok: true,
        state: apiState == 'connected' ? 'running' : 'idle',
        transport: json['transport'] as String? ?? '',
        bytesUp: (json['bytesUp'] as num?)?.toInt() ?? 0,
        bytesDown: (json['bytesDown'] as num?)?.toInt() ?? 0,
      );
    } on PlatformException catch (e) {
      return NetHelperResult(ok: false, error: e.message ?? e.code);
    }
  }
}

class NetworkProtection {
  static final NetHelperClient _helper = NetHelperClient();

  static String chimeraExePath() {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir/chimera.exe';
  }

  static String chimeraHelperExePath() {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir/chimera-helper.exe';
  }

  static Future<bool> isAvailable() => File(chimeraExePath()).exists();

  static Future<bool> isHelperInstalled() async {
    final result = await _helper.ping();
    return result.ok;
  }

  static Future<NetworkProtectionResult> installHelper() async {
    final exe = chimeraHelperExePath();
    if (!await File(exe).exists()) {
      return const NetworkProtectionResult(
        ok: false,
        error: 'chimera-helper.exe not found next to the app',
      );
    }
    try {
      final psCommand =
          "Start-Process -FilePath '$exe' -ArgumentList 'install' -Verb RunAs -Wait";
      final result = await Process.run('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        psCommand,
      ]);
      if (result.exitCode != 0) {
        return NetworkProtectionResult(
          ok: false,
          error: (result.stderr as String).trim(),
        );
      }

      await Future.delayed(const Duration(milliseconds: 500));
      final ok = await isHelperInstalled();
      return NetworkProtectionResult(
        ok: ok,
        error: ok ? '' : 'helper installed but is not responding yet',
      );
    } catch (e) {
      return NetworkProtectionResult(ok: false, error: e.toString());
    }
  }

  static Future<NetworkProtectionResult> enable({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    String dev = '',
    List<String> dns = kDefaultCustomDns,

    String transport = '',

    String token = '',
  }) async {
    if (await isHelperInstalled()) {
      final helperResult = await _helper.start(
        server: server,
        pbk: pbk,
        mode: mode == NetworkProtectionMode.killswitch
            ? 'killswitch'
            : 'dnsLeakGuard',
        sni: sni,
        sid: sid,
        dns: dns,
        transport: transport,
        token: token,
      );
      return NetworkProtectionResult(
        ok: helperResult.ok,
        error: helperResult.error,
      );
    }

    final args = [
      'tun',
      '-setup-elevate',
      '-setup-os',
      '-setup-firewall',
      if (mode == NetworkProtectionMode.killswitch) '-setup-killswitch',
      '-setup-keep',
      '-server',
      server,
      '-pbk',
      pbk,
      if (sni.isNotEmpty) ...['-sni', sni],
      if (sid.isNotEmpty) ...['-sid', sid],
      if (dev.isNotEmpty) ...['-dev', dev],
      if (dns.isNotEmpty) ...['-dns', dns.join(',')],
      if (transport.isNotEmpty) ...['-transport', transport],
      if (token.isNotEmpty) ...['-token', token],
    ];
    return _runCli(args);
  }

  static Future<NetworkProtectionResult> disable({String dev = ''}) async {
    if (await isHelperInstalled()) {
      final helperResult = await _helper.stop();
      return NetworkProtectionResult(
        ok: helperResult.ok,
        error: helperResult.error,
      );
    }

    final args = [
      'tun',
      '-setup-elevate',
      '-setup-restore',
      if (dev.isNotEmpty) ...['-dev', dev],
    ];
    return _runCli(args);
  }

  static Future<NetworkProtectionResult> _runCli(List<String> args) async {
    final exe = chimeraExePath();
    if (!await File(exe).exists()) {
      return const NetworkProtectionResult(
        ok: false,
        error: 'chimera.exe not found next to the app',
      );
    }
    try {
      final result = await Process.run(exe, args);
      if (result.exitCode != 0) {
        return NetworkProtectionResult(
          ok: false,
          error: (result.stderr as String).trim(),
        );
      }
      return const NetworkProtectionResult(ok: true);
    } catch (e) {
      return NetworkProtectionResult(ok: false, error: e.toString());
    }
  }
}
