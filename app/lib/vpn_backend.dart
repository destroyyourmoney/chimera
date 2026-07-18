import 'dart:io';

import 'package:flutter/services.dart';

import 'nethelper_client.dart';

class VpnBackendResult {
  const VpnBackendResult({required this.ok, this.error = ''});
  final bool ok;
  final String error;
}

abstract class VpnBackend {
  factory VpnBackend.forPlatform() {
    if (Platform.isAndroid) return AndroidVpnServiceBackend();
    return WindowsHelperVpnBackend();
  }

  Future<bool> isReady();

  Future<VpnBackendResult> start({
    required String server,
    required String pbk,
    required String mode,
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '',
  });

  Future<VpnBackendResult> stop();
}

class WindowsHelperVpnBackend implements VpnBackend {
  final _client = NetHelperClient();

  @override
  Future<bool> isReady() async => (await _client.ping()).ok;

  @override
  Future<VpnBackendResult> start({
    required String server,
    required String pbk,
    required String mode,
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '',
  }) async {
    final r = await _client.start(
      server: server,
      pbk: pbk,
      mode: mode,
      sni: sni,
      sid: sid,
      dns: dns,
      transport: transport,
      token: token,
    );
    return VpnBackendResult(ok: r.ok, error: r.error);
  }

  @override
  Future<VpnBackendResult> stop() async {
    final r = await _client.stop();
    return VpnBackendResult(ok: r.ok, error: r.error);
  }
}

class AndroidVpnServiceBackend implements VpnBackend {
  static const _channel = MethodChannel('chimera/vpn');

  @override
  Future<bool> isReady() async {
    try {
      return await _channel.invokeMethod<bool>('isPrepared') ?? false;
    } on PlatformException {
      return false;
    }
  }

  @override
  Future<VpnBackendResult> start({
    required String server,
    required String pbk,
    required String mode,
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '',
  }) async {
    try {
      await _channel.invokeMethod('start', {
        'server': server,
        'pbk': pbk,
        'mode': mode,
        'sni': sni,
        'sid': sid,
        'dns': dns,
        'transport': transport,
        'token': token,
      });
      return const VpnBackendResult(ok: true);
    } on PlatformException catch (e) {
      return VpnBackendResult(ok: false, error: e.message ?? e.code);
    }
  }

  @override
  Future<VpnBackendResult> stop() async {
    try {
      await _channel.invokeMethod('stop');
      return const VpnBackendResult(ok: true);
    } on PlatformException catch (e) {
      return VpnBackendResult(ok: false, error: e.message ?? e.code);
    }
  }
}
