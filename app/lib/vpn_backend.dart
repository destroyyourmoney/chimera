// Platform-specific network layer abstraction (ROADMAP2 §4 Android): one
// Dart codebase, two backends. `WindowsHelperVpnBackend` wraps the existing
// `nethelper_client.dart` (chimera-helper, elevated Windows service);
// `AndroidVpnServiceBackend` talks to a Kotlin `ChimeraVpnService`
// (android.net.VpnService) over a MethodChannel, backed by the real
// gomobile-compiled Go tunnel (see ChimeraVpnService.kt's RealGoTunnel).
// Everything above this abstraction (Home's connect button, catalog/
// anticensorship selection) stays platform-agnostic. `main.dart` reaches
// Android through `AndroidNetworkProtectionController`
// (network_protection.dart), not this class directly -- see
// `TunnelService`'s constructor in chimera_service.dart for the platform
// pick.
import 'dart:io';

import 'package:flutter/services.dart';

import 'nethelper_client.dart';

/// Uniform result shape across both backends -- NetHelperResult already has
/// this shape on Windows; AndroidVpnServiceBackend adapts its MethodChannel
/// replies into the same thing.
class VpnBackendResult {
  const VpnBackendResult({required this.ok, this.error = ''});
  final bool ok;
  final String error;
}

abstract class VpnBackend {
  /// Picks the backend for the current platform. Call once; the result is
  /// cheap to hold for the app's lifetime.
  factory VpnBackend.forPlatform() {
    if (Platform.isAndroid) return AndroidVpnServiceBackend();
    return WindowsHelperVpnBackend();
  }

  /// Whether this backend's OS-level prerequisite is satisfied (helper
  /// service installed on Windows; VpnService consent granted on Android).
  /// `start` may still prompt for it lazily -- this is for UI that wants to
  /// show/hide an "enable" affordance ahead of time.
  Future<bool> isReady();

  /// Brings the full-tunnel up against the given curated/BYO server.
  Future<VpnBackendResult> start({
    required String server,
    required String pbk,
    required String mode, // 'dnsLeakGuard' | 'killswitch'
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '', // control-plane capability token, ROADMAP2 §1
  });

  Future<VpnBackendResult> stop();
}

/// Windows backend: thin adapter over the existing chimera-helper client --
/// no behavior change from before this abstraction existed.
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

/// Android backend: MethodChannel to the Kotlin ChimeraVpnService. The
/// channel name/method shapes here must match
/// MainActivity.kt's configureFlutterEngine exactly.
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
