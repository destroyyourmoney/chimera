// OS-level network protection toggle. Two backends:
//
//   1. chimera-helper (preferred): a persistent, already-elevated Windows
//      service (see internal/nethelper's doc comment and
//      nethelper_client.dart) that owns the actual TUN/routes/DNS/firewall
//      setup. Once installed, enable/disable are a local authenticated TCP
//      call with NO UAC prompt -- this is what lets a plain "Connect" bring
//      up full-tunnel protection by default (main.dart's _connect) instead
//      of staying SOCKS5-only.
//   2. Direct CLI elevation (fallback): shells out to the bundled
//      chimera.exe's `tun -setup-elevate -setup-os ...` machinery
//      (internal/winnet), UAC-prompting on every single call. Used only
//      when chimera-helper isn't installed yet, so the existing Settings
//      toggle still works for anyone who hasn't opted into the helper.
//
// Both tiers require a real full-tunnel TUN device alongside the firewall
// rules, since the rules are scoped to that TUN interface alias. The tray
// app is TUN-only -- there is no SOCKS5 fallback -- so Connect always goes
// through one of these two tiers:
//   - [NetworkProtectionMode.dnsLeakGuard]: blocks outbound DNS on
//     non-tunnel interfaces only.
//   - [NetworkProtectionMode.killswitch]: blocks ALL outbound traffic except
//     the TUN device, loopback, and the resolved server endpoints.
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

/// NetworkProtectionController is the interface TunnelService (see
/// chimera_service.dart) depends on for the TUN-only connect flow --
/// factored out of the concrete NetworkProtection/NetHelperClient calls so
/// tests can inject a fake instead of driving real chimera-helper IPC and
/// process elevation.
abstract class NetworkProtectionController {
  Future<NetworkProtectionResult> engage({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    List<String> dns = kDefaultCustomDns,
    String transport = '',
    String token = '', // control-plane capability token, ROADMAP2 §1
  });
  Future<void> disengage();

  /// status reports the live state of a running tunnel (state/transport/
  /// bytesUp/bytesDown), sourced from chimera-helper's ping (see
  /// NetHelperClient.ping and internal/nethelper.Server.fillStats).
  Future<NetHelperResult> status();
}

/// DefaultNetworkProtectionController wraps the real NetworkProtection
/// static methods and NetHelperClient.ping.
class DefaultNetworkProtectionController implements NetworkProtectionController {
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

/// AndroidNetworkProtectionController is TunnelService's Android counterpart
/// to [DefaultNetworkProtectionController]: engage/disengage delegate to
/// [AndroidVpnServiceBackend] (the Kotlin ChimeraVpnService over
/// MethodChannel), and status polls that same channel's "status" case
/// (ChimeraVpnService.currentStatusJson, backed by chimeramobile.Tunnel's
/// stateJSON) rather than chimera-helper's Windows-only ping. There's no
/// CLI-elevation fallback tier here -- Android's VpnService consent prompt
/// (handled in MainActivity.kt) is the only permission step, nothing like
/// chimera-helper's install-once/UAC-once split applies.
class AndroidNetworkProtectionController implements NetworkProtectionController {
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
      mode: mode == NetworkProtectionMode.killswitch ? 'killswitch' : 'dnsLeakGuard',
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
      // api.StateSnapshot's vocabulary ("connecting"/"connected"/
      // "disconnected", see internal/api/api.go's State.String) differs from
      // chimera-helper's own ("idle"/"running", internal/nethelper/protocol.go)
      // -- NetHelperResult.isRunning checks for the literal string "running",
      // so translate here rather than change that shared getter.
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

  /// chimeraExePath resolves chimera.exe next to the running executable,
  /// same convention chimera.dll already uses (see chimera_bindings.dart).
  static String chimeraExePath() {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir/chimera.exe';
  }

  static String chimeraHelperExePath() {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir/chimera-helper.exe';
  }

  static Future<bool> isAvailable() => File(chimeraExePath()).exists();

  /// isHelperInstalled reports whether chimera-helper is installed, running,
  /// and reachable with this app's token -- i.e. whether enable()/disable()
  /// below will be UAC-free.
  static Future<bool> isHelperInstalled() async {
    final result = await _helper.ping();
    return result.ok;
  }

  /// installHelper registers and starts chimera-helper through one UAC
  /// prompt (`Start-Process -Verb RunAs`, same elevation mechanism
  /// internal/winnet.ElevatePowerShell already uses for the CLI fallback).
  /// After this succeeds, enable()/disable() -- and therefore a plain
  /// Connect -- no longer prompt for elevation.
  static Future<NetworkProtectionResult> installHelper() async {
    final exe = chimeraHelperExePath();
    if (!await File(exe).exists()) {
      return const NetworkProtectionResult(
        ok: false,
        error: 'chimera-helper.exe not found next to the app',
      );
    }
    try {
      // Start-Process -Verb RunAs -Wait: the same UAC-elevation pattern
      // internal/winnet.ElevatePowerShell renders for the CLI, done here
      // directly since chimera-helper.exe is a separate binary with no
      // -setup-elevate flag of its own.
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
      // installService (Go side) waits for the service to reach Running
      // before returning, but that's inside the elevated child; give the
      // freshly-started service a moment to open its listener before the
      // caller's first ping.
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

  /// enable brings up a full-tunnel TUN device with the requested tier of
  /// firewall protection installed. UAC-free once chimera-helper is
  /// installed; otherwise falls back to one elevated UAC prompt per call.
  static Future<NetworkProtectionResult> enable({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    String dev = '',
    List<String> dns = kDefaultCustomDns,
    /// Anti-censorship transport: '', 'auto', 'quic', or 'tcp' -- matches
    /// the per-server Mode a chimera:// link carries. Empty defers to
    /// chimera.exe tun's own "auto" default. This is the TUN path's
    /// equivalent of Mullvad's obfuscation method picker.
    String transport = '',
    // Control-plane capability token (ROADMAP2 §1) -- forwarded to
    // chimera.exe tun's own -token flag on both tiers below. Empty for
    // -auth-mode useracl servers/legacy BYO links, which don't need one.
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

  /// disable restores routes/DNS and removes the firewall rules (including
  /// resetting the killswitch's DefaultOutboundAction override, unconditionally
  /// -- see internal/winnet.RestorePowerShell). UAC-free once chimera-helper
  /// is installed; otherwise one elevated UAC prompt per call.
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
