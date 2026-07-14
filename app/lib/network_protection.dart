// OS-level network protection toggle: shells out to the bundled chimera.exe
// CLI's existing, already-tested `chimera tun -setup-firewall
// [-setup-killswitch]`/`-setup-restore` machinery (internal/winnet) instead
// of reimplementing firewall/elevation logic here. `-setup-elevate` makes the
// CLI itself re-launch through the Windows UAC prompt
// (internal/winnet.Elevate / ElevatePowerShell), so this file only assembles
// the argument list -- one UAC prompt per enable/disable, no persistent
// elevated service.
//
// Two tiers, both requiring a real full-tunnel TUN device
// (`-setup-os`) alongside the firewall rules, since the rules are scoped to
// that TUN interface alias -- separate from the TUN-less SOCKS5 path the
// rest of the tray app uses:
//   - [NetworkProtectionMode.dnsLeakGuard]: blocks outbound DNS on
//     non-tunnel interfaces only.
//   - [NetworkProtectionMode.killswitch]: blocks ALL outbound traffic except
//     the TUN device, loopback, and the resolved server endpoints.
import 'dart:io';

import 'settings_store.dart';

class NetworkProtectionResult {
  const NetworkProtectionResult({required this.ok, this.error = ''});
  final bool ok;
  final String error;
}

class NetworkProtection {
  /// chimeraExePath resolves chimera.exe next to the running executable,
  /// same convention chimera.dll already uses (see chimera_bindings.dart).
  static String chimeraExePath() {
    final dir = File(Platform.resolvedExecutable).parent.path;
    return '$dir/chimera.exe';
  }

  static Future<bool> isAvailable() => File(chimeraExePath()).exists();

  /// enable brings up a full-tunnel TUN device with the requested tier of
  /// firewall protection installed, through one elevated UAC prompt.
  static Future<NetworkProtectionResult> enable({
    required NetworkProtectionMode mode,
    required String server,
    required String pbk,
    String sni = '',
    String sid = '',
    String dev = '',
    List<String> dns = kDefaultCustomDns,
  }) {
    assert(mode != NetworkProtectionMode.off);
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
    ];
    return _run(args);
  }

  /// disable restores routes/DNS and removes the firewall rules (including
  /// resetting the killswitch's DefaultOutboundAction override, unconditionally
  /// -- see internal/winnet.RestorePowerShell), through one elevated UAC prompt.
  static Future<NetworkProtectionResult> disable({String dev = ''}) {
    final args = [
      'tun',
      '-setup-elevate',
      '-setup-restore',
      if (dev.isNotEmpty) ...['-dev', dev],
    ];
    return _run(args);
  }

  static Future<NetworkProtectionResult> _run(List<String> args) async {
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
