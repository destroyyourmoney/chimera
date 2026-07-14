// Pings every saved server via `chimera health -json` (cmd/chimera
// healthCmd -> internal/healthreport) so the Servers list can show live
// latency per row -- purely informational. This deliberately does NOT pick
// a "best" server and auto-connect to it: `internal/api`'s AutoPool already
// races/fails over across every saved server live at dial time (see
// ROADMAP.md Этап 4), which is a better, continuously-updated version of
// "connect to the fastest one" than a static pre-connect snapshot could be.
// A one-shot latency readout is the part that pool doesn't already give you
// before you hit Connect.
//
// One `chimera health` subprocess per server (not a single call with a
// comma-separated -server list), because each saved server can carry its
// own pbk/sni/sid and `chimera health` only accepts one pbk/sni/sid shared
// across all hosts in a single invocation.
import 'dart:convert';
import 'dart:io';

import 'chimera_bindings.dart';
import 'network_protection.dart';
import 'settings_store.dart';

class ServerPingResult {
  const ServerPingResult({required this.ok, this.rttMs = 0, this.error = ''});
  final bool ok;
  final int rttMs;
  final String error;
}

class ServerPing {
  /// Returns a result per input server, keyed by [ServerEntry.id]. Servers
  /// whose link fails to parse, or whose ping times out/errors, come back
  /// as a not-OK result rather than being omitted, so callers can render a
  /// "failed" state instead of leaving stale UI.
  static Future<Map<String, ServerPingResult>> pingAll(
    List<ServerEntry> servers,
    ChimeraNativeApi bindings,
  ) async {
    final exe = NetworkProtection.chimeraExePath();
    if (!await File(exe).exists()) {
      return {
        for (final s in servers)
          s.id: const ServerPingResult(
            ok: false,
            error: 'chimera.exe not found next to the app',
          ),
      };
    }
    final entries = await Future.wait(
      servers.map((s) async => MapEntry(s.id, await _pingOne(exe, bindings, s))),
    );
    return Map.fromEntries(entries);
  }

  static Future<ServerPingResult> _pingOne(
    String exe,
    ChimeraNativeApi bindings,
    ServerEntry entry,
  ) async {
    try {
      final env =
          jsonDecode(bindings.parseLink(entry.link)) as Map<String, dynamic>;
      final parseErr = env['error'] as String? ?? '';
      if (parseErr.isNotEmpty) {
        return ServerPingResult(ok: false, error: parseErr);
      }
      final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
      final host = p['Host'] as String? ?? '';
      final port = p['Port'] as String? ?? '';
      final pbk = p['Pbk'] as String? ?? '';
      final sni = p['Sni'] as String? ?? '';
      final sid = p['Sid'] as String? ?? '';
      if (host.isEmpty || pbk.isEmpty) {
        return const ServerPingResult(ok: false, error: 'unparseable link');
      }

      final result = await Process.run(exe, [
        'health',
        '-server',
        '$host:$port',
        '-pbk',
        pbk,
        if (sni.isNotEmpty) ...['-sni', sni],
        if (sid.isNotEmpty) ...['-sid', sid],
        '-json',
      ]).timeout(
        const Duration(seconds: 8),
        onTimeout: () => ProcessResult(0, 1, '', 'timed out'),
      );
      final out = (result.stdout as String).trim();
      if (out.isEmpty) {
        final err = (result.stderr as String).trim();
        return ServerPingResult(ok: false, error: err.isEmpty ? 'no response' : err);
      }
      final decoded = jsonDecode(out) as List<dynamic>;
      if (decoded.isEmpty) {
        return const ServerPingResult(ok: false, error: 'no response');
      }
      final r = decoded.first as Map<String, dynamic>;
      if (r['ok'] != true) {
        return ServerPingResult(
          ok: false,
          error: r['error'] as String? ?? 'unreachable',
        );
      }
      return ServerPingResult(ok: true, rttMs: r['rtt_ms'] as int? ?? 0);
    } catch (e) {
      return ServerPingResult(ok: false, error: e.toString());
    }
  }
}
