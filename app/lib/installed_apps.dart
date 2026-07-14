// Enumerates installed apps for the split-tunnel picker
// (docs/app/platform-features.md §2). No native/Go plumbing needed for this
// -- `Get-StartApps` (built into Windows PowerShell) lists every Start Menu
// entry (desktop shortcuts + UWP packages) with a stable AppID, which is
// exactly the identifier a future WFP app-id filter or `addAllowedApplication`
// equivalent would key on. Same "shell out to PowerShell" pattern already
// used by `internal/provision` for operator commands.
import 'dart:convert';
import 'dart:io';

import 'settings_store.dart';

class InstalledApps {
  /// Returns the installed-apps list sorted by display name. Empty (not an
  /// exception) on non-Windows or if the shell call fails -- the picker
  /// should degrade to "no apps found yet", never crash Settings.
  static Future<List<SplitTunnelApp>> list() async {
    if (!Platform.isWindows) return const [];
    try {
      final result = await Process.run('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        'Get-StartApps | ConvertTo-Json -Compress',
      ]);
      if (result.exitCode != 0) return const [];
      final out = (result.stdout as String).trim();
      if (out.isEmpty) return const [];
      final decoded = jsonDecode(out);
      // ConvertTo-Json emits a bare object (not a list) when there is
      // exactly one result -- normalize both shapes.
      final rawList = decoded is List ? decoded : [decoded];
      final apps = <SplitTunnelApp>[];
      for (final e in rawList) {
        if (e is! Map) continue;
        final name = e['Name'] as String? ?? '';
        final id = e['AppID'] as String? ?? '';
        if (name.isEmpty || id.isEmpty) continue;
        apps.add(SplitTunnelApp(id: id, name: name));
      }
      apps.sort(
        (a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()),
      );
      return apps;
    } catch (_) {
      return const [];
    }
  }
}
