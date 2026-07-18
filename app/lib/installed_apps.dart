import 'dart:convert';
import 'dart:io';

import 'settings_store.dart';

class InstalledApps {
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

      final rawList = decoded is List ? decoded : [decoded];
      final apps = <SplitTunnelApp>[];
      for (final e in rawList) {
        if (e is! Map) continue;
        final name = e['Name'] as String? ?? '';
        final id = e['AppID'] as String? ?? '';
        if (name.isEmpty || id.isEmpty) continue;
        apps.add(SplitTunnelApp(id: id, name: name));
      }
      apps.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
      return apps;
    } catch (_) {
      return const [];
    }
  }
}
