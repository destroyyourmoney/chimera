import 'dart:convert';

import 'package:file_selector/file_selector.dart';

import 'chimera_service.dart';
import 'settings_store.dart';

class Diagnostics {
  static String buildReport({
    required ChimeraSettings settings,
    required ChimeraState state,
    required String appVersion,
  }) {
    final buf = StringBuffer()
      ..writeln('CHIMERA tray diagnostics report')
      ..writeln('App version: $appVersion')
      ..writeln('Generated: ${DateTime.now().toIso8601String()}')
      ..writeln()
      ..writeln('-- Connection state --')
      ..writeln('State: ${state.state}')
      ..writeln('Transport: ${state.transport}')
      ..writeln(
        'Data flowed up/down: ${state.bytesUp > 0}/${state.bytesDown > 0}',
      )
      ..writeln(
        'Last error: ${state.lastError.isEmpty ? "(none)" : state.lastError}',
      )
      ..writeln('Endpoints:');
    if (state.endpoints.isEmpty) {
      buf.writeln('  (none)');
    }
    for (var i = 0; i < state.endpoints.length; i++) {
      final e = state.endpoints[i];
      buf.writeln(
        '  - endpoint ${i + 1}: healthy=${e.healthy} rtt=${e.rttMs}ms',
      );
    }
    buf
      ..writeln()
      ..writeln('-- Settings --')
      ..writeln('Servers saved: ${settings.servers.length}');
    for (var i = 0; i < settings.servers.length; i++) {
      buf.writeln(
        '  - server ${i + 1}: ${_redactLink(settings.servers[i].link)}',
      );
    }
    buf
      ..writeln('Autostart: ${settings.autostart}')
      ..writeln('Network protection: ${settings.networkProtection.name}')
      ..writeln('Custom DNS: ${settings.customDns.join(", ")}')
      ..writeln(
        'Split tunneling: enabled=${settings.splitTunnel.enabled} '
        'mode=${settings.splitTunnel.mode.name} '
        'apps=${settings.splitTunnel.apps.length}',
      );
    return buf.toString();
  }

  static String _redactLink(String link) {
    try {
      final uri = Uri.parse(link);
      final redacted = {
        for (final k in uri.queryParameters.keys)
          k: (k == 'pbk' || k == 'sid' || k == 'sni')
              ? '<redacted>'
              : uri.queryParameters[k]!,
      };
      return uri
          .replace(host: '<redacted>', queryParameters: redacted)
          .toString();
    } catch (_) {
      return '<unparseable link>';
    }
  }

  static Future<String?> saveReport(String report) async {
    const typeGroup = XTypeGroup(label: 'text', extensions: ['txt']);
    final location = await getSaveLocation(
      suggestedName: 'chimera-diagnostics.txt',
      acceptedTypeGroups: [typeGroup],
    );
    if (location == null) return null;
    final file = XFile.fromData(
      utf8.encode(report),
      mimeType: 'text/plain',
      name: 'chimera-diagnostics.txt',
    );
    await file.saveTo(location.path);
    return location.path;
  }
}
