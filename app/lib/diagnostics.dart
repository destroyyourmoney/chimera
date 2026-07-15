// Diagnostics export for the Support screen: assembles a redacted text
// report (settings summary + last known connection state) the user can save
// and attach to a support request. Never writes secrets (server public key,
// short ID) in the clear -- both are effectively bearer credentials for the
// operator's server.
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
      ..writeln('Bytes up/down: ${state.bytesUp}/${state.bytesDown}')
      ..writeln('Last error: ${state.lastError.isEmpty ? "(none)" : state.lastError}')
      ..writeln('Endpoints:');
    if (state.endpoints.isEmpty) {
      buf.writeln('  (none)');
    }
    for (final e in state.endpoints) {
      buf.writeln('  - ${e.server}: healthy=${e.healthy} rtt=${e.rttMs}ms');
    }
    buf
      ..writeln()
      ..writeln('-- Settings --')
      ..writeln('Servers saved: ${settings.servers.length}');
    for (final s in settings.servers) {
      final label = s.label.isNotEmpty ? s.label : '(no label)';
      buf.writeln('  - $label: ${_redactLink(s.link)}');
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

  /// Keeps host/port and query parameter names, blanks out `pbk`/`sid`
  /// values -- those double as auth credentials for the server.
  static String _redactLink(String link) {
    try {
      final uri = Uri.parse(link);
      final redacted = {
        for (final k in uri.queryParameters.keys)
          k: (k == 'pbk' || k == 'sid')
              ? '<redacted>'
              : uri.queryParameters[k]!,
      };
      return uri.replace(queryParameters: redacted).toString();
    } catch (_) {
      return '<unparseable link>';
    }
  }

  /// Opens a native "Save as" dialog and writes the report there. Returns
  /// the saved path, or null if the user cancelled.
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
