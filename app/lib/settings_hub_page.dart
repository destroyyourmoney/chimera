// Settings hub (Mullvad-style): a small gear icon on Home opens this list of
// rows -- VPN settings, User interface settings, Split tunneling, Support,
// App info -- each pushing its own sub-page, plus a bottom
// "Disconnect & quit" / "Quit" action. Replaces the old flat
// Settings/Split-tunneling nav rows on Home.
import 'package:flutter/material.dart';

import 'anti_censorship_page.dart';
import 'app_info.dart';
import 'app_info_page.dart';
import 'settings_store.dart';
import 'split_tunnel_page.dart';
import 'support_page.dart';
import 'theme.dart';
import 'ui_settings_page.dart';
import 'vpn_settings_page.dart';

class SettingsHubPage extends StatelessWidget {
  const SettingsHubPage({
    super.key,
    required this.settings,
    required this.busy,
    required this.isConnected,
    required this.onPersist,
    required this.onToggleAutostart,
    required this.onSetNetworkProtection,
    required this.onSetCustomDns,
    required this.onSetTransport,
    required this.buildDiagnosticsReport,
    required this.onDisconnectAndQuit,
  });

  final ChimeraSettings settings;
  final bool busy;
  final bool isConnected;
  final Future<void> Function() onPersist;
  final ValueChanged<bool> onToggleAutostart;
  final Future<void> Function(NetworkProtectionMode mode) onSetNetworkProtection;
  final Future<void> Function(List<String> dns) onSetCustomDns;
  final Future<void> Function(String transport) onSetTransport;
  final String Function() buildDiagnosticsReport;
  final VoidCallback onDisconnectAndQuit;

  String _networkProtectionLabel(NetworkProtectionMode m) {
    switch (m) {
      case NetworkProtectionMode.killswitch:
        return 'Kill switch';
      case NetworkProtectionMode.dnsLeakGuard:
        return 'DNS leak guard';
    }
  }

  String _transportLabel(String t) {
    switch (t) {
      case 'quic':
        return 'QUIC';
      case 'tcp':
        return 'TCP';
      default:
        return 'Automatic';
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: SafeArea(
        child: Column(
          children: [
            Expanded(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
                children: [
                  _hubRow(
                    context,
                    tokens,
                    title: 'VPN settings',
                    subtitle: _networkProtectionLabel(
                      settings.networkProtection,
                    ),
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => VpnSettingsPage(
                          mode: settings.networkProtection,
                          customDns: settings.customDns,
                          busy: busy,
                          hasServers: settings.servers.isNotEmpty,
                          onSetMode: onSetNetworkProtection,
                          onSetCustomDns: onSetCustomDns,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  _hubRow(
                    context,
                    tokens,
                    title: 'Anti-censorship',
                    subtitle: _transportLabel(settings.transport),
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => AntiCensorshipPage(
                          transport: settings.transport,
                          busy: busy,
                          onSetTransport: onSetTransport,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  _hubRow(
                    context,
                    tokens,
                    title: 'User interface settings',
                    subtitle: settings.autostart
                        ? 'Launch at login: on'
                        : 'Launch at login: off',
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => UiSettingsPage(
                          autostart: settings.autostart,
                          busy: busy,
                          onToggleAutostart: onToggleAutostart,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  _hubRow(
                    context,
                    tokens,
                    title: 'Split tunneling',
                    subtitle: settings.splitTunnel.enabled
                        ? '${settings.splitTunnel.apps.length} app(s), '
                              '${settings.splitTunnel.mode == SplitTunnelMode.include ? "include" : "exclude"}'
                        : 'Off',
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => SplitTunnelPage(
                          settings: settings.splitTunnel,
                          onChanged: onPersist,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  _hubRow(
                    context,
                    tokens,
                    title: 'Support',
                    onTap: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) =>
                            SupportPage(buildReport: buildDiagnosticsReport),
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  _hubRow(
                    context,
                    tokens,
                    title: 'App info',
                    subtitle: kAppVersion,
                    onTap: () => Navigator.of(
                      context,
                    ).push(MaterialPageRoute(builder: (_) => const AppInfoPage())),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: SizedBox(
                width: double.infinity,
                child: FilledButton(
                  style: FilledButton.styleFrom(
                    backgroundColor: Theme.of(context).colorScheme.error,
                    foregroundColor: Colors.white,
                  ),
                  onPressed: onDisconnectAndQuit,
                  child: Text(isConnected ? 'Disconnect & quit' : 'Quit'),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _hubRow(
    BuildContext context,
    ChimeraTokens tokens, {
    required String title,
    String? subtitle,
    required VoidCallback onTap,
  }) {
    return Material(
      color: tokens.surface2,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                        color: Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                    if (subtitle != null) ...[
                      const SizedBox(height: 2),
                      Text(
                        subtitle,
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 12,
                          color: tokens.textFaint,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              Icon(Icons.chevron_right, color: tokens.textFaint, size: 20),
            ],
          ),
        ),
      ),
    );
  }
}
