// User interface settings screen: launch-at-login and a note about theming.
// Actual platform calls (launch_at_startup) live in HomePage/_HomePageState.
import 'package:flutter/material.dart';

import 'theme.dart';

class UiSettingsPage extends StatefulWidget {
  const UiSettingsPage({
    super.key,
    required this.autostart,
    required this.busy,
    required this.onToggleAutostart,
  });

  final bool autostart;
  final bool busy;
  final ValueChanged<bool> onToggleAutostart;

  @override
  State<UiSettingsPage> createState() => _UiSettingsPageState();
}

class _UiSettingsPageState extends State<UiSettingsPage> {
  // Mirrors widget.autostart locally: this page is pushed as its own route,
  // so HomePage's setState() after the value actually changes can't reach an
  // already-built UiSettingsPage (see VpnSettingsPage's _mode for the same
  // issue/fix). Optimistic -- launch_at_startup enable/disable is treated as
  // best-effort everywhere else in this app too.
  late bool _autostart;

  @override
  void initState() {
    super.initState();
    _autostart = widget.autostart;
  }

  void _toggle(bool v) {
    setState(() => _autostart = v);
    widget.onToggleAutostart(v);
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      appBar: AppBar(title: const Text('User interface settings')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 6),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Launch at login',
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 13.5,
                          fontWeight: FontWeight.w500,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Starts CHIMERA in the tray when you sign in.',
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 12,
                          color: tokens.textFaint,
                          height: 1.3,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                Switch(
                  value: _autostart,
                  onChanged: widget.busy ? null : _toggle,
                ),
              ],
            ),
          ),
          Divider(height: 32, color: Theme.of(context).dividerColor),
          Text(
            'Appearance',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 11,
              fontWeight: FontWeight.w600,
              letterSpacing: 0.6,
              color: tokens.textFaint,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Follows your system light/dark theme automatically. A manual '
            'override isn\'t offered yet.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12.5,
              color: tokens.textMuted,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}
