// Anti-censorship method picker (Mullvad-style): a global override for
// which transport CHIMERA's TUN device uses, on top of whatever each
// server's own link already encodes (server_form.dart's per-link Mode
// picker). 'auto' defers to the server's own choice; 'quic'/'tcp' force
// that transport regardless. See settings_store.dart's
// ChimeraSettings.transport doc comment for the resolution rule.
import 'package:flutter/material.dart';

import 'theme.dart';

class AntiCensorshipPage extends StatefulWidget {
  const AntiCensorshipPage({
    super.key,
    required this.transport,
    required this.busy,
    required this.onSetTransport,
  });

  final String transport;
  final bool busy;
  final Future<void> Function(String transport) onSetTransport;

  @override
  State<AntiCensorshipPage> createState() => _AntiCensorshipPageState();
}

class _AntiCensorshipPageState extends State<AntiCensorshipPage> {
  // Mirrors widget.transport locally -- see VpnSettingsPage's _mode doc
  // comment for why a pushed route needs its own copy to be reactive.
  late String _transport;

  @override
  void initState() {
    super.initState();
    _transport = widget.transport;
  }

  void _setTransport(String v) {
    setState(() => _transport = v);
    widget.onSetTransport(v);
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      appBar: AppBar(title: const Text('Anti-censorship')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
        children: [
          Text(
            'Please note that these methods do not improve performance, '
            'and may increase system utilization and battery consumption.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12,
              color: tokens.textFaint,
              height: 1.3,
            ),
          ),
          const SizedBox(height: 12),
          _methodTile(
            context,
            tokens,
            value: 'auto',
            title: 'Automatic',
            subtitle:
                'Races QUIC and TCP and uses whichever connects first -- '
                'or each server\'s own configured method, if it has one.',
          ),
          _methodTile(
            context,
            tokens,
            value: 'quic',
            title: 'QUIC',
            subtitle:
                'Forces the QUIC (UDP-based) transport for every server. '
                'Faster, but more easily blocked or throttled by '
                'networks that restrict UDP.',
          ),
          _methodTile(
            context,
            tokens,
            value: 'tcp',
            title: 'TCP',
            subtitle:
                'Forces the TCP-based obfuscated transport for every '
                'server. Best at getting through networks that block or '
                'throttle UDP.',
          ),
        ],
      ),
    );
  }

  Widget _methodTile(
    BuildContext context,
    ChimeraTokens tokens, {
    required String value,
    required String title,
    required String subtitle,
  }) {
    return RadioListTile<String>(
      value: value,
      // ignore: deprecated_member_use
      groupValue: _transport,
      // ignore: deprecated_member_use
      onChanged: widget.busy ? null : (v) => _setTransport(v!),
      contentPadding: EdgeInsets.zero,
      dense: true,
      title: Text(
        title,
        style: TextStyle(
          fontFamily: 'Plex Sans',
          fontSize: 13.5,
          fontWeight: FontWeight.w500,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      ),
      subtitle: Text(
        subtitle,
        style: TextStyle(
          fontFamily: 'Plex Sans',
          fontSize: 12,
          color: tokens.textFaint,
          height: 1.3,
        ),
      ),
    );
  }
}
