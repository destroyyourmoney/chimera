import 'package:flutter/material.dart';

import 'settings_store.dart';
import 'theme.dart';

class VpnSettingsPage extends StatefulWidget {
  const VpnSettingsPage({
    super.key,
    required this.mode,
    required this.customDns,
    required this.busy,
    required this.hasServers,
    required this.onSetMode,
    required this.onSetCustomDns,
  });

  final NetworkProtectionMode mode;
  final List<String> customDns;
  final bool busy;
  final bool hasServers;
  final Future<bool> Function(NetworkProtectionMode mode) onSetMode;
  final Future<void> Function(List<String> dns) onSetCustomDns;

  @override
  State<VpnSettingsPage> createState() => _VpnSettingsPageState();
}

class _VpnSettingsPageState extends State<VpnSettingsPage> {
  late final TextEditingController _dnsCtrl;

  late NetworkProtectionMode _mode;

  @override
  void initState() {
    super.initState();
    _dnsCtrl = TextEditingController(text: widget.customDns.join(', '));
    _mode = widget.mode;
  }

  @override
  void dispose() {
    _dnsCtrl.dispose();
    super.dispose();
  }

  Future<void> _setMode(NetworkProtectionMode v) async {
    final prev = _mode;
    setState(() => _mode = v);

    final ok = await widget.onSetMode(v);
    if (!ok && mounted) setState(() => _mode = prev);
  }

  void _submitDns() {
    final servers = _dnsCtrl.text
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    widget.onSetCustomDns(servers);
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(const SnackBar(content: Text('Custom DNS servers saved')));
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final canEdit = !widget.busy && widget.hasServers;
    return Scaffold(
      appBar: AppBar(title: const Text('VPN settings')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 12, 20, 24),
        children: [
          _sectionLabel(tokens, 'Network protection'),
          const SizedBox(height: 2),
          Text(
            'Runs a real full-tunnel TUN device with OS-level firewall '
            'rules (one UAC prompt, or none once chimera-helper is '
            'installed).',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12,
              color: tokens.textFaint,
              height: 1.3,
            ),
          ),
          if (!widget.hasServers)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(
                'Add a server first.',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 12,
                  color: tokens.warn,
                ),
              ),
            ),
          const SizedBox(height: 6),
          _modeTile(
            tokens,
            value: NetworkProtectionMode.dnsLeakGuard,
            title: 'DNS leak guard',
            subtitle: 'Blocks outbound DNS on non-tunnel interfaces.',
            canEdit: canEdit,
          ),
          _modeTile(
            tokens,
            value: NetworkProtectionMode.killswitch,
            title: 'Kill switch',
            subtitle:
                'Blocks ALL outbound traffic except the tunnel, loopback, '
                'and the server itself.',
            canEdit: canEdit,
          ),
          const SizedBox(height: 20),
          Divider(height: 1, color: Theme.of(context).dividerColor),
          const SizedBox(height: 16),
          _sectionLabel(tokens, 'Custom DNS servers'),
          const SizedBox(height: 8),
          TextField(
            controller: _dnsCtrl,
            decoration: const InputDecoration(
              labelText: 'Comma-separated IPv4 addresses',
              hintText: '1.1.1.1, 8.8.8.8',
            ),
            onSubmitted: (_) => _submitDns(),
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerLeft,
            child: FilledButton(
              onPressed: _submitDns,
              child: const Text('Save'),
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Applies the next time network protection is turned on. If '
            'it\'s already on, turn it off and back on to pick up the change.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 11.5,
              color: tokens.textFaint,
              height: 1.3,
            ),
          ),
        ],
      ),
    );
  }

  Widget _sectionLabel(ChimeraTokens tokens, String text) {
    return Text(
      text.toUpperCase(),
      style: TextStyle(
        fontFamily: 'Plex Sans',
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.6,
        color: tokens.textFaint,
      ),
    );
  }

  Widget _modeTile(
    ChimeraTokens tokens, {
    required NetworkProtectionMode value,
    required String title,
    required String subtitle,
    required bool canEdit,
  }) {
    return RadioListTile<NetworkProtectionMode>(
      value: value,
      // ignore: deprecated_member_use
      groupValue: _mode,
      // ignore: deprecated_member_use
      onChanged: canEdit ? (v) => _setMode(v!) : null,
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
