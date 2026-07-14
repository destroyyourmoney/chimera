// Support screen: export a redacted diagnostics report to attach to a
// support request, plus a short note on where the operator/self-hosted
// documentation lives. CHIMERA is self-hosted (bring-your-own-server, no
// central account/subscription) so there's no "contact support" URL to
// link -- the operator running the server is the point of contact.
import 'package:flutter/material.dart';

import 'diagnostics.dart';
import 'theme.dart';

class SupportPage extends StatefulWidget {
  const SupportPage({super.key, required this.buildReport});

  /// Builds the report text on demand (so it reflects the latest state at
  /// export time, not whenever this screen was opened).
  final String Function() buildReport;

  @override
  State<SupportPage> createState() => _SupportPageState();
}

class _SupportPageState extends State<SupportPage> {
  bool _exporting = false;

  Future<void> _export() async {
    setState(() => _exporting = true);
    try {
      final path = await Diagnostics.saveReport(widget.buildReport());
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(path == null ? 'Export cancelled' : 'Saved to $path'),
        ),
      );
    } finally {
      if (mounted) setState(() => _exporting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      appBar: AppBar(title: const Text('Support')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        children: [
          Text(
            'CHIMERA is self-hosted: there\'s no CHIMERA account or central '
            'support desk. Whoever runs your server is your point of '
            'contact -- share the diagnostics export below with them.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12.5,
              color: tokens.textMuted,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 16),
          Text(
            'The export includes connection state, endpoint health, and '
            'your settings -- server public keys and short IDs are blanked '
            'out, they act as credentials.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12,
              color: tokens.textFaint,
              height: 1.35,
            ),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: _exporting ? null : _export,
              icon: const Icon(Icons.file_download_outlined, size: 18),
              label: Text(
                _exporting ? 'Exporting…' : 'Export diagnostics',
              ),
            ),
          ),
        ],
      ),
    );
  }
}
