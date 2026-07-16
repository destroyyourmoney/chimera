// Support screen: export a redacted diagnostics report to attach to a
// support request, plus a short note on where the operator/self-hosted
// documentation lives. CHIMERA is self-hosted (bring-your-own-server, no
// central account/subscription) so there's no "contact support" URL to
// link -- the operator running the server is the point of contact.
import 'package:flutter/material.dart';

import 'chimera_service.dart';
import 'diagnostics.dart';
import 'speed_sparkline.dart';
import 'theme.dart';

class SupportPage extends StatefulWidget {
  const SupportPage({
    super.key,
    required this.buildReport,
    this.state,
    this.downSamples = const [],
  });

  /// Builds the report text on demand (so it reflects the latest state at
  /// export time, not whenever this screen was opened).
  final String Function() buildReport;

  /// Live connection state for the throughput/endpoint-health section below
  /// -- moved here from Home (ROADMAP2 redesign: the artifact's Home is just
  /// the signal core + one server card + one latency pill, with no
  /// per-endpoint RTT table or sparkline). Null/empty on a build that hasn't
  /// wired a live tunnel yet.
  final ChimeraState? state;
  final List<double> downSamples;

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

  String _fmtBytes(int n) {
    if (n < 1024) return '$n B';
    if (n < 1024 * 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
    return '${(n / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final state = widget.state;
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Support')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        children: [
          if (state != null && state.isConnected) ...[
            _sectionLabel(tokens, 'Live connection'),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: tokens.surface2,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Theme.of(context).dividerColor),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: _metric(
                          context,
                          tokens,
                          label: 'UPLOAD',
                          value: '${_fmtBytes(state.bytesUp)}/s',
                        ),
                      ),
                      Expanded(
                        child: _metric(
                          context,
                          tokens,
                          label: 'DOWNLOAD',
                          value: '${_fmtBytes(state.bytesDown)}/s',
                        ),
                      ),
                    ],
                  ),
                  if (widget.downSamples.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    SpeedSparkline(
                      samples: widget.downSamples,
                      color: scheme.primary,
                    ),
                  ],
                ],
              ),
            ),
            if (state.endpoints.isNotEmpty) ...[
              const SizedBox(height: 16),
              _sectionLabel(tokens, 'Endpoint health'),
              const SizedBox(height: 8),
              _endpointHealth(context, tokens, state),
            ],
            const SizedBox(height: 20),
          ],
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

  Widget _sectionLabel(ChimeraTokens tokens, String text) => Text(
    text.toUpperCase(),
    style: TextStyle(
      fontFamily: 'Plex Sans',
      fontSize: 11,
      fontWeight: FontWeight.w600,
      letterSpacing: 0.6,
      color: tokens.textFaint,
    ),
  );

  Widget _metric(
    BuildContext context,
    ChimeraTokens tokens, {
    required String label,
    required String value,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: TextStyle(
            fontFamily: 'Plex Sans',
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.4,
            color: tokens.textFaint,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          value,
          style: monoStyle(
            fontSize: 15,
            weight: FontWeight.w500,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
      ],
    );
  }

  Widget _endpointHealth(
    BuildContext context,
    ChimeraTokens tokens,
    ChimeraState state,
  ) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(11),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Column(
        children: [
          for (var i = 0; i < state.endpoints.length; i++) ...[
            if (i > 0)
              Divider(height: 1, color: Theme.of(context).dividerColor),
            Padding(
              padding: const EdgeInsets.symmetric(
                horizontal: 12,
                vertical: 10,
              ),
              child: Row(
                children: [
                  Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: state.endpoints[i].healthy
                          ? scheme.primary
                          : scheme.error,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      state.endpoints[i].server,
                      overflow: TextOverflow.ellipsis,
                      style: monoStyle(fontSize: 12.5),
                    ),
                  ),
                  Text(
                    '${state.endpoints[i].rttMs} ms',
                    style: monoStyle(fontSize: 12, color: tokens.textMuted),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}
