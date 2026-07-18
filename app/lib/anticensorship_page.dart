import 'package:flutter/material.dart';

import 'settings_store.dart';
import 'theme.dart';

class _TransportSpec {
  const _TransportSpec({
    required this.mode,
    required this.name,
    required this.description,
    required this.speedPct,
    required this.stealthPct,
  });

  final ObfuscationMode mode;
  final String name;
  final String description;
  final int speedPct;
  final int stealthPct;
}

const _transports = <_TransportSpec>[
  _TransportSpec(
    mode: ObfuscationMode.reality,
    name: 'Reality',
    description:
        'Disguised as HTTPS to a real website. The best balance of speed '
        'and stealth -- the default for most people.',
    speedPct: 88,
    stealthPct: 92,
  ),
  _TransportSpec(
    mode: ObfuscationMode.quicH3,
    name: 'QUIC / H3',
    description:
        'Disguised as Chrome HTTP/3. Passes most DPI well; more sensitive '
        'to packet loss than Reality.',
    speedPct: 80,
    stealthPct: 85,
  ),
  _TransportSpec(
    mode: ObfuscationMode.shadowsocksAead,
    name: 'Shadowsocks-AEAD',
    description:
        'Minimal overhead, highest throughput. Does not disguise itself as '
        'any specific protocol -- to an observer, the traffic looks like '
        'random noise, not a known one.',
    speedPct: 97,
    stealthPct: 55,
  ),
  _TransportSpec(
    mode: ObfuscationMode.dnsOverTcp,
    name: 'DNS-over-TCP',
    description:
        'Disguised as DNS lookups. Slower than the others, but blocking it '
        'outright breaks DNS for the censor too -- a harder tradeoff to make.',
    speedPct: 38,
    stealthPct: 74,
  ),
];

class AnticensorshipPage extends StatefulWidget {
  const AnticensorshipPage({
    super.key,
    required this.current,
    required this.onChanged,
    this.availableTransportParams,
    this.embedded = false,
  });

  final ObfuscationMode current;
  final Future<void> Function(ObfuscationMode mode) onChanged;

  final bool embedded;

  final Set<String>? availableTransportParams;

  @override
  State<AnticensorshipPage> createState() => _AnticensorshipPageState();
}

class _AnticensorshipPageState extends State<AnticensorshipPage> {
  late ObfuscationMode _selected = widget.current;

  bool _isAvailable(ObfuscationMode mode) {
    final available = widget.availableTransportParams;
    if (available == null) return true;
    return available.contains(obfuscationModeQueryParam(mode));
  }

  Future<void> _select(ObfuscationMode mode) async {
    if (!_isAvailable(mode)) return;
    setState(() => _selected = mode);
    await widget.onChanged(mode);
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final content = SafeArea(
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
        children: _transports
            .map(
              (t) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _transportCard(context, tokens, t),
              ),
            )
            .toList(),
      ),
    );
    if (widget.embedded) return content;
    return Scaffold(
      appBar: AppBar(title: const Text('Anti-censorship')),
      body: content,
    );
  }

  Widget _transportCard(
    BuildContext context,
    ChimeraTokens tokens,
    _TransportSpec t,
  ) {
    final isSelected = _selected == t.mode;
    final isAvailable = _isAvailable(t.mode);
    final scheme = Theme.of(context).colorScheme;
    return Opacity(
      opacity: isAvailable ? 1 : 0.45,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: isAvailable ? () => _select(t.mode) : null,
          child: AnimatedContainer(
            duration: ChimeraMotion.fast,
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 13),
            decoration: BoxDecoration(
              color: isSelected ? tokens.accentSoft : tokens.surface2,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: isSelected
                    ? scheme.primary
                    : Theme.of(context).dividerColor,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      t.name,
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontSize: 13.5,
                        fontWeight: FontWeight.w600,
                        color: scheme.onSurface,
                      ),
                    ),
                    Icon(
                      isSelected
                          ? Icons.radio_button_checked
                          : Icons.radio_button_off,
                      size: 18,
                      color: isSelected ? scheme.primary : tokens.textFaint,
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  isAvailable
                      ? t.description
                      : 'Not available on the currently selected server.',
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 11.5,
                    height: 1.5,
                    color: tokens.textMuted,
                  ),
                ),
                const SizedBox(height: 10),
                Row(
                  children: [
                    Expanded(
                      child: _meter(context, tokens, 'Speed', t.speedPct),
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: _meter(context, tokens, 'Stealth', t.stealthPct),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _meter(
    BuildContext context,
    ChimeraTokens tokens,
    String label,
    int pct,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label.toUpperCase(),
          style: monoStyle(
            fontSize: 9.5,
            weight: FontWeight.w600,
            color: tokens.textFaint,
          ),
        ),
        const SizedBox(height: 4),
        ClipRRect(
          borderRadius: BorderRadius.circular(2),
          child: LinearProgressIndicator(
            value: pct / 100,
            minHeight: 4,
            backgroundColor: tokens.neutralPill,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
      ],
    );
  }
}
