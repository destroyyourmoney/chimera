import 'dart:async';

import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'account_page.dart';
import 'account_store.dart';
import 'anticensorship_page.dart';
import 'app_info_page.dart';
import 'catalog_page.dart';
import 'chimera_service.dart';
import 'settings_hub_page.dart';
import 'settings_store.dart';
import 'split_tunnel_page.dart';
import 'support_page.dart';
import 'theme.dart';

enum _HeroVisualState { on, off, reconnect, fail }

enum ShellView {
  home,
  locations,
  split,
  anti,
  account,
  settings,
  support,
  about,
}

class FullWindowShell extends StatefulWidget {
  const FullWindowShell({
    super.key,
    this.initError,
    required this.state,
    required this.busy,
    required this.settings,
    required this.onToggleConnection,
    required this.selectedServer,
    required this.onToggleFavorite,
    required this.onSelectServer,
    required this.onSetObfuscationMode,
    required this.availableTransportParams,
    required this.onSplitTunnelChanged,
    required this.onLoggedOut,
    required this.onPersist,
    required this.onToggleAutostart,
    required this.onSetNetworkProtection,
    required this.onSetCustomDns,
    required this.buildDiagnosticsReport,
    required this.onDisconnectAndQuit,
    required this.onSetMinimizeToTray,
    this.downSamples = const [],
  });

  final String? initError;

  final ChimeraState state;
  final bool busy;
  final ChimeraSettings settings;
  final Future<void> Function() onToggleConnection;
  final ({String city, String country, String flag})? selectedServer;

  final Future<void> Function(String id) onToggleFavorite;
  final Future<void> Function(CatalogServer server) onSelectServer;

  final Future<void> Function(ObfuscationMode mode) onSetObfuscationMode;
  final Set<String>? availableTransportParams;

  final Future<void> Function() onSplitTunnelChanged;

  final Future<void> Function() onLoggedOut;

  final Future<void> Function() onPersist;
  final ValueChanged<bool> onToggleAutostart;
  final Future<bool> Function(NetworkProtectionMode mode)
  onSetNetworkProtection;
  final Future<void> Function(List<String> dns) onSetCustomDns;
  final String Function() buildDiagnosticsReport;
  final VoidCallback onDisconnectAndQuit;
  final Future<void> Function(bool value) onSetMinimizeToTray;

  final List<double> downSamples;

  @override
  State<FullWindowShell> createState() => _FullWindowShellState();
}

class _FullWindowShellState extends State<FullWindowShell> {
  ShellView _view = ShellView.home;
  DateTime? _connectedSince;
  Timer? _sessionTicker;
  Future<AccountInfo?>? _accountFuture;

  @override
  void initState() {
    super.initState();
    _syncSessionClock();
    _sessionTicker = Timer.periodic(const Duration(seconds: 1), (_) {
      if (mounted) setState(() {});
    });
  }

  @override
  void didUpdateWidget(covariant FullWindowShell oldWidget) {
    super.didUpdateWidget(oldWidget);
    _syncSessionClock();
  }

  void _syncSessionClock() {
    if (widget.state.isConnected) {
      _connectedSince ??= DateTime.now();
    } else {
      _connectedSince = null;
    }
  }

  @override
  void dispose() {
    _sessionTicker?.cancel();
    super.dispose();
  }

  void _goto(ShellView v) => setState(() => _view = v);

  _HeroVisualState get _heroState {
    if (widget.state.isConnected) return _HeroVisualState.on;
    if (widget.busy || widget.state.isReconnecting) {
      return _HeroVisualState.reconnect;
    }
    if (widget.state.lastError.isNotEmpty) return _HeroVisualState.fail;
    return _HeroVisualState.off;
  }

  String _sessionLabel() {
    final since = _connectedSince;
    if (since == null) return '--:--:--';
    final d = DateTime.now().difference(since);
    String two(int n) => n.toString().padLeft(2, '0');
    return '${two(d.inHours)}:${two(d.inMinutes % 60)}:${two(d.inSeconds % 60)}';
  }

  String _transportLabel(String _) {
    switch (widget.state.transport) {
      case 'quic':
        return 'QUIC / H3';
      case 'ss':
        return 'Shadowsocks-AEAD';
      case 'dot':
        return 'DNS-over-TCP';
      case 'reality':
        return 'Reality';
      default:
        return widget.state.transport.isEmpty ? '—' : widget.state.transport;
    }
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final scheme = Theme.of(context).colorScheme;
    return Scaffold(
      body: Column(
        children: [
          _titlebar(context, tokens),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _rail(context, tokens, scheme),
                Expanded(
                  child: Container(
                    color: tokens.bgWash,
                    child: _content(context, tokens, scheme),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _titlebar(BuildContext context, ChimeraTokens tokens) {
    return Container(
      height: 40,
      decoration: BoxDecoration(
        color: tokens.bgWash,
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Row(
        children: [
          Expanded(
            child: DragToMoveArea(
              child: Padding(
                padding: const EdgeInsets.only(left: 14),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 12,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'CHIMERA',
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontWeight: FontWeight.w600,
                        fontSize: 12,
                        letterSpacing: 0.03,
                        color: tokens.textMuted,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          _winBtn(
            context,
            icon: Icons.remove,
            onTap: () => windowManager.minimize(),
          ),
          _winBtn(
            context,
            icon: Icons.crop_square,
            onTap: () async {
              if (await windowManager.isMaximized()) {
                await windowManager.unmaximize();
              } else {
                await windowManager.maximize();
              }
            },
          ),
          _winBtn(
            context,
            icon: Icons.close,
            danger: true,
            onTap: () => windowManager.close(),
          ),
        ],
      ),
    );
  }

  Widget _winBtn(
    BuildContext context, {
    required IconData icon,
    required VoidCallback onTap,
    bool danger = false,
  }) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return SizedBox(
      width: 42,
      height: 40,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          hoverColor: danger ? tokens.dangerSoft : tokens.surface2,
          onTap: onTap,
          child: Icon(icon, size: 14, color: tokens.textFaint),
        ),
      ),
    );
  }

  Widget _rail(BuildContext context, ChimeraTokens tokens, ColorScheme scheme) {
    return Container(
      width: 76,
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          stops: const [0.0, 0.46],
          colors: [tokens.railTop, tokens.railBottom],
        ),
        border: Border(
          right: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Column(
        children: [
          const SizedBox(height: 16),
          Container(
            width: 40,
            height: 40,
            decoration: BoxDecoration(
              color: tokens.surface2,
              borderRadius: BorderRadius.circular(11),
              border: Border.all(color: Theme.of(context).dividerColor),
            ),
            child: Icon(
              Icons.shield_outlined,
              size: 18,
              color: tokens.accentText,
            ),
          ),
          const SizedBox(height: 22),
          _railBtn(
            context,
            tokens,
            icon: Icons.home_outlined,
            label: 'Home',
            view: ShellView.home,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.public_outlined,
            label: 'Locations',
            view: ShellView.locations,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.alt_route_outlined,
            label: 'Split',
            view: ShellView.split,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.security_outlined,
            label: 'Anti-DPI',
            view: ShellView.anti,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.person_outline,
            label: 'Account',
            view: ShellView.account,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.settings_outlined,
            label: 'Settings',
            view: ShellView.settings,
          ),
          const Spacer(),
          _railBtn(
            context,
            tokens,
            icon: Icons.help_outline,
            label: 'Support',
            view: ShellView.support,
          ),
          _railBtn(
            context,
            tokens,
            icon: Icons.info_outline,
            label: 'About',
            view: ShellView.about,
          ),
          const SizedBox(height: 12),
          _statusPill(context, tokens),
          const SizedBox(height: 14),
        ],
      ),
    );
  }

  Widget _railBtn(
    BuildContext context,
    ChimeraTokens tokens, {
    required IconData icon,
    required String label,
    required ShellView view,
  }) {
    final active = _view == view;
    final color = active ? tokens.accentText : tokens.textFaint;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: () => _goto(view),
          child: Container(
            width: 56,
            height: 56,
            decoration: active
                ? BoxDecoration(
                    border: Border(
                      left: BorderSide(
                        color: Theme.of(context).colorScheme.primary,
                        width: 2.5,
                      ),
                    ),
                  )
                : null,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(icon, size: 19, color: color),
                const SizedBox(height: 5),
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 9.5,
                    fontWeight: FontWeight.w600,
                    color: color,
                    letterSpacing: 0.02,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _statusPill(BuildContext context, ChimeraTokens tokens) {
    final on = widget.state.isConnected;
    final label = switch (_heroState) {
      _HeroVisualState.on => 'ON',
      _HeroVisualState.reconnect => '···',
      _HeroVisualState.fail => '!',
      _HeroVisualState.off => 'OFF',
    };
    final dotColor = switch (_heroState) {
      _HeroVisualState.on => Theme.of(context).colorScheme.primary,
      _HeroVisualState.reconnect => tokens.warn,
      _HeroVisualState.fail => Theme.of(context).colorScheme.error,
      _HeroVisualState.off => tokens.textFaint,
    };
    return Container(
      width: 56,
      padding: const EdgeInsets.symmetric(vertical: 7),
      decoration: BoxDecoration(
        color: tokens.surface2,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Column(
        children: [
          Container(
            width: 7,
            height: 7,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: dotColor,
              boxShadow: on
                  ? [
                      BoxShadow(
                        color: dotColor.withValues(alpha: 0.6),
                        blurRadius: 8,
                        spreadRadius: 1,
                      ),
                    ]
                  : null,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 8,
              color: tokens.textFaint,
              letterSpacing: 0.04,
            ),
          ),
        ],
      ),
    );
  }

  Widget _content(
    BuildContext context,
    ChimeraTokens tokens,
    ColorScheme scheme,
  ) {
    switch (_view) {
      case ShellView.home:
        return _viewShell(
          eyebrow: 'CHIMERA PROTOCOL',
          title: 'Home',
          scrollable: true,
          child: _homeContent(context, tokens, scheme),
        );
      case ShellView.locations:
        return _viewShell(
          eyebrow: 'CURATED CATALOG',
          title: 'Locations',
          scrollable: false,
          child: CatalogPage(
            embedded: true,
            favoriteIds: widget.settings.favoriteServerIds,
            selectedId: widget.settings.lastConnectedServerId,
            onToggleFavorite: widget.onToggleFavorite,
            onSelect: (server) async {
              await widget.onSelectServer(server);
              if (mounted) _goto(ShellView.home);
            },
          ),
        );
      case ShellView.split:
        return _viewShell(
          eyebrow: 'PER-APP ROUTING',
          title: 'Split tunneling',
          scrollable: false,
          child: SplitTunnelPage(
            embedded: true,
            settings: widget.settings.splitTunnel,
            onChanged: widget.onSplitTunnelChanged,
          ),
        );
      case ShellView.anti:
        return _viewShell(
          eyebrow: 'TRANSPORT STRATEGY',
          title: 'Anti-censorship',
          scrollable: false,
          child: AnticensorshipPage(
            embedded: true,
            current: widget.settings.obfuscationMode,
            onChanged: widget.onSetObfuscationMode,
            availableTransportParams: widget.availableTransportParams,
          ),
        );
      case ShellView.account:
        return _viewShell(
          eyebrow: 'ACCESS',
          title: 'Account',
          scrollable: false,
          child: _accountContent(context, tokens),
        );
      case ShellView.settings:
        return _viewShell(
          eyebrow: 'PREFERENCES',
          title: 'Settings',
          scrollable: false,
          child: SettingsHubPage(
            embedded: true,
            settings: widget.settings,
            busy: widget.busy,
            isConnected: widget.state.isConnected,
            onPersist: widget.onPersist,
            onToggleAutostart: widget.onToggleAutostart,
            onSetNetworkProtection: widget.onSetNetworkProtection,
            onSetCustomDns: widget.onSetCustomDns,
            buildDiagnosticsReport: widget.buildDiagnosticsReport,
            onDisconnectAndQuit: widget.onDisconnectAndQuit,
            state: widget.state,
            downSamples: widget.downSamples,
            onSetMinimizeToTray: widget.onSetMinimizeToTray,
          ),
        );
      case ShellView.support:
        return _viewShell(
          eyebrow: 'DIAGNOSTICS',
          title: 'Support',
          scrollable: false,
          child: SupportPage(
            embedded: true,
            buildReport: widget.buildDiagnosticsReport,
            state: widget.state,
            downSamples: widget.downSamples,
          ),
        );
      case ShellView.about:
        return _viewShell(
          eyebrow: '',
          title: 'About',
          scrollable: false,
          child: const AppInfoPage(embedded: true),
        );
    }
  }

  Widget _viewShell({
    required String eyebrow,
    required String title,
    required bool scrollable,
    required Widget child,
  }) {
    final head = Padding(
      padding: const EdgeInsets.fromLTRB(40, 28, 40, 20),
      child: Builder(
        builder: (context) {
          final tokens = Theme.of(context).extension<ChimeraTokens>()!;
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (eyebrow.isNotEmpty)
                Text(
                  eyebrow,
                  style: monoStyle(
                    fontSize: 10,
                    weight: FontWeight.w600,
                    color: tokens.textFaint,
                  ).copyWith(letterSpacing: 1.2),
                ),
              const SizedBox(height: 4),
              Text(
                title,
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 21,
                  fontWeight: FontWeight.w700,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ],
          );
        },
      ),
    );

    if (!scrollable) {
      return Column(
        children: [
          head,
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 40),
              child: child,
            ),
          ),
          const SizedBox(height: 24),
        ],
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(0, 0, 0, 40),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          head,
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 40),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 620),
                child: child,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _accountContent(BuildContext context, ChimeraTokens tokens) {
    _accountFuture ??= AccountStore().load();
    return FutureBuilder<AccountInfo?>(
      future: _accountFuture,
      builder: (context, snapshot) {
        if (snapshot.connectionState != ConnectionState.done) {
          return const Center(child: CircularProgressIndicator());
        }
        final account = snapshot.data;
        if (account == null) {
          return Center(
            child: Text(
              'No account on this device.',
              style: TextStyle(
                fontFamily: 'Plex Sans',
                fontSize: 13,
                color: tokens.textFaint,
              ),
            ),
          );
        }
        return AccountPage(
          embedded: true,
          account: account,
          onLoggedOut: widget.onLoggedOut,
        );
      },
    );
  }

  Widget _homeContent(
    BuildContext context,
    ChimeraTokens tokens,
    ColorScheme scheme,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (widget.initError != null) ...[
          _engineErrorBanner(context, scheme),
          const SizedBox(height: 12),
        ],
        _hero(context, tokens, scheme),
        const SizedBox(height: 12),
        _statRow(context, tokens),
        const SizedBox(height: 12),
        _serverRow(context, tokens),
      ],
    );
  }

  Widget _engineErrorBanner(BuildContext context, ColorScheme scheme) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.error.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(11),
        border: Border.all(color: scheme.error.withValues(alpha: 0.4)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, size: 18, color: scheme.error),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'CHIMERA engine failed to load, so Connect is unavailable: ${widget.initError}',
              style: TextStyle(
                fontFamily: 'Plex Sans',
                fontSize: 12,
                color: scheme.error,
                height: 1.35,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _hero(BuildContext context, ChimeraTokens tokens, ColorScheme scheme) {
    final s = _heroState;
    final ringColor = switch (s) {
      _HeroVisualState.on => scheme.primary,
      _HeroVisualState.reconnect => tokens.warn,
      _HeroVisualState.fail => scheme.error,
      _HeroVisualState.off => tokens.textFaint,
    };
    final label = switch (s) {
      _HeroVisualState.on => 'Protected',
      _HeroVisualState.reconnect => 'Reconnecting…',
      _HeroVisualState.fail => 'Kill switch active',
      _HeroVisualState.off => 'Not protected',
    };
    final detail = switch (s) {
      _HeroVisualState.on =>
        'via ${_transportLabel(widget.state.state)} '
            '${widget.selectedServer != null ? '· ${widget.selectedServer!.city}, ${widget.selectedServer!.country}' : ''}',
      _HeroVisualState.reconnect => 'Lost connection — retrying…',
      _HeroVisualState.fail =>
        widget.state.lastError.isNotEmpty
            ? friendlyConnectError(widget.state.lastError)
            : 'Tunnel failed and traffic is blocked to prevent a leak.',
      _HeroVisualState.off => 'Your traffic is not routed through Chimera.',
    };
    final btnLabel = switch (s) {
      _HeroVisualState.on => 'Disconnect',
      _HeroVisualState.reconnect => 'Cancel',
      _HeroVisualState.fail => 'Retry connection',
      _HeroVisualState.off => 'Connect',
    };
    final btnColor = switch (s) {
      _HeroVisualState.fail => scheme.error,
      _ => scheme.primary,
    };
    final isFilled = s != _HeroVisualState.off;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.fromLTRB(24, 40, 24, 30),
      decoration: BoxDecoration(
        color: tokens.surface2,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: Theme.of(context).dividerColor),
        gradient: RadialGradient(
          center: const Alignment(0, -1.4),
          radius: 1.6,
          colors: [
            tokens.heroWash.withValues(alpha: 0.35),
            tokens.heroWash.withValues(alpha: 0.0),
          ],
        ),
      ),
      child: Column(
        children: [
          SizedBox(
            height: 168,
            child: _PulsingRings(
              color: ringColor,
              active:
                  s == _HeroVisualState.on || s == _HeroVisualState.reconnect,
              fast: s == _HeroVisualState.reconnect,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            label,
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 19,
              fontWeight: FontWeight.w700,
              color: ringColor,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            detail,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 13,
              color: tokens.textMuted,
            ),
          ),
          const SizedBox(height: 22),
          SizedBox(
            width: 240,
            child: isFilled
                ? ElevatedButton(
                    onPressed: () => widget.onToggleConnection(),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: btnColor,
                      foregroundColor: tokens.accentInk,
                      shape: const StadiumBorder(),
                      padding: const EdgeInsets.symmetric(vertical: 13),
                    ),
                    child: Text(btnLabel),
                  )
                : OutlinedButton(
                    onPressed: () => widget.onToggleConnection(),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: scheme.onSurface,
                      side: BorderSide(color: Theme.of(context).dividerColor),
                      shape: const StadiumBorder(),
                      padding: const EdgeInsets.symmetric(vertical: 13),
                    ),
                    child: Text(btnLabel),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _statRow(BuildContext context, ChimeraTokens tokens) {
    Widget stat(String label, String value) => Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: tokens.surface2,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Theme.of(context).dividerColor),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: monoStyle(
                fontSize: 10,
                weight: FontWeight.w600,
                color: tokens.textFaint,
              ).copyWith(letterSpacing: 1.0),
            ),
            const SizedBox(height: 6),
            Text(
              value,
              style: monoStyle(
                fontSize: 17,
                weight: FontWeight.w600,
                color: Theme.of(context).colorScheme.onSurface,
              ),
            ),
          ],
        ),
      ),
    );
    final latency = widget.state.endpoints.where((e) => e.rttMs > 0).toList();
    final latencyLabel = latency.isEmpty
        ? '—'
        : '${(latency.map((e) => e.rttMs).reduce((a, b) => a + b) / latency.length).round()}ms';
    return Row(
      children: [
        stat('Transport', _transportLabel(widget.state.state)),
        const SizedBox(width: 12),
        stat('Latency', latencyLabel),
        const SizedBox(width: 12),
        stat(
          'Session',
          widget.state.isConnected ? _sessionLabel() : '--:--:--',
        ),
      ],
    );
  }

  Widget _serverRow(BuildContext context, ChimeraTokens tokens) {
    final s = widget.selectedServer;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: tokens.surface2,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Row(
        children: [
          if (s != null) ...[
            Text(s.flag, style: const TextStyle(fontSize: 20)),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    s.city,
                    style: TextStyle(
                      fontFamily: 'Plex Sans',
                      fontWeight: FontWeight.w600,
                      fontSize: 13.5,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                  ),
                  Text(
                    s.country,
                    style: monoStyle(fontSize: 11.5, color: tokens.textFaint),
                  ),
                ],
              ),
            ),
          ] else
            Expanded(
              child: Text(
                'Choose a location',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontWeight: FontWeight.w600,
                  fontSize: 13.5,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
          TextButton(
            onPressed: () => _goto(ShellView.locations),
            child: const Text('Change location →'),
          ),
        ],
      ),
    );
  }
}

class _PulsingRings extends StatefulWidget {
  const _PulsingRings({
    required this.color,
    required this.active,
    required this.fast,
  });

  final Color color;
  final bool active;
  final bool fast;

  @override
  State<_PulsingRings> createState() => _PulsingRingsState();
}

class _PulsingRingsState extends State<_PulsingRings>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 2600),
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _apply();
  }

  @override
  void didUpdateWidget(covariant _PulsingRings oldWidget) {
    super.didUpdateWidget(oldWidget);
    _apply();
  }

  void _apply() {
    _ctrl.duration = widget.fast
        ? const Duration(milliseconds: 1100)
        : const Duration(milliseconds: 2600);
    final reduceMotion = MediaQuery.of(context).disableAnimations;
    if (widget.active && !reduceMotion) {
      if (!_ctrl.isAnimating) _ctrl.repeat();
    } else {
      _ctrl.stop();
    }
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  double _phase(double offset) => (_ctrl.value + offset) % 1.0;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: AnimatedBuilder(
        animation: _ctrl,
        builder: (context, _) => Stack(
          alignment: Alignment.center,
          children: [
            _ring(168, 0.0),
            _ring(122, 0.4 / 2.6),
            _ring(82, 0.8 / 2.6),
            Container(
              width: 15,
              height: 15,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: widget.color,
                boxShadow: widget.active
                    ? [
                        BoxShadow(
                          color: widget.color.withValues(alpha: 0.25),
                          spreadRadius: 7,
                        ),
                        BoxShadow(
                          color: widget.color.withValues(alpha: 0.6),
                          blurRadius: 26,
                          spreadRadius: 3,
                        ),
                      ]
                    : [
                        BoxShadow(
                          color: widget.color.withValues(alpha: 0.15),
                          spreadRadius: 7,
                        ),
                      ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _ring(double diameter, double phaseOffset) {
    if (!widget.active) {
      return Opacity(
        opacity: 0.12,
        child: Container(
          width: diameter,
          height: diameter,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(color: widget.color, width: 1),
          ),
        ),
      );
    }
    final t = _phase(phaseOffset);
    final scale = 0.86 + 0.32 * t;
    final opacity = 0.5 * (1 - t);
    return Opacity(
      opacity: opacity.clamp(0.0, 1.0),
      child: Transform.scale(
        scale: scale,
        child: Container(
          width: diameter,
          height: diameter,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            border: Border.all(color: widget.color, width: 1),
          ),
        ),
      ),
    );
  }
}
