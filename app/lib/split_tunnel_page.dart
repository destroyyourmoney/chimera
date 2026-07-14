// Split tunneling screen (docs/app/platform-features.md §2), styled after
// Mullvad's app picker: master Enable toggle, Include/Exclude segmented
// control, search, and two lists -- the chosen apps (with a live counter)
// and everything else -- with a +/- button per row instead of checkboxes so
// a row visibly moves between sections when tapped.
//
// This screen owns the picker UI and persistence only. On today's desktop
// tray (TUN-less SOCKS5, see main.dart's header comment) there is no
// OS-level per-app routing yet -- that's the elevated-helper WFP/cgroup work
// tracked in ROADMAP.md's Этап 4 "per-app routing" item -- so the toggle is
// honest about not being enforced until that lands.
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'installed_apps.dart';
import 'settings_store.dart';
import 'theme.dart';

/// Keyword-matched presets: desktop apps don't have a stable cross-machine
/// package id the way Android does, so a template selects by matching
/// installed display names against a keyword list rather than a fixed id
/// set. Good enough for "pick my messengers" without a maintained catalog.
const Map<String, List<String>> _templates = {
  'Messengers': ['telegram', 'whatsapp', 'signal', 'discord', 'skype', 'viber'],
  'Browsers': ['chrome', 'firefox', 'edge', 'brave', 'opera'],
  'Streaming': ['spotify', 'netflix', 'twitch', 'vlc'],
};

class SplitTunnelPage extends StatefulWidget {
  const SplitTunnelPage({
    super.key,
    required this.settings,
    required this.onChanged,
  });

  /// Owned by the caller (HomePage/_settings.splitTunnel); this screen
  /// mutates it in place and calls [onChanged] to persist, matching the
  /// ServersPage convention.
  final SplitTunnelSettings settings;
  final Future<void> Function() onChanged;

  @override
  State<SplitTunnelPage> createState() => _SplitTunnelPageState();
}

class _SplitTunnelPageState extends State<SplitTunnelPage> {
  final _searchCtrl = TextEditingController();
  List<SplitTunnelApp> _allApps = [];
  bool _loading = true;
  String _query = '';
  Timer? _debounce;

  bool get _supportsPerAppRouting => Platform.isWindows;

  @override
  void initState() {
    super.initState();
    _searchCtrl.addListener(() {
      setState(() => _query = _searchCtrl.text.trim().toLowerCase());
    });
    _loadApps();
  }

  Future<void> _loadApps() async {
    final apps = await InstalledApps.list();
    if (!mounted) return;
    setState(() {
      _allApps = apps;
      _loading = false;
    });
  }

  @override
  void dispose() {
    if (_debounce?.isActive ?? false) {
      _debounce!.cancel();
      widget.onChanged();
    }
    _searchCtrl.dispose();
    super.dispose();
  }

  void _persistDebounced() {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 500), () {
      widget.onChanged();
    });
  }

  void _setEnabled(bool v) {
    setState(() => widget.settings.enabled = v);
    widget.onChanged();
  }

  void _setMode(SplitTunnelMode m) {
    if (widget.settings.mode == m) return;
    setState(() => widget.settings.mode = m);
    widget.onChanged();
  }

  void _addApp(SplitTunnelApp app) {
    setState(() {
      widget.settings.apps.add(app);
      widget.settings.template = null;
    });
    _persistDebounced();
  }

  void _removeApp(SplitTunnelApp app) {
    setState(() {
      widget.settings.apps.removeWhere((a) => a.id == app.id);
      widget.settings.template = null;
    });
    _persistDebounced();
  }

  void _applyTemplate(String name) {
    final keywords = _templates[name]!;
    final matches = _allApps
        .where((a) => keywords.any((k) => a.name.toLowerCase().contains(k)))
        .toList();
    setState(() {
      widget.settings.apps
        ..clear()
        ..addAll(matches);
      widget.settings.template = name;
    });
    _persistDebounced();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          matches.isEmpty
              ? 'No installed apps matched "$name"'
              : 'Applied "$name" (${matches.length} app(s))',
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final selectedIds = widget.settings.apps.map((a) => a.id).toSet();
    final selected = widget.settings.apps
        .where((a) => _query.isEmpty || a.name.toLowerCase().contains(_query))
        .toList();
    final available = _allApps
        .where((a) => !selectedIds.contains(a.id))
        .where((a) => _query.isEmpty || a.name.toLowerCase().contains(_query))
        .toList();
    final selectedLabel = widget.settings.mode == SplitTunnelMode.include
        ? 'Included apps'
        : 'Excluded apps';

    return Scaffold(
      appBar: AppBar(title: const Text('Split tunneling')),
      body: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 0),
              child: _enableRow(context, tokens),
            ),
            if (widget.settings.enabled) ...[
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 0),
                child: _warningBanner(context, tokens),
              ),
              if (!_supportsPerAppRouting)
                Padding(
                  padding: const EdgeInsets.fromLTRB(20, 10, 20, 0),
                  child: _unsupportedBanner(context, tokens),
                ),
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 14, 20, 0),
                child: _modeSegment(context, tokens),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 0),
                child: _templateChips(context, tokens),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 12, 20, 8),
                child: TextField(
                  controller: _searchCtrl,
                  decoration: const InputDecoration(
                    hintText: 'Search for…',
                    prefixIcon: Icon(Icons.search, size: 18),
                  ),
                ),
              ),
              Expanded(
                child: _loading
                    ? const Center(child: CircularProgressIndicator())
                    : ListView(
                        padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
                        children: [
                          _sectionHeader(
                            tokens,
                            '$selectedLabel — ${selected.length} out of ${_allApps.length}',
                          ),
                          const SizedBox(height: 6),
                          if (selected.isEmpty)
                            _emptyState(tokens, 'No apps chosen yet.')
                          else
                            for (final a in selected)
                              _appRow(
                                context,
                                tokens,
                                a,
                                isAdd: false,
                                onTap: () => _removeApp(a),
                              ),
                          const SizedBox(height: 20),
                          _sectionHeader(tokens, 'All apps'),
                          const SizedBox(height: 6),
                          if (available.isEmpty)
                            _emptyState(
                              tokens,
                              _query.isEmpty
                                  ? 'Every installed app is already added.'
                                  : 'No apps match "$_query".',
                            )
                          else
                            for (final a in available)
                              _appRow(
                                context,
                                tokens,
                                a,
                                isAdd: true,
                                onTap: () => _addApp(a),
                              ),
                        ],
                      ),
              ),
            ] else
              Padding(
                padding: const EdgeInsets.fromLTRB(20, 20, 20, 0),
                child: Text(
                  'Turn this on to route only chosen apps through CHIMERA '
                  '(or everything except them).',
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 12.5,
                    color: tokens.textMuted,
                    height: 1.35,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _enableRow(BuildContext context, ChimeraTokens tokens) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Split tunneling',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 13.5,
                  fontWeight: FontWeight.w500,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                'Choose apps that should (or should not) go through the tunnel.',
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
        Switch(value: widget.settings.enabled, onChanged: _setEnabled),
      ],
    );
  }

  Widget _warningBanner(BuildContext context, ChimeraTokens tokens) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: tokens.warnSoft,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.warning_amber_rounded, size: 16, color: tokens.warn),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              'Split tunneling is a privacy trade-off: apps outside the tunnel '
              'are not protected.',
              style: TextStyle(
                fontFamily: 'Plex Sans',
                fontSize: 12,
                color: tokens.warn,
                height: 1.3,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _unsupportedBanner(BuildContext context, ChimeraTokens tokens) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: tokens.dangerSoft,
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.info_outline, size: 16, color: Theme.of(context).colorScheme.error),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              'Per-app routing on this platform is not implemented yet -- your '
              'selection is saved but not enforced until it ships.',
              style: TextStyle(
                fontFamily: 'Plex Sans',
                fontSize: 12,
                color: Theme.of(context).colorScheme.error,
                height: 1.3,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _modeSegment(BuildContext context, ChimeraTokens tokens) {
    return SegmentedButton<SplitTunnelMode>(
      segments: const [
        ButtonSegment(
          value: SplitTunnelMode.exclude,
          label: Text('Exclude'),
          icon: Icon(Icons.remove_circle_outline, size: 16),
        ),
        ButtonSegment(
          value: SplitTunnelMode.include,
          label: Text('Include'),
          icon: Icon(Icons.add_circle_outline, size: 16),
        ),
      ],
      selected: {widget.settings.mode},
      onSelectionChanged: (s) => _setMode(s.first),
    );
  }

  Widget _templateChips(BuildContext context, ChimeraTokens tokens) {
    return Wrap(
      spacing: 8,
      runSpacing: 8,
      children: [
        for (final name in _templates.keys)
          ChoiceChip(
            label: Text(name),
            selected: widget.settings.template == name,
            onSelected: (_) => _applyTemplate(name),
          ),
      ],
    );
  }

  Widget _sectionHeader(ChimeraTokens tokens, String text) {
    return Text(
      text.toUpperCase(),
      style: TextStyle(
        fontFamily: 'Plex Sans',
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.5,
        color: tokens.textFaint,
      ),
    );
  }

  Widget _emptyState(ChimeraTokens tokens, String text) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 10),
      child: Text(
        text,
        style: TextStyle(
          fontFamily: 'Plex Sans',
          fontSize: 12.5,
          color: tokens.textFaint,
        ),
      ),
    );
  }

  Widget _appRow(
    BuildContext context,
    ChimeraTokens tokens,
    SplitTunnelApp app, {
    required bool isAdd,
    required VoidCallback onTap,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: Theme.of(context).dividerColor),
        ),
        child: Row(
          children: [
            CircleAvatar(
              radius: 12,
              backgroundColor: tokens.neutralPill,
              child: Text(
                app.name.isNotEmpty ? app.name[0].toUpperCase() : '?',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: tokens.textMuted,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                app.name,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 13,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
            IconButton(
              icon: Icon(
                isAdd ? Icons.add_circle_outline : Icons.remove_circle_outline,
                size: 18,
              ),
              tooltip: isAdd ? 'Add to list' : 'Remove from list',
              onPressed: onTap,
            ),
          ],
        ),
      ),
    );
  }
}
