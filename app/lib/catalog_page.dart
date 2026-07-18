import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';

import 'account_store.dart';
import 'catalog_cache_store.dart';
import 'theme.dart';

class CatalogListener {
  const CatalogListener({required this.transport, required this.port});

  factory CatalogListener.fromJson(Map<String, dynamic> json) =>
      CatalogListener(
        transport: json['transport'] as String? ?? '',
        port: json['port'] as int? ?? 0,
      );

  final String transport;
  final int port;

  Map<String, dynamic> toJson() => {'transport': transport, 'port': port};
}

class CatalogServer {
  const CatalogServer({
    required this.id,
    required this.host,
    required this.port,
    required this.pubKey,
    required this.sni,
    required this.fingerprint,
    required this.city,
    required this.country,
    required this.loadPct,
    required this.healthy,
    this.listeners = const [],
  });

  factory CatalogServer.fromJson(Map<String, dynamic> json) {
    final port = json['port'] as int? ?? 443;
    final rawListeners = json['listeners'] as List<dynamic>?;

    final listeners = (rawListeners == null || rawListeners.isEmpty)
        ? [CatalogListener(transport: 'reality', port: port)]
        : rawListeners
              .map((e) => CatalogListener.fromJson(e as Map<String, dynamic>))
              .toList();
    return CatalogServer(
      id: '${json['id']}',
      host: json['host'] as String? ?? '',
      port: port,
      pubKey: json['pubkey'] as String? ?? '',
      sni: json['sni'] as String? ?? '',
      fingerprint: json['fp'] as String? ?? '',
      city: json['city'] as String? ?? '',
      country: json['country'] as String? ?? '',
      loadPct: json['load_pct'] as int? ?? 0,
      healthy: json['healthy'] as bool? ?? true,
      listeners: listeners,
    );
  }

  final String id;
  final String host;
  final int port;
  final String pubKey;
  final String sni;
  final String fingerprint;
  final String city;
  final String country;
  final int loadPct;
  final bool healthy;
  final List<CatalogListener> listeners;

  String get flag => flagForCountry(country);

  int? portFor(String transportParam) {
    final wanted = transportParam.isEmpty ? 'reality' : transportParam;
    for (final l in listeners) {
      if (l.transport == wanted) return l.port;
    }
    return null;
  }

  Set<String> get availableTransportParams =>
      listeners.map((l) => l.transport == 'reality' ? '' : l.transport).toSet();

  Map<String, dynamic> toJson() => {
    'id': id,
    'host': host,
    'port': port,
    'pubkey': pubKey,
    'sni': sni,
    'fp': fingerprint,
    'city': city,
    'country': country,
    'load_pct': loadPct,
    'healthy': healthy,
    'listeners': listeners.map((l) => l.toJson()).toList(),
  };
}

String flagForCountry(String country) {
  const known = {
    'Sweden': '🇸🇪',
    'Switzerland': '🇨🇭',
    'Netherlands': '🇳🇱',
    'Serbia': '🇷🇸',
    'Slovakia': '🇸🇰',
    'Belgium': '🇧🇪',
    'Romania': '🇷🇴',
    'Germany': '🇩🇪',
    'France': '🇫🇷',
    'United Kingdom': '🇬🇧',
    'Poland': '🇵🇱',
    'United States': '🇺🇸',
    'Norway': '🇳🇴',
    'Denmark': '🇩🇰',
    'Finland': '🇫🇮',
    'Austria': '🇦🇹',
    'Spain': '🇪🇸',
    'Italy': '🇮🇹',
    'Portugal': '🇵🇹',
    'Canada': '🇨🇦',
    'Japan': '🇯🇵',
    'Singapore': '🇸🇬',
    'Australia': '🇦🇺',
  };
  return known[country] ?? '🌐';
}

class CatalogClient {
  CatalogClient({AccountStore? accountStore})
    : _accountStore = accountStore ?? AccountStore();

  final AccountStore _accountStore;

  Future<List<CatalogServer>> fetch() async {
    final account = await _accountStore.load();
    if (account == null || account.token.isEmpty) {
      throw StateError('no account token available');
    }
    Object? lastError;
    for (final base in _accountStore.mirrors) {
      try {
        final resp = await _accountStore.client
            .get(
              Uri.parse('$base/v1/catalog'),
              headers: {'Authorization': 'Bearer ${account.token}'},
            )
            .timeout(const Duration(seconds: 15));
        if (resp.statusCode != 200) {
          lastError = 'catalog fetch failed: HTTP ${resp.statusCode}';
          continue;
        }

        final decoded = jsonDecode(resp.body);
        final list = decoded == null ? const [] : decoded as List<dynamic>;
        return list
            .map((e) => CatalogServer.fromJson(e as Map<String, dynamic>))
            .toList();
      } catch (e) {
        lastError = e;
        continue;
      }
    }
    throw lastError ?? Exception('no control-plane mirrors configured');
  }
}

class CatalogPage extends StatefulWidget {
  const CatalogPage({
    super.key,
    required this.favoriteIds,
    required this.selectedId,
    required this.onToggleFavorite,
    required this.onSelect,
    this.client,
    this.cache,
    this.embedded = false,
  });

  final List<String> favoriteIds;
  final String? selectedId;
  final Future<void> Function(String id) onToggleFavorite;
  final Future<void> Function(CatalogServer server) onSelect;
  final CatalogClient? client;
  final CatalogCacheStore? cache;

  final bool embedded;

  @override
  State<CatalogPage> createState() => _CatalogPageState();
}

class _CatalogPageState extends State<CatalogPage> {
  final _searchCtrl = TextEditingController();
  late final CatalogClient _client = widget.client ?? CatalogClient();
  late final CatalogCacheStore _cache = widget.cache ?? CatalogCacheStore();
  String _query = '';
  List<CatalogServer> _servers = const [];
  DateTime? _cachedAt;
  bool _loading = true;
  bool _refreshing = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _init();
  }

  Future<void> _init() async {
    final snapshot = await _cache.load();
    if (snapshot != null && mounted) {
      setState(() {
        _servers = snapshot.servers;
        _cachedAt = snapshot.fetchedAt;
        _loading = false;
      });
    }
    await _load();
  }

  Future<void> _load() async {
    setState(() {
      _refreshing = true;
      if (_servers.isEmpty) _loading = true;
      _error = null;
    });
    try {
      final servers = await _client.fetch();
      if (mounted) {
        setState(() {
          _servers = servers;
          _cachedAt = DateTime.now();
        });
      }
      unawaited(_cache.save(servers));
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = _refreshing = false);
    }
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  List<CatalogServer> get _filtered {
    if (_query.isEmpty) return _servers;
    final q = _query.toLowerCase();
    return _servers
        .where(
          (s) =>
              s.city.toLowerCase().contains(q) ||
              s.country.toLowerCase().contains(q),
        )
        .toList();
  }

  Color _loadColor(ChimeraTokens tokens, int pct) {
    if (pct >= 60) return tokens.warn;
    return Theme.of(context).colorScheme.primary;
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final favorites = _filtered
        .where((s) => widget.favoriteIds.contains(s.id))
        .toList();
    final rest = _filtered
        .where((s) => !widget.favoriteIds.contains(s.id))
        .toList();

    final refreshButton = IconButton(
      icon: _refreshing
          ? const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : const Icon(Icons.refresh, size: 20),
      tooltip: 'Refresh',
      onPressed: _refreshing ? null : _load,
    );
    final content = SafeArea(
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
            child: TextField(
              controller: _searchCtrl,
              onChanged: (v) => setState(() => _query = v),
              decoration: InputDecoration(
                hintText: 'Search country or city',
                prefixIcon: Icon(
                  Icons.search,
                  size: 18,
                  color: tokens.textFaint,
                ),

                suffixIcon: widget.embedded ? refreshButton : null,
              ),
            ),
          ),

          if (_error != null && _servers.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  horizontal: 12,
                  vertical: 10,
                ),
                decoration: BoxDecoration(
                  color: tokens.surface2,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Theme.of(context).dividerColor),
                ),
                child: Row(
                  children: [
                    Icon(Icons.history, size: 14, color: tokens.textFaint),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _cachedAt == null
                            ? 'Showing saved results'
                            : 'Showing saved results from ${relativeTime(_cachedAt!)}',
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 11.5,
                          color: tokens.textFaint,
                        ),
                      ),
                    ),
                    GestureDetector(
                      onTap: _load,
                      child: Text(
                        'Retry',
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 11.5,
                          fontWeight: FontWeight.w600,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            )
          else if (_error != null)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: tokens.dangerSoft,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  "Couldn't load the server list. Check your connection and try again.",
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 12,
                    color: tokens.textMuted,
                  ),
                ),
              ),
            ),
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : ListView(
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
                    children: [
                      if (favorites.isNotEmpty) ...[
                        _groupLabel(tokens, 'Favorites'),
                        ...favorites.map((s) => _serverRow(context, tokens, s)),
                        const SizedBox(height: 8),
                      ],
                      _groupLabel(
                        tokens,
                        'All locations · ${_filtered.length} servers',
                      ),
                      ...rest.map((s) => _serverRow(context, tokens, s)),
                      if (_filtered.isEmpty && _error == null)
                        Padding(
                          padding: const EdgeInsets.only(top: 32),
                          child: Center(
                            child: Text(
                              'No matching locations',
                              style: TextStyle(
                                fontFamily: 'Plex Sans',
                                fontSize: 13,
                                color: tokens.textMuted,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
    if (widget.embedded) return content;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Select location'),
        actions: [refreshButton],
      ),
      body: content,
    );
  }

  Widget _groupLabel(ChimeraTokens tokens, String text) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 8),
    child: Text(
      text.toUpperCase(),
      style: TextStyle(
        fontFamily: 'Plex Sans',
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.6,
        color: tokens.textFaint,
      ),
    ),
  );

  Widget _serverRow(
    BuildContext context,
    ChimeraTokens tokens,
    CatalogServer s,
  ) {
    final isFavorite = widget.favoriteIds.contains(s.id);
    final isSelected = widget.selectedId == s.id;
    return Material(
      color: isSelected ? tokens.accentSoft : Colors.transparent,
      borderRadius: BorderRadius.circular(11),
      child: InkWell(
        borderRadius: BorderRadius.circular(11),
        onTap: () => widget.onSelect(s),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
          child: Row(
            children: [
              SizedBox(
                width: 30,
                child: Text(s.flag, style: const TextStyle(fontSize: 18)),
              ),
              const SizedBox(width: 6),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      s.city,
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontSize: 13.5,
                        fontWeight: FontWeight.w600,
                        color: Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Row(
                      children: [
                        Text(
                          s.country,
                          style: TextStyle(
                            fontFamily: 'Plex Sans',
                            fontSize: 11.5,
                            color: tokens.textMuted,
                          ),
                        ),
                        const SizedBox(width: 8),
                        SizedBox(
                          width: 40,
                          height: 4,
                          child: ClipRRect(
                            borderRadius: BorderRadius.circular(2),
                            child: LinearProgressIndicator(
                              value: s.loadPct / 100,
                              backgroundColor: tokens.neutralPill,
                              color: _loadColor(tokens, s.loadPct),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              IconButton(
                icon: Icon(
                  isFavorite ? Icons.star : Icons.star_border,
                  size: 19,
                  color: isFavorite ? tokens.warn : tokens.textFaint,
                ),
                onPressed: () => widget.onToggleFavorite(s.id),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
