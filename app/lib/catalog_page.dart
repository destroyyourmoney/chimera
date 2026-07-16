// Curated server list (ROADMAP2 §2/§4): search + favorites over the fleet
// served by the real `GET /v1/catalog` (internal/controlplane/api.go),
// token-gated per ROADMAP2 §0.1 п.1 -- not a public, unauthenticated
// endpoint. Falls back to the last successfully fetched list (kept only in
// memory for this screen's lifetime) if a refetch fails, so a brief
// control-plane hiccup doesn't blank the picker.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import 'account_store.dart';
import 'theme.dart';

/// One transport endpoint a [CatalogServer] actually has a running listener
/// for (ROADMAP2 §3/§4 multi-transport support --
/// internal/controlplane/catalog.go's `CatalogListener`). `transport` is the
/// same short code `internal/subscription.Parse` reads out of a `mode=`
/// query param: `'reality'` for the primary Reality/TCP listener (dialed
/// with no `mode=` param at all -- see `obfuscationModeQueryParam`), or
/// `'quic'`/`'ss'`/`'dot'`.
class CatalogListener {
  const CatalogListener({required this.transport, required this.port});

  factory CatalogListener.fromJson(Map<String, dynamic> json) => CatalogListener(
    transport: json['transport'] as String? ?? '',
    port: json['port'] as int? ?? 0,
  );

  final String transport;
  final int port;
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
    // A control-plane that predates multi-transport listeners (or a row
    // that hasn't been backfilled) sends no `listeners` array at all --
    // synthesize the one Reality/TCP listener `host`/`port` always implied,
    // same default internal/controlplane/catalog.go's `CatalogStore.Add`
    // applies server-side. Never leave this empty: everything downstream
    // (CatalogServer.portFor, main.dart's _upsertCuratedServer) treats
    // "no listener for transport X" as "don't offer X for this server", and
    // an empty list would wrongly disable Reality too.
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

  /// The port to dial for [transportParam] (an `obfuscationModeQueryParam`
  /// value: `''`/`'reality'` for Reality, else `'quic'`/`'ss'`/`'dot'`), or
  /// null if this server has no listener for that transport -- callers must
  /// treat null as "not offered here", never fall back to guessing a port.
  int? portFor(String transportParam) {
    final wanted = transportParam.isEmpty ? 'reality' : transportParam;
    for (final l in listeners) {
      if (l.transport == wanted) return l.port;
    }
    return null;
  }

  /// The set of `obfuscationModeQueryParam` values this server actually
  /// offers -- drives which Anti-censorship cards are selectable for the
  /// currently chosen server (ROADMAP2 §0 "no false promises": don't let the
  /// user pick a transport this server can't actually serve).
  Set<String> get availableTransportParams =>
      listeners.map((l) => l.transport == 'reality' ? '' : l.transport).toSet();
}

/// Best-effort flag emoji from a country name -- cosmetic only; an unknown
/// country just falls back to a generic marker rather than blocking
/// rendering on a full ISO-3166 lookup table. Shared with main.dart's Home
/// server-card, which shows the same flag for the currently selected server.
String flagForCountry(String country) {
  const known = {
    'Sweden': '🇸🇪', 'Switzerland': '🇨🇭', 'Netherlands': '🇳🇱', 'Serbia': '🇷🇸',
    'Slovakia': '🇸🇰', 'Belgium': '🇧🇪', 'Romania': '🇷🇴', 'Germany': '🇩🇪',
    'France': '🇫🇷', 'United Kingdom': '🇬🇧', 'Poland': '🇵🇱',
    'United States': '🇺🇸', 'Norway': '🇳🇴', 'Denmark': '🇩🇰', 'Finland': '🇫🇮',
    'Austria': '🇦🇹', 'Spain': '🇪🇸', 'Italy': '🇮🇹', 'Portugal': '🇵🇹',
    'Canada': '🇨🇦', 'Japan': '🇯🇵', 'Singapore': '🇸🇬', 'Australia': '🇦🇺',
  };
  return known[country] ?? '🌐';
}

/// Fetches the curated catalog from the control-plane, trying each mirror
/// in turn (ROADMAP2 §0.1 п.5), authenticated with the account's own
/// capability token.
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
        final resp = await http
            .get(
              Uri.parse('$base/v1/catalog'),
              headers: {'Authorization': 'Bearer ${account.token}'},
            )
            .timeout(const Duration(seconds: 10));
        if (resp.statusCode != 200) {
          lastError = 'catalog fetch failed: HTTP ${resp.statusCode}';
          continue;
        }
        // A server that predates the empty-catalog fix (Go's nil-slice ->
        // `null` JSON encoding for zero rows) sends a `null` body instead of
        // `[]`; treat that the same as an empty catalog rather than
        // crashing the type cast below.
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
  });

  final List<String> favoriteIds;
  final String? selectedId;
  final Future<void> Function(String id) onToggleFavorite;
  final Future<void> Function(CatalogServer server) onSelect;
  final CatalogClient? client;

  @override
  State<CatalogPage> createState() => _CatalogPageState();
}

class _CatalogPageState extends State<CatalogPage> {
  final _searchCtrl = TextEditingController();
  late final CatalogClient _client = widget.client ?? CatalogClient();
  String _query = '';
  List<CatalogServer> _servers = const [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final servers = await _client.fetch();
      if (mounted) setState(() => _servers = servers);
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _loading = false);
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
    final favorites = _filtered.where((s) => widget.favoriteIds.contains(s.id)).toList();
    final rest = _filtered.where((s) => !widget.favoriteIds.contains(s.id)).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Select location'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, size: 20),
            tooltip: 'Refresh',
            onPressed: _loading ? null : _load,
          ),
        ],
      ),
      body: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
              child: TextField(
                controller: _searchCtrl,
                onChanged: (v) => setState(() => _query = v),
                decoration: InputDecoration(
                  hintText: 'Search country or city',
                  prefixIcon: Icon(Icons.search, size: 18, color: tokens.textFaint),
                ),
              ),
            ),
            if (_error != null)
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
                    'Could not load the server list: $_error',
                    style: TextStyle(fontFamily: 'Plex Sans', fontSize: 12, color: tokens.textMuted),
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
                        _groupLabel(tokens, 'All locations · ${_filtered.length} servers'),
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
      ),
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

  Widget _serverRow(BuildContext context, ChimeraTokens tokens, CatalogServer s) {
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
