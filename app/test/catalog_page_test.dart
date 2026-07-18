import 'package:chimera_tray/catalog_cache_store.dart';
import 'package:chimera_tray/catalog_page.dart';
import 'package:chimera_tray/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class _FakeCatalogClient implements CatalogClient {
  _FakeCatalogClient(this._servers, {this.error});

  final List<CatalogServer> _servers;
  final Object? error;

  @override
  Future<List<CatalogServer>> fetch() async {
    if (error != null) throw error!;
    return _servers;
  }
}

class _FakeCatalogCacheStore implements CatalogCacheStore {
  _FakeCatalogCacheStore({CatalogSnapshot? seed}) : _snapshot = seed;

  CatalogSnapshot? _snapshot;

  @override
  Future<CatalogSnapshot?> load() async => _snapshot;

  @override
  Future<void> save(List<CatalogServer> servers) async {
    _snapshot = CatalogSnapshot(servers: servers, fetchedAt: DateTime.now());
  }

  @override
  Future<void> clear() async {
    _snapshot = null;
  }
}

const _stockholm = CatalogServer(
  id: 'se-sto-1',
  host: 'se1.example.com',
  port: 443,
  pubKey: 'pk1',
  sni: 'www.microsoft.com',
  fingerprint: 'chrome',
  city: 'Stockholm',
  country: 'Sweden',
  loadPct: 22,
  healthy: true,
);

const _amsterdam = CatalogServer(
  id: 'nl-ams-1',
  host: 'nl1.example.com',
  port: 443,
  pubKey: 'pk2',
  sni: 'www.microsoft.com',
  fingerprint: 'chrome',
  city: 'Amsterdam',
  country: 'Netherlands',
  loadPct: 40,
  healthy: true,
);

Widget _wrap(Widget child) => MaterialApp(theme: chimeraDarkTheme, home: child);

void main() {
  testWidgets('shows fetched servers grouped under "All locations"', (
    tester,
  ) async {
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const [],
          selectedId: null,
          onToggleFavorite: (_) async {},
          onSelect: (_) async {},
          client: _FakeCatalogClient([_stockholm, _amsterdam]),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Stockholm'), findsOneWidget);
    expect(find.text('Amsterdam'), findsOneWidget);

    expect(find.textContaining('ALL LOCATIONS'), findsOneWidget);
  });

  testWidgets('favorited server appears under "Favorites"', (tester) async {
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const ['se-sto-1'],
          selectedId: null,
          onToggleFavorite: (_) async {},
          onSelect: (_) async {},
          client: _FakeCatalogClient([_stockholm, _amsterdam]),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.textContaining('FAVORITES'), findsOneWidget);
  });

  testWidgets('search filters by city/country', (tester) async {
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const [],
          selectedId: null,
          onToggleFavorite: (_) async {},
          onSelect: (_) async {},
          client: _FakeCatalogClient([_stockholm, _amsterdam]),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'amst');
    await tester.pumpAndSettle();

    expect(find.text('Amsterdam'), findsOneWidget);
    expect(find.text('Stockholm'), findsNothing);
  });

  testWidgets('tapping a server calls onSelect with that server', (
    tester,
  ) async {
    CatalogServer? selected;
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const [],
          selectedId: null,
          onToggleFavorite: (_) async {},
          onSelect: (s) async => selected = s,
          client: _FakeCatalogClient([_stockholm]),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('Stockholm'));
    await tester.pumpAndSettle();

    expect(selected?.id, 'se-sto-1');
  });

  testWidgets('tapping the star calls onToggleFavorite with the server id', (
    tester,
  ) async {
    String? toggledId;
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const [],
          selectedId: null,
          onToggleFavorite: (id) async => toggledId = id,
          onSelect: (_) async {},
          client: _FakeCatalogClient([_stockholm]),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.byIcon(Icons.star_border));
    await tester.pumpAndSettle();

    expect(toggledId, 'se-sto-1');
  });

  testWidgets('shows an error banner when the fetch fails', (tester) async {
    await tester.pumpWidget(
      _wrap(
        CatalogPage(
          favoriteIds: const [],
          selectedId: null,
          onToggleFavorite: (_) async {},
          onSelect: (_) async {},
          client: _FakeCatalogClient(
            const [],
            error: StateError('no account token available'),
          ),
          cache: _FakeCatalogCacheStore(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      find.textContaining("Couldn't load the server list"),
      findsOneWidget,
    );
  });

  testWidgets(
    'shows cached results with a retry note when a refetch fails, instead of going blank',
    (tester) async {
      final cache = _FakeCatalogCacheStore(
        seed: CatalogSnapshot(
          servers: [_stockholm],
          fetchedAt: DateTime.now().subtract(const Duration(minutes: 4)),
        ),
      );
      await tester.pumpWidget(
        _wrap(
          CatalogPage(
            favoriteIds: const [],
            selectedId: null,
            onToggleFavorite: (_) async {},
            onSelect: (_) async {},
            client: _FakeCatalogClient(
              const [],
              error: StateError('control-plane unreachable'),
            ),
            cache: cache,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Stockholm'), findsOneWidget);
      expect(find.textContaining('Showing saved results'), findsOneWidget);
      expect(find.text('Retry'), findsOneWidget);
      expect(
        find.textContaining("Couldn't load the server list"),
        findsNothing,
      );
    },
  );
}
