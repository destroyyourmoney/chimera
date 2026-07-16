// Widget tests for catalog_page.dart, using a fake CatalogClient (no real
// HTTP call) -- CatalogPage takes an optional `client` for exactly this
// kind of injection, same reasoning server_test.go's fakeSteal gives for
// substituting a real dependency in tests.
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
  testWidgets('shows fetched servers grouped under "All locations"', (tester) async {
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const [],
      selectedId: null,
      onToggleFavorite: (_) async {},
      onSelect: (_) async {},
      client: _FakeCatalogClient([_stockholm, _amsterdam]),
    )));
    await tester.pumpAndSettle();

    expect(find.text('Stockholm'), findsOneWidget);
    expect(find.text('Amsterdam'), findsOneWidget);
    // Group labels are rendered uppercase (_groupLabel calls .toUpperCase()).
    expect(find.textContaining('ALL LOCATIONS'), findsOneWidget);
  });

  testWidgets('favorited server appears under "Favorites"', (tester) async {
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const ['se-sto-1'],
      selectedId: null,
      onToggleFavorite: (_) async {},
      onSelect: (_) async {},
      client: _FakeCatalogClient([_stockholm, _amsterdam]),
    )));
    await tester.pumpAndSettle();

    expect(find.textContaining('FAVORITES'), findsOneWidget);
  });

  testWidgets('search filters by city/country', (tester) async {
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const [],
      selectedId: null,
      onToggleFavorite: (_) async {},
      onSelect: (_) async {},
      client: _FakeCatalogClient([_stockholm, _amsterdam]),
    )));
    await tester.pumpAndSettle();

    await tester.enterText(find.byType(TextField), 'amst');
    await tester.pumpAndSettle();

    expect(find.text('Amsterdam'), findsOneWidget);
    expect(find.text('Stockholm'), findsNothing);
  });

  testWidgets('tapping a server calls onSelect with that server', (tester) async {
    CatalogServer? selected;
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const [],
      selectedId: null,
      onToggleFavorite: (_) async {},
      onSelect: (s) async => selected = s,
      client: _FakeCatalogClient([_stockholm]),
    )));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Stockholm'));
    await tester.pumpAndSettle();

    expect(selected?.id, 'se-sto-1');
  });

  testWidgets('tapping the star calls onToggleFavorite with the server id', (tester) async {
    String? toggledId;
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const [],
      selectedId: null,
      onToggleFavorite: (id) async => toggledId = id,
      onSelect: (_) async {},
      client: _FakeCatalogClient([_stockholm]),
    )));
    await tester.pumpAndSettle();

    await tester.tap(find.byIcon(Icons.star_border));
    await tester.pumpAndSettle();

    expect(toggledId, 'se-sto-1');
  });

  testWidgets('shows an error banner when the fetch fails', (tester) async {
    await tester.pumpWidget(_wrap(CatalogPage(
      favoriteIds: const [],
      selectedId: null,
      onToggleFavorite: (_) async {},
      onSelect: (_) async {},
      client: _FakeCatalogClient(const [], error: StateError('no account token available')),
    )));
    await tester.pumpAndSettle();

    expect(find.textContaining('Could not load the server list'), findsOneWidget);
  });
}
