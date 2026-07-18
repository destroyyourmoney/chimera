import 'package:chimera_tray/anticensorship_page.dart';
import 'package:chimera_tray/settings_store.dart';
import 'package:chimera_tray/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _wrap(Widget child) => MaterialApp(theme: chimeraDarkTheme, home: child);

void main() {
  testWidgets('shows all 4 transport names', (tester) async {
    await tester.pumpWidget(
      _wrap(
        AnticensorshipPage(
          current: ObfuscationMode.reality,
          onChanged: (_) async {},
        ),
      ),
    );

    expect(find.text('Reality'), findsOneWidget);
    expect(find.text('QUIC / H3'), findsOneWidget);
    expect(find.text('Shadowsocks-AEAD'), findsOneWidget);
    expect(find.text('DNS-over-TCP'), findsOneWidget);
  });

  testWidgets('tapping a transport calls onChanged with that mode', (
    tester,
  ) async {
    ObfuscationMode? changedTo;
    await tester.pumpWidget(
      _wrap(
        AnticensorshipPage(
          current: ObfuscationMode.reality,
          onChanged: (mode) async => changedTo = mode,
        ),
      ),
    );

    await tester.tap(find.text('Shadowsocks-AEAD'));
    await tester.pumpAndSettle();

    expect(changedTo, ObfuscationMode.shadowsocksAead);
  });

  testWidgets(
    'the current mode starts selected (radio checked icon shown once)',
    (tester) async {
      await tester.pumpWidget(
        _wrap(
          AnticensorshipPage(
            current: ObfuscationMode.dnsOverTcp,
            onChanged: (_) async {},
          ),
        ),
      );

      expect(find.byIcon(Icons.radio_button_checked), findsOneWidget);
      expect(find.byIcon(Icons.radio_button_off), findsNWidgets(3));
    },
  );

  group('availableTransportParams (ROADMAP2 §3/§4 multi-transport)', () {
    testWidgets('null (unknown) keeps every transport tappable', (
      tester,
    ) async {
      ObfuscationMode? changedTo;
      await tester.pumpWidget(
        _wrap(
          AnticensorshipPage(
            current: ObfuscationMode.reality,
            onChanged: (mode) async => changedTo = mode,
            availableTransportParams: null,
          ),
        ),
      );

      await tester.tap(find.text('DNS-over-TCP'));
      await tester.pumpAndSettle();
      expect(changedTo, ObfuscationMode.dnsOverTcp);
    });

    testWidgets('tapping an unavailable transport does not call onChanged', (
      tester,
    ) async {
      ObfuscationMode? changedTo;
      await tester.pumpWidget(
        _wrap(
          AnticensorshipPage(
            current: ObfuscationMode.reality,
            onChanged: (mode) async => changedTo = mode,
            availableTransportParams: const {''},
          ),
        ),
      );

      await tester.tap(find.text('Shadowsocks-AEAD'));
      await tester.pumpAndSettle();
      expect(changedTo, isNull);
    });

    testWidgets('an unavailable transport shows the "not available" caption', (
      tester,
    ) async {
      await tester.pumpWidget(
        _wrap(
          AnticensorshipPage(
            current: ObfuscationMode.reality,
            onChanged: (_) async {},
            availableTransportParams: const {''},
          ),
        ),
      );

      expect(
        find.text('Not available on the currently selected server.'),
        findsNWidgets(3),
      );
    });

    testWidgets('an available transport can still be tapped', (tester) async {
      ObfuscationMode? changedTo;
      await tester.pumpWidget(
        _wrap(
          AnticensorshipPage(
            current: ObfuscationMode.reality,
            onChanged: (mode) async => changedTo = mode,
            availableTransportParams: const {'', 'quic'},
          ),
        ),
      );

      await tester.tap(find.text('QUIC / H3'));
      await tester.pumpAndSettle();
      expect(changedTo, ObfuscationMode.quicH3);
    });
  });
}
