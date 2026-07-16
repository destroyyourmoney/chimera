// Widget tests for anticensorship_page.dart: the 4-transport picker
// persists the selection via its onChanged callback and reflects the
// `current` mode visually (selected card highlighted).
import 'package:chimera_tray/anticensorship_page.dart';
import 'package:chimera_tray/settings_store.dart';
import 'package:chimera_tray/theme.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

Widget _wrap(Widget child) => MaterialApp(theme: chimeraDarkTheme, home: child);

void main() {
  testWidgets('shows all 4 transport names', (tester) async {
    await tester.pumpWidget(_wrap(AnticensorshipPage(
      current: ObfuscationMode.reality,
      onChanged: (_) async {},
    )));

    expect(find.text('Reality'), findsOneWidget);
    expect(find.text('QUIC / H3'), findsOneWidget);
    expect(find.text('Shadowsocks-AEAD'), findsOneWidget);
    expect(find.text('DNS-over-TCP'), findsOneWidget);
  });

  testWidgets('tapping a transport calls onChanged with that mode', (tester) async {
    ObfuscationMode? changedTo;
    await tester.pumpWidget(_wrap(AnticensorshipPage(
      current: ObfuscationMode.reality,
      onChanged: (mode) async => changedTo = mode,
    )));

    await tester.tap(find.text('Shadowsocks-AEAD'));
    await tester.pumpAndSettle();

    expect(changedTo, ObfuscationMode.shadowsocksAead);
  });

  testWidgets('the current mode starts selected (radio checked icon shown once)', (tester) async {
    await tester.pumpWidget(_wrap(AnticensorshipPage(
      current: ObfuscationMode.dnsOverTcp,
      onChanged: (_) async {},
    )));

    expect(find.byIcon(Icons.radio_button_checked), findsOneWidget);
    expect(find.byIcon(Icons.radio_button_off), findsNWidgets(3));
  });
}
