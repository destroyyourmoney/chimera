// Pure model tests for ChimeraSettings/ServerEntry: JSON round-trip and the
// #!chimera-subscription-v1 document assembly. SettingsStore's file I/O
// (getApplicationSupportDirectory via path_provider) isn't covered here --
// it's a thin wrapper with no branching logic worth mocking a platform
// channel for; the model logic below is where real bugs would hide.
import 'package:chimera_tray/catalog_page.dart';
import 'package:chimera_tray/settings_store.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('ServerEntry', () {
    test('round-trips through JSON', () {
      final entry = ServerEntry(id: 'a1', label: 'My server', link: 'chimera://host:443?pbk=x');
      final decoded = ServerEntry.fromJson(entry.toJson());
      expect(decoded.id, 'a1');
      expect(decoded.label, 'My server');
      expect(decoded.link, 'chimera://host:443?pbk=x');
    });

    test('fromJson defaults missing label/link to empty string', () {
      final decoded = ServerEntry.fromJson({'id': 'a1'});
      expect(decoded.id, 'a1');
      expect(decoded.label, '');
      expect(decoded.link, '');
    });

    test('fromJson defaults catalogListeners to empty when absent', () {
      final decoded = ServerEntry.fromJson({'id': 'a1'});
      expect(decoded.catalogListeners, isEmpty);
    });

    test('round-trips catalogListeners through JSON', () {
      final entry = ServerEntry(
        id: 'catalog-1',
        label: 'Stockholm',
        link: 'chimera://h:443',
        catalogListeners: const [
          CatalogListener(transport: 'reality', port: 443),
          CatalogListener(transport: 'quic', port: 8443),
        ],
      );
      final decoded = ServerEntry.fromJson(entry.toJson());
      expect(decoded.catalogListeners.length, 2);
      expect(decoded.catalogListeners[0].transport, 'reality');
      expect(decoded.catalogListeners[0].port, 443);
      expect(decoded.catalogListeners[1].transport, 'quic');
      expect(decoded.catalogListeners[1].port, 8443);
    });
  });

  group('ChimeraSettings', () {
    test('round-trips through JSON including servers list', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(id: '1', label: 'first', link: 'chimera://a:443'),
          ServerEntry(id: '2', label: 'second', link: 'chimera://b:443'),
        ],
        signKeyHex: 'deadbeef',
        autostart: true,
        networkProtection: NetworkProtectionMode.killswitch,
        customDns: ['9.9.9.9'],
        lastConnectedServerId: '1',
      );
      final decoded = ChimeraSettings.fromJson(settings.toJson());
      expect(decoded.servers.length, 2);
      expect(decoded.servers[0].label, 'first');
      expect(decoded.servers[1].link, 'chimera://b:443');
      expect(decoded.signKeyHex, 'deadbeef');
      expect(decoded.autostart, true);
      expect(decoded.networkProtection, NetworkProtectionMode.killswitch);
      expect(decoded.customDns, ['9.9.9.9']);
      expect(decoded.lastConnectedServerId, '1');
    });

    test('fromJson on empty map yields safe defaults', () {
      final decoded = ChimeraSettings.fromJson({});
      expect(decoded.servers, isEmpty);
      expect(decoded.signKeyHex, '');
      expect(decoded.autostart, false);
      // A missing key (never explicitly saved -- including settings files
      // from before this field existed) migrates to the dnsLeakGuard
      // default -- the floor tier, since the app is TUN-only and there's no
      // "off" anymore. See _networkProtectionModeFromJson's doc comment.
      expect(decoded.networkProtection, NetworkProtectionMode.dnsLeakGuard);
      expect(decoded.customDns, kDefaultCustomDns);
      expect(decoded.lastConnectedServerId, isNull);
    });

    test('fromJson migrates a settings file saved before SOCKS5 removal ("off") to dnsLeakGuard', () {
      final decoded = ChimeraSettings.fromJson({'networkProtection': 'off'});
      expect(decoded.networkProtection, NetworkProtectionMode.dnsLeakGuard);
    });

    test('networkProtection round-trips dnsLeakGuard mode too', () {
      final settings = ChimeraSettings(
        networkProtection: NetworkProtectionMode.dnsLeakGuard,
      );
      final decoded = ChimeraSettings.fromJson(settings.toJson());
      expect(decoded.networkProtection, NetworkProtectionMode.dnsLeakGuard);
    });

    test('fromJson treats an unknown networkProtection string as dnsLeakGuard', () {
      final decoded = ChimeraSettings.fromJson({'networkProtection': 'garbage'});
      expect(decoded.networkProtection, NetworkProtectionMode.dnsLeakGuard);
    });

    test('subscriptionText assembles the #!chimera-subscription-v1 header and one link per line', () {
      final settings = ChimeraSettings(servers: [
        ServerEntry(id: '1', label: 'a', link: 'chimera://a:443?pbk=x'),
        ServerEntry(id: '2', label: 'b', link: 'chimera://b:443?pbk=y'),
      ]);
      final doc = settings.subscriptionText();
      final lines = doc.split('\n');
      expect(lines[0], '#!chimera-subscription-v1');
      expect(lines[1], 'chimera://a:443?pbk=x');
      expect(lines[2], 'chimera://b:443?pbk=y');
    });

    test('subscriptionText with no servers is still a valid header-only document', () {
      final doc = ChimeraSettings().subscriptionText();
      expect(doc, '#!chimera-subscription-v1\n');
    });

    test('reordering servers changes subscriptionText line order (priority = order)', () {
      final settings = ChimeraSettings(servers: [
        ServerEntry(id: '1', label: 'a', link: 'chimera://a:443'),
        ServerEntry(id: '2', label: 'b', link: 'chimera://b:443'),
      ]);
      final before = settings.subscriptionText();
      final item = settings.servers.removeAt(1);
      settings.servers.insert(0, item);
      final after = settings.subscriptionText();
      expect(before, isNot(equals(after)));
      expect(after.split('\n')[1], 'chimera://b:443');
    });

    test('fromJson defaults splitTunnel to disabled/exclude/empty when absent', () {
      final decoded = ChimeraSettings.fromJson({});
      expect(decoded.splitTunnel.enabled, false);
      expect(decoded.splitTunnel.mode, SplitTunnelMode.exclude);
      expect(decoded.splitTunnel.apps, isEmpty);
      expect(decoded.splitTunnel.template, isNull);
    });

    test('round-trips splitTunnel through JSON', () {
      final settings = ChimeraSettings(
        splitTunnel: SplitTunnelSettings(
          enabled: true,
          mode: SplitTunnelMode.include,
          apps: [SplitTunnelApp(id: 'app.id', name: 'Telegram')],
          template: 'Messengers',
        ),
      );
      final decoded = ChimeraSettings.fromJson(settings.toJson());
      expect(decoded.splitTunnel.enabled, true);
      expect(decoded.splitTunnel.mode, SplitTunnelMode.include);
      expect(decoded.splitTunnel.apps.single.id, 'app.id');
      expect(decoded.splitTunnel.apps.single.name, 'Telegram');
      expect(decoded.splitTunnel.template, 'Messengers');
    });
  });

  group('ObfuscationMode', () {
    test('round-trips all four values through JSON', () {
      for (final mode in ObfuscationMode.values) {
        final settings = ChimeraSettings(obfuscationMode: mode);
        final decoded = ChimeraSettings.fromJson(settings.toJson());
        expect(decoded.obfuscationMode, mode);
      }
    });

    test('fromJson defaults to reality when absent or unrecognized', () {
      expect(ChimeraSettings.fromJson({}).obfuscationMode, ObfuscationMode.reality);
      expect(
        ChimeraSettings.fromJson({'obfuscationMode': 'garbage'}).obfuscationMode,
        ObfuscationMode.reality,
      );
    });
  });

  group('obfuscationModeQueryParam', () {
    test('maps all 4 modes to the query-param value subscription.go expects', () {
      expect(obfuscationModeQueryParam(ObfuscationMode.reality), '');
      expect(obfuscationModeQueryParam(ObfuscationMode.quicH3), 'quic');
      expect(obfuscationModeQueryParam(ObfuscationMode.shadowsocksAead), 'ss');
      expect(obfuscationModeQueryParam(ObfuscationMode.dnsOverTcp), 'dot');
    });
  });

  group('applyObfuscationModeToCatalogServers', () {
    test('rewrites mode= on a catalog server link, preserving other params', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(
            id: 'catalog-1',
            label: 'Stockholm, Sweden',
            link: 'chimera://185.100.157.232:443?pbk=abc&sni=example.com&fp=chrome#1',
          ),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.shadowsocksAead);

      final uri = Uri.parse(settings.servers.single.link);
      expect(uri.queryParameters['mode'], 'ss');
      expect(uri.queryParameters['pbk'], 'abc');
      expect(uri.queryParameters['sni'], 'example.com');
      expect(uri.queryParameters['fp'], 'chrome');
    });

    test('switching to Reality removes the mode= param entirely (matches _upsertCuratedServer)', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(
            id: 'catalog-1',
            label: 'Stockholm, Sweden',
            link: 'chimera://185.100.157.232:443?pbk=abc&mode=quic',
          ),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.reality);

      final uri = Uri.parse(settings.servers.single.link);
      expect(uri.queryParameters.containsKey('mode'), isFalse);
    });

    test('leaves non-catalog (BYO/legacy) server links untouched', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(id: 'byo-1', label: 'My server', link: 'chimera://host:443?pbk=x&mode=quic'),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.shadowsocksAead);

      expect(settings.servers.single.link, 'chimera://host:443?pbk=x&mode=quic');
    });

    test('updates every saved catalog server, not just the first', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(id: 'catalog-1', label: 'a', link: 'chimera://a:443?pbk=x'),
          ServerEntry(id: 'catalog-2', label: 'b', link: 'chimera://b:443?pbk=y'),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.dnsOverTcp);

      for (final s in settings.servers) {
        expect(Uri.parse(s.link).queryParameters['mode'], 'dot');
      }
    });
  });

  group('applyObfuscationModeToCatalogServers with catalogListeners (per-transport ports)', () {
    test('rewrites both mode= and the port to the target transport\'s own listener port', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(
            id: 'catalog-1',
            label: 'Stockholm, Sweden',
            link: 'chimera://185.100.157.232:443?pbk=abc&sni=example.com',
            catalogListeners: const [
              CatalogListener(transport: 'reality', port: 443),
              CatalogListener(transport: 'quic', port: 8443),
              CatalogListener(transport: 'ss', port: 8444),
              CatalogListener(transport: 'dot', port: 8445),
            ],
          ),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.shadowsocksAead);

      final uri = Uri.parse(settings.servers.single.link);
      expect(uri.port, 8444);
      expect(uri.queryParameters['mode'], 'ss');
      expect(uri.queryParameters['pbk'], 'abc');
      expect(uri.host, '185.100.157.232');
    });

    test('switching back to Reality restores the reality listener\'s port and drops mode=', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(
            id: 'catalog-1',
            label: 'a',
            link: 'chimera://h:8443?pbk=x&mode=quic',
            catalogListeners: const [
              CatalogListener(transport: 'reality', port: 443),
              CatalogListener(transport: 'quic', port: 8443),
            ],
          ),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.reality);

      final uri = Uri.parse(settings.servers.single.link);
      expect(uri.port, 443);
      expect(uri.queryParameters.containsKey('mode'), isFalse);
    });

    test('leaves a server unchanged entirely when it has no listener for the target transport', () {
      final original = 'chimera://h:443?pbk=x';
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(
            id: 'catalog-1',
            label: 'a',
            link: original,
            catalogListeners: const [CatalogListener(transport: 'reality', port: 443)],
          ),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.quicH3);

      // Not switched to a port that can't work -- link is byte-for-byte
      // untouched, still dialing the one transport this server actually has.
      expect(settings.servers.single.link, original);
    });

    test('falls back to mode-only rewrite (legacy behavior) when catalogListeners is empty', () {
      final settings = ChimeraSettings(
        servers: [
          ServerEntry(id: 'catalog-1', label: 'a', link: 'chimera://h:443?pbk=x'),
        ],
      );

      settings.applyObfuscationModeToCatalogServers(ObfuscationMode.quicH3);

      final uri = Uri.parse(settings.servers.single.link);
      // No listener info recorded (e.g. an older catalog fetch) -- port is
      // left alone, only mode= is best-effort updated as before this field
      // existed.
      expect(uri.port, 443);
      expect(uri.queryParameters['mode'], 'quic');
    });
  });

  group('favoriteServerIds', () {
    test('round-trips through JSON', () {
      final settings = ChimeraSettings(favoriteServerIds: ['se-sto-1', 'nl-ams-1']);
      final decoded = ChimeraSettings.fromJson(settings.toJson());
      expect(decoded.favoriteServerIds, ['se-sto-1', 'nl-ams-1']);
    });

    test('defaults to empty when absent', () {
      expect(ChimeraSettings.fromJson({}).favoriteServerIds, isEmpty);
    });
  });

  group('SplitTunnelSettings', () {
    test('fromJson treats any non-"include" mode string as exclude', () {
      final decoded = SplitTunnelSettings.fromJson({'mode': 'garbage'});
      expect(decoded.mode, SplitTunnelMode.exclude);
    });

    test('SplitTunnelApp round-trips through JSON', () {
      final app = SplitTunnelApp(id: 'x', name: 'Y');
      final decoded = SplitTunnelApp.fromJson(app.toJson());
      expect(decoded.id, 'x');
      expect(decoded.name, 'Y');
    });
  });
}
