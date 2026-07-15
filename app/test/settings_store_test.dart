// Pure model tests for ChimeraSettings/ServerEntry: JSON round-trip and the
// #!chimera-subscription-v1 document assembly. SettingsStore's file I/O
// (getApplicationSupportDirectory via path_provider) isn't covered here --
// it's a thin wrapper with no branching logic worth mocking a platform
// channel for; the model logic below is where real bugs would hide.
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
