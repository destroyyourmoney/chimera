// Unit tests for CatalogServer/CatalogListener multi-transport parsing
// (ROADMAP2 §3/§4): a server can run several `chimera server -transport X`
// listeners, each on its own port, and the client must never treat a
// transport as dialable unless the catalog actually says so.
import 'package:chimera_tray/catalog_page.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('CatalogServer.fromJson listeners', () {
    test('parses an explicit listeners array', () {
      final server = CatalogServer.fromJson({
        'id': 1,
        'host': 'h',
        'port': 443,
        'pubkey': 'pk',
        'sni': 'sni',
        'country': 'Sweden',
        'city': 'Stockholm',
        'listeners': [
          {'transport': 'reality', 'port': 443},
          {'transport': 'quic', 'port': 8443},
          {'transport': 'ss', 'port': 8444},
          {'transport': 'dot', 'port': 8445},
        ],
      });

      expect(server.listeners.length, 4);
      expect(server.portFor(''), 443);
      expect(server.portFor('quic'), 8443);
      expect(server.portFor('ss'), 8444);
      expect(server.portFor('dot'), 8445);
    });

    test('synthesizes a single Reality listener when listeners is absent (old control-plane)', () {
      final server = CatalogServer.fromJson({
        'id': 1,
        'host': 'h',
        'port': 443,
        'pubkey': 'pk',
        'sni': 'sni',
        'country': 'X',
        'city': 'Y',
      });

      expect(server.listeners.length, 1);
      expect(server.listeners.single.transport, 'reality');
      expect(server.portFor(''), 443);
      expect(server.portFor('quic'), isNull);
    });

    test('synthesizes a single Reality listener when listeners is an empty array', () {
      final server = CatalogServer.fromJson({
        'id': 1,
        'host': 'h',
        'port': 443,
        'pubkey': 'pk',
        'sni': 'sni',
        'country': 'X',
        'city': 'Y',
        'listeners': [],
      });

      expect(server.listeners.length, 1);
      expect(server.listeners.single.transport, 'reality');
    });

    test('portFor returns null for a transport this server does not offer', () {
      final server = CatalogServer.fromJson({
        'id': 1,
        'host': 'h',
        'port': 443,
        'pubkey': 'pk',
        'sni': 'sni',
        'country': 'X',
        'city': 'Y',
        'listeners': [
          {'transport': 'reality', 'port': 443},
        ],
      });

      expect(server.portFor('quic'), isNull);
      expect(server.portFor('ss'), isNull);
      expect(server.portFor('dot'), isNull);
    });
  });

  group('CatalogServer.availableTransportParams', () {
    test('maps reality to the empty-string param used by obfuscationModeQueryParam', () {
      final server = CatalogServer.fromJson({
        'id': 1,
        'host': 'h',
        'port': 443,
        'pubkey': 'pk',
        'sni': 'sni',
        'country': 'X',
        'city': 'Y',
        'listeners': [
          {'transport': 'reality', 'port': 443},
          {'transport': 'quic', 'port': 8443},
        ],
      });

      expect(server.availableTransportParams, {'', 'quic'});
    });
  });
}
