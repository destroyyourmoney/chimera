// Tests ChimeraService's main-isolate bookkeeping: connect()/disconnect()
// return values and the reconnect watchdog's exponential backoff, against a
// FakeChimeraApi instead of the real chimera.dll (not present in the
// `flutter test` working directory, and each real call would be an actual
// native call). The StartSocks runner always spawns via the real
// ChimeraBindings.open() singleton (isolates can't share injected fakes) --
// in this test environment that isolate fails to load chimera.dll and dies
// with a stderr-only error, which is harmless and doesn't affect the
// assertions below (they only cover main-isolate state, which is already
// returned/set before the isolate's own outcome matters).
import 'dart:convert';

import 'package:chimera_tray/chimera_bindings.dart';
import 'package:chimera_tray/chimera_service.dart';
import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeChimeraApi implements ChimeraNativeApi {
  String? connectError;
  int newTunnelCallCount = 0;
  int connectCallCount = 0;
  int nextHandle = 1;

  @override
  String newTunnel(String subscriptionText, String signKeyHex) {
    newTunnelCallCount++;
    return jsonEncode({'handle': nextHandle, 'error': ''});
  }

  @override
  String newTunnelFromLink(String uri) =>
      jsonEncode({'handle': nextHandle, 'error': ''});

  @override
  String connect(int handle) {
    connectCallCount++;
    return connectError ?? '';
  }

  @override
  String startFD(int handle, int fd, int mtu) => '';

  @override
  String startSocks(int handle, String listen) => '';

  @override
  void stop(int handle) {}

  @override
  String stateJSON(int handle) =>
      jsonEncode({'state': 'connected', 'transport': 'tcp', 'bytesUp': 0, 'bytesDown': 0});

  @override
  String parseLink(String uri) => jsonEncode({'result': '{}', 'error': ''});

  @override
  String deployServer(String specJson) =>
      jsonEncode({'result': '{}', 'error': ''});

  @override
  void freeHandle(int handle) {}
}

const _sub = '#!chimera-subscription-v1\nchimera://127.0.0.1:443?pbk=x\n';

void main() {
  group('ChimeraState.fromJson', () {
    test('parses endpoints and isConnected', () {
      final state = ChimeraState.fromJson({
        'state': 'connected',
        'transport': 'quic',
        'bytesUp': 10,
        'bytesDown': 20,
        'endpoints': [
          {'server': 'a:443', 'healthy': true, 'fails': 0, 'rttMs': 15},
        ],
      });
      expect(state.isConnected, true);
      expect(state.transport, 'quic');
      expect(state.endpoints, hasLength(1));
      expect(state.endpoints.single.server, 'a:443');
      expect(state.endpoints.single.healthy, true);
      expect(state.endpoints.single.rttMs, 15);
    });

    test('missing fields default safely and isConnected is false', () {
      final state = ChimeraState.fromJson({});
      expect(state.state, 'disconnected');
      expect(state.isConnected, false);
      expect(state.endpoints, isEmpty);
    });
  });

  group('ChimeraService.connect', () {
    test('returns the error string on a failed native connect, without spawning the runner', () async {
      final fake = FakeChimeraApi()..connectError = 'auth failed';
      final service = ChimeraService(bindings: fake);
      final err = await service.connect(_sub);
      expect(err, 'auth failed');
      expect(fake.newTunnelCallCount, 1);
      expect(fake.connectCallCount, 1);
      service.dispose();
    });

    test('returns null on success and records the native calls', () async {
      final fake = FakeChimeraApi();
      final service = ChimeraService(bindings: fake);
      final err = await service.connect(_sub, listen: '127.0.0.1:11080');
      expect(err, isNull);
      expect(fake.newTunnelCallCount, 1);
      expect(fake.connectCallCount, 1);
      service.dispose();
    });
  });

  group('ChimeraService reconnect watchdog', () {
    test('retries with exponential backoff capped at 30s while connect keeps failing', () {
      fakeAsync((async) {
        final fake = FakeChimeraApi()..connectError = 'boom';
        final service = ChimeraService(bindings: fake);

        service.connect(_sub);
        async.flushMicrotasks();
        expect(fake.connectCallCount, 1);

        async.elapse(const Duration(seconds: 2));
        expect(fake.connectCallCount, 2); // first retry: min backoff (2s)

        async.elapse(const Duration(seconds: 4));
        expect(fake.connectCallCount, 3); // backoff doubled to 4s

        async.elapse(const Duration(seconds: 8));
        expect(fake.connectCallCount, 4); // backoff doubled to 8s

        async.elapse(const Duration(seconds: 16));
        expect(fake.connectCallCount, 5); // backoff doubled to 16s

        async.elapse(const Duration(seconds: 30));
        expect(fake.connectCallCount, 6); // capped at 30s, not 32s

        async.elapse(const Duration(seconds: 30));
        expect(fake.connectCallCount, 7); // stays capped at 30s

        service.dispose();
      });
    });

    test('disconnect() cancels a pending reconnect and stops further retries', () {
      fakeAsync((async) {
        final fake = FakeChimeraApi()..connectError = 'boom';
        final service = ChimeraService(bindings: fake);

        service.connect(_sub);
        async.flushMicrotasks();
        expect(fake.connectCallCount, 1);

        service.disconnect();
        async.flushMicrotasks();

        async.elapse(const Duration(seconds: 100));
        expect(fake.connectCallCount, 1); // no retries after user disconnect

        service.dispose();
      });
    });

    test('a fresh connect() call resets backoff to the minimum', () {
      fakeAsync((async) {
        final fake = FakeChimeraApi()..connectError = 'boom';
        final service = ChimeraService(bindings: fake);

        service.connect(_sub);
        async.flushMicrotasks();
        async.elapse(const Duration(seconds: 2));
        async.elapse(const Duration(seconds: 4));
        expect(fake.connectCallCount, 3);

        // User-initiated reconnect should restart backoff at the minimum
        // (2s), not continue from wherever the watchdog had grown to.
        service.connect(_sub);
        async.flushMicrotasks();
        expect(fake.connectCallCount, 4);

        async.elapse(const Duration(seconds: 2));
        expect(fake.connectCallCount, 5); // min backoff again, not 8s

        service.dispose();
      });
    });
  });
}
