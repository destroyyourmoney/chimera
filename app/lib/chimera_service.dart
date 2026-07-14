// App-level wrapper around ChimeraBindings: owns the tunnel handle lifecycle,
// runs the blocking StartSocks call on a background isolate (dart:ffi calls
// block the calling isolate for their whole native-call duration, and
// StartSocks blocks until Stop()), and polls StateJSON on a timer for the
// tray UI. Mirrors the lifecycle mobile/bind.go's doc comment prescribes:
// Connect() returns fast, StartSocks() blocks on a background thread,
// StateJSON() is polled ~1s.
import 'dart:async';
import 'dart:convert';
import 'dart:isolate';

import 'chimera_bindings.dart';

class EndpointStatus {
  const EndpointStatus({
    required this.server,
    required this.healthy,
    required this.fails,
    required this.rttMs,
  });

  factory EndpointStatus.fromJson(Map<String, dynamic> json) => EndpointStatus(
    server: json['server'] as String? ?? '',
    healthy: json['healthy'] as bool? ?? false,
    fails: (json['fails'] as num?)?.toInt() ?? 0,
    rttMs: (json['rttMs'] as num?)?.toInt() ?? 0,
  );

  final String server;
  final bool healthy;
  final int fails;
  final int rttMs;
}

class ChimeraState {
  const ChimeraState({
    required this.state,
    required this.transport,
    required this.bytesUp,
    required this.bytesDown,
    required this.lastError,
    this.endpoints = const [],
  });

  factory ChimeraState.disconnected({String lastError = ''}) => ChimeraState(
    state: 'disconnected',
    transport: '',
    bytesUp: 0,
    bytesDown: 0,
    lastError: lastError,
  );

  factory ChimeraState.fromJson(Map<String, dynamic> json) => ChimeraState(
    state: json['state'] as String? ?? 'disconnected',
    transport: json['transport'] as String? ?? '',
    bytesUp: (json['bytesUp'] as num?)?.toInt() ?? 0,
    bytesDown: (json['bytesDown'] as num?)?.toInt() ?? 0,
    lastError: '',
    endpoints: (json['endpoints'] as List<dynamic>? ?? const [])
        .map((e) => EndpointStatus.fromJson(e as Map<String, dynamic>))
        .toList(),
  );

  final String state;
  final String transport;
  final int bytesUp;
  final int bytesDown;
  final String lastError;
  final List<EndpointStatus> endpoints;

  bool get isConnected => state == 'connected';
}

/// _startSocksInIsolate re-opens chimera.dll in the spawned isolate (a
/// DynamicLibrary handle isn't shared across isolates) and runs the blocking
/// StartSocks call there. Only the plain-int handle crosses the isolate
/// boundary -- it's just an opaque number (a runtime/cgo.Handle key on the Go
/// side), not a native pointer, so it's safe to pass via the isolate's
/// argument.
void _startSocksInIsolate(List<Object> args) {
  final handle = args[0] as int;
  final listen = args[1] as String;
  final SendPort done = args[2] as SendPort;
  final bindings = ChimeraBindings.open();
  final err = bindings.startSocks(handle, listen);
  done.send(err);
}

class ChimeraService {
  /// bindings is injectable so tests can exercise connect/disconnect/
  /// reconnect-watchdog logic against a fake instead of the real
  /// chimera.dll. The spawned StartSocks isolate always uses the real
  /// ChimeraBindings.open() (isolates don't share objects), so injection
  /// only covers the main-isolate-only logic -- which is exactly what the
  /// watchdog and connect()/disconnect() bookkeeping is.
  ChimeraService({ChimeraNativeApi? bindings})
    : _bindings = bindings ?? ChimeraBindings.open();

  final ChimeraNativeApi _bindings;
  int? _handle;
  Isolate? _runnerIsolate;
  Timer? _pollTimer;
  final _stateController = StreamController<ChimeraState>.broadcast();

  // Reconnect watchdog (Phase F): _desiredConnected reflects the user's own
  // Connect/Disconnect intent, not transient link state. When the poll loop
  // observes a drop while it's true, _scheduleReconnect retries with capped
  // exponential backoff instead of hammering a dead server.
  bool _desiredConnected = false;
  String _lastSubscriptionText = '';
  String _lastSignKeyHex = '';
  String _lastListen = '127.0.0.1:1080';
  Timer? _reconnectTimer;
  Duration _reconnectDelay = _minReconnectDelay;
  static const _minReconnectDelay = Duration(seconds: 2);
  static const _maxReconnectDelay = Duration(seconds: 30);

  Stream<ChimeraState> get stateUpdates => _stateController.stream;

  /// connect builds a tunnel from a `#!chimera-subscription-v1` document (a
  /// single `chimera://` link is a valid one-line subscription), connects
  /// (fast -- verifies reachability), then starts the SOCKS5 fallback
  /// listener on a background isolate. Returns an error message, or null on
  /// success.
  Future<String?> connect(
    String subscriptionText, {
    String signKeyHex = '',
    String listen = '127.0.0.1:1080',
  }) async {
    await _teardown();
    _desiredConnected = true;
    _lastSubscriptionText = subscriptionText;
    _lastSignKeyHex = signKeyHex;
    _lastListen = listen;
    _reconnectDelay = _minReconnectDelay;

    final err = await _connectOnce(subscriptionText, signKeyHex, listen);
    if (err == null) return null;
    if (_desiredConnected) _scheduleReconnect();
    return err;
  }

  Future<String?> _connectOnce(
    String subscriptionText,
    String signKeyHex,
    String listen,
  ) async {
    final newTunnelResult = _bindings.newTunnel(subscriptionText, signKeyHex);
    final newTunnelEnv = jsonDecode(newTunnelResult) as Map<String, dynamic>;
    final handleErr = newTunnelEnv['error'] as String? ?? '';
    if (handleErr.isNotEmpty) {
      _stateController.add(ChimeraState.disconnected(lastError: handleErr));
      return handleErr;
    }
    final handle = (newTunnelEnv['handle'] as num).toInt();
    _handle = handle;

    final connectErr = _bindings.connect(handle);
    if (connectErr.isNotEmpty) {
      _bindings.freeHandle(handle);
      _handle = null;
      _stateController.add(ChimeraState.disconnected(lastError: connectErr));
      return connectErr;
    }

    final receivePort = ReceivePort();
    _runnerIsolate = await Isolate.spawn(_startSocksInIsolate, [
      handle,
      listen,
      receivePort.sendPort,
    ]);
    // Listen for the runner's eventual exit (Stop() or a real failure) purely
    // for diagnostics; the tray doesn't need to react beyond logging today.
    receivePort.listen((message) {
      receivePort.close();
    });

    _startPolling();
    return null;
  }

  /// disconnect is the user-initiated stop: clears the reconnect intent so
  /// the watchdog does not immediately reconnect.
  Future<void> disconnect() async {
    _desiredConnected = false;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    await _teardown();
    _stateController.add(ChimeraState.disconnected());
  }

  Future<void> _teardown() async {
    _pollTimer?.cancel();
    _pollTimer = null;

    final handle = _handle;
    if (handle != null) {
      _bindings.stop(handle); // cancels the blocking StartSocks runner
      _bindings.freeHandle(handle);
      _handle = null;
    }
    _runnerIsolate?.kill(priority: Isolate.immediate);
    _runnerIsolate = null;
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(_reconnectDelay, () async {
      if (!_desiredConnected) return;
      final err = await _connectOnce(
        _lastSubscriptionText,
        _lastSignKeyHex,
        _lastListen,
      );
      if (err != null && _desiredConnected) {
        _scheduleReconnect();
      } else if (err == null) {
        _reconnectDelay = _minReconnectDelay;
      }
    });
    final next = _reconnectDelay * 2;
    _reconnectDelay = next > _maxReconnectDelay ? _maxReconnectDelay : next;
  }

  void _startPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      final handle = _handle;
      if (handle == null) return;
      final json = _bindings.stateJSON(handle);
      try {
        final decoded = jsonDecode(json) as Map<String, dynamic>;
        final state = ChimeraState.fromJson(decoded);
        _stateController.add(state);
        if (_desiredConnected &&
            !state.isConnected &&
            _reconnectTimer == null) {
          await _teardown();
          _scheduleReconnect();
        }
      } catch (_) {
        // Malformed state JSON should never happen (Go side always emits
        // valid JSON, see facade.go's StateJSON doc comment) -- ignore a
        // single bad tick rather than crash the UI.
      }
    });
  }

  void dispose() {
    _pollTimer?.cancel();
    _reconnectTimer?.cancel();
    _runnerIsolate?.kill(priority: Isolate.immediate);
    _stateController.close();
  }
}
