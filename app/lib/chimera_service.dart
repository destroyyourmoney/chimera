// TUN-only tunnel lifecycle for the tray app: no SOCKS5, no chimera.dll
// session. Connect does a fast reachability preflight over chimera.dll's
// FFI (newTunnel/connect/freeHandle -- no startSocks, no isolate, no
// session left open), then hands off to NetworkProtectionController.engage
// to bring up the real TUN device/routes/firewall via chimera-helper (or its
// elevated CLI fallback). Live state/throughput comes from polling
// NetworkProtectionController.status, which is chimera-helper reading the
// chimera.exe tun child's own status file (see internal/tun.Bridge.Stats
// and cmd/chimera/tun_on.go's runStatusWriter) -- not from any local proxy
// session, which is what used to leave the tray showing 0 B/s.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:isolate';

import 'chimera_bindings.dart';
import 'network_protection.dart';
import 'settings_store.dart';

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

/// PrimaryServer is the parsed connection material for the one server the
/// TUN device is actually built against -- resolved by the caller (see
/// main.dart's _resolvePrimaryServer, unchanged) from the first saved
/// server's link, the same "primary server" convention the old
/// NetworkProtection.enable call sites already used.
class PrimaryServer {
  const PrimaryServer({
    required this.host,
    required this.port,
    required this.pbk,
    this.sni = '',
    this.sid = '',
    this.transport = '',
    this.token = '',
  });

  final String host;
  final String port;
  final String pbk;
  final String sni;
  final String sid;

  /// Anti-censorship transport carried by this server's chimera:// link
  /// (its Mode field: '', 'auto', 'quic', or 'tcp') -- forced onto the TUN
  /// device's carrier dialer so full-tunnel Connect actually uses the
  /// obfuscation method the server was configured with, the same way the
  /// old SOCKS5 path used to.
  final String transport;

  /// Control-plane capability token (ROADMAP2 §1), read live from
  /// AccountStore at connect time (see main.dart's _resolvePrimaryServer)
  /// rather than baked into the saved server entry -- the token refreshes
  /// on its own ~24h TTL, so a value captured once at "Choose server" time
  /// would go stale. Empty for -auth-mode useracl servers/legacy BYO links.
  final String token;

  String get address => '$host:$port';
}

class TunnelService {
  /// bindings/controller are injectable so tests can exercise connect/
  /// disconnect/reconnect-watchdog logic against fakes instead of the real
  /// chimera.dll and chimera-helper IPC. Defaults are platform-picked:
  /// ChimeraBindings.open() throws on anything but Windows (no chimera.dll
  /// there), so Android gets AndroidNoPreflightNativeApi (the reachability
  /// check it would have done happens inside ChimeraVpnService.kt's
  /// RealGoTunnel.start instead) paired with AndroidNetworkProtectionController.
  TunnelService({ChimeraNativeApi? bindings, NetworkProtectionController? controller})
    : _bindings =
          bindings ??
          (Platform.isAndroid ? const AndroidNoPreflightNativeApi() : ChimeraBindings.open()),
      _controller =
          controller ??
          (Platform.isAndroid
              ? AndroidNetworkProtectionController()
              : DefaultNetworkProtectionController());

  final ChimeraNativeApi _bindings;
  final NetworkProtectionController _controller;

  Timer? _pollTimer;
  final _stateController = StreamController<ChimeraState>.broadcast();

  // Reconnect watchdog: _desiredConnected reflects the user's own Connect/
  // Disconnect intent, not transient link state. When a poll observes the
  // tunnel down while it's true, _scheduleReconnect retries the whole
  // preflight+engage flow with capped exponential backoff instead of
  // hammering a dead server.
  bool _desiredConnected = false;
  String _lastSubscriptionText = '';
  String _lastSignKeyHex = '';
  NetworkProtectionMode _lastMode = NetworkProtectionMode.dnsLeakGuard;
  List<String> _lastDns = List.of(kDefaultCustomDns);
  PrimaryServer? _lastPrimaryServer;
  Timer? _reconnectTimer;
  Duration _reconnectDelay = _minReconnectDelay;
  static const _minReconnectDelay = Duration(seconds: 2);
  static const _maxReconnectDelay = Duration(seconds: 30);

  Stream<ChimeraState> get stateUpdates => _stateController.stream;

  /// connect verifies the subscription reaches a real handshake fast (via
  /// chimera.dll, no session left open), then brings up the full-tunnel TUN
  /// device against [primaryServer] at [mode]. Returns an error message, or
  /// null on success.
  Future<String?> connect(
    String subscriptionText, {
    required PrimaryServer primaryServer,
    String signKeyHex = '',
    NetworkProtectionMode mode = NetworkProtectionMode.dnsLeakGuard,
    List<String> dns = kDefaultCustomDns,
  }) async {
    await _teardown();
    _desiredConnected = true;
    _lastSubscriptionText = subscriptionText;
    _lastSignKeyHex = signKeyHex;
    _lastMode = mode;
    _lastDns = dns;
    _lastPrimaryServer = primaryServer;
    _reconnectDelay = _minReconnectDelay;

    final err = await _connectOnce();
    if (err == null) return null;
    if (_desiredConnected) _scheduleReconnect();
    return err;
  }

  Future<String?> _connectOnce() async {
    final connectErr = await _preflight(_lastSubscriptionText, _lastSignKeyHex);
    if (connectErr.isNotEmpty) {
      _stateController.add(ChimeraState.disconnected(lastError: connectErr));
      return connectErr;
    }

    final primary = _lastPrimaryServer!;
    final result = await _controller.engage(
      mode: _lastMode,
      server: primary.address,
      pbk: primary.pbk,
      sni: primary.sni,
      sid: primary.sid,
      dns: _lastDns,
      transport: primary.transport,
      token: primary.token,
    );
    if (!result.ok) {
      _stateController.add(ChimeraState.disconnected(lastError: result.error));
      return result.error;
    }

    _startPolling();
    return null;
  }

  /// _preflight runs the newTunnel/connect/freeHandle reachability check
  /// (see ChimeraNativeApi) and returns the connect error, or '' on success.
  ///
  /// `lib.lookupFunction` calls are synchronous, and `connect` blocks on a
  /// real network round-trip (pingAny dialing every configured endpoint in
  /// turn -- see internal/api.pingAny). Run on the real chimera.dll bindings
  /// directly on the UI isolate, that freezes the whole Flutter engine for
  /// the duration: window minimize/move, the tray's own click handling, and
  /// even "Quit" (which awaits disconnect() behind the same isolate) all
  /// stop responding until the native call returns. So for the real bindings
  /// this hands the call to a fresh background isolate (which must reopen
  /// chimera.dll itself -- DynamicLibrary handles don't cross isolates, only
  /// the plain-int tunnel handle does). Fakes (tests, Android's no-op stub)
  /// aren't isolate-sendable and are already instant, so they run inline.
  Future<String> _preflight(String subscriptionText, String signKeyHex) {
    final bindings = _bindings;
    if (bindings is ChimeraBindings) {
      return Isolate.run(
        () => _runPreflight(ChimeraBindings.open(), subscriptionText, signKeyHex),
      );
    }
    return Future.value(_runPreflight(bindings, subscriptionText, signKeyHex));
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
    await _controller.disengage();
  }

  void _scheduleReconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(_reconnectDelay, () async {
      if (!_desiredConnected) return;
      final err = await _connectOnce();
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
      final result = await _controller.status();
      final state = ChimeraState(
        state: result.isRunning ? 'connected' : 'disconnected',
        transport: result.transport,
        bytesUp: result.bytesUp,
        bytesDown: result.bytesDown,
        lastError: result.ok ? '' : result.error,
      );
      _stateController.add(state);
      if (_desiredConnected && !state.isConnected && _reconnectTimer == null) {
        await _teardown();
        _scheduleReconnect();
      }
    });
  }

  void dispose() {
    _pollTimer?.cancel();
    _reconnectTimer?.cancel();
    _stateController.close();
  }
}

/// Top-level so it can run inside the background isolate `_preflight` spawns
/// for the real bindings (an `Isolate.run` closure must not capture `this`).
/// Returns the connect error, or '' on success.
String _runPreflight(
  ChimeraNativeApi bindings,
  String subscriptionText,
  String signKeyHex,
) {
  final newTunnelResult = bindings.newTunnel(subscriptionText, signKeyHex);
  final newTunnelEnv = jsonDecode(newTunnelResult) as Map<String, dynamic>;
  final handleErr = newTunnelEnv['error'] as String? ?? '';
  if (handleErr.isNotEmpty) return handleErr;
  final handle = (newTunnelEnv['handle'] as num).toInt();

  final connectErr = bindings.connect(handle);
  bindings.freeHandle(handle);
  return connectErr;
}
