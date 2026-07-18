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
    this.isReconnecting = false,
  });

  factory ChimeraState.disconnected({
    String lastError = '',
    bool isReconnecting = false,
  }) => ChimeraState(
    state: 'disconnected',
    transport: '',
    bytesUp: 0,
    bytesDown: 0,
    lastError: lastError,
    isReconnecting: isReconnecting,
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

  final bool isReconnecting;

  bool get isConnected => state == 'connected';
}

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

  final String transport;

  final String token;

  String get address => '$host:$port';
}

class TunnelService {
  TunnelService({
    ChimeraNativeApi? bindings,
    NetworkProtectionController? controller,
  }) : _bindings =
           bindings ??
           (Platform.isAndroid
               ? const AndroidNoPreflightNativeApi()
               : ChimeraBindings.open()),
       _controller =
           controller ??
           (Platform.isAndroid
               ? AndroidNetworkProtectionController()
               : DefaultNetworkProtectionController());

  final ChimeraNativeApi _bindings;
  final NetworkProtectionController _controller;

  Timer? _pollTimer;
  final _stateController = StreamController<ChimeraState>.broadcast();

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

  Future<String> _preflight(String subscriptionText, String signKeyHex) {
    final bindings = _bindings;
    if (bindings is ChimeraBindings) {
      return Isolate.run(
        () =>
            _runPreflight(ChimeraBindings.open(), subscriptionText, signKeyHex),
      );
    }
    return Future.value(_runPreflight(bindings, subscriptionText, signKeyHex));
  }

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

    _stateController.add(ChimeraState.disconnected(isReconnecting: true));
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

String friendlyConnectError(String raw) {
  if (raw.isEmpty) return raw;
  final lower = raw.toLowerCase();
  if (lower.contains('deadline exceeded') ||
      lower.contains('timeout') ||
      lower.contains('timed out')) {
    return 'Server took too long to respond. Try again or pick a different location.';
  }
  if (lower.contains('wsarecv') ||
      lower.contains('connection attempt failed') ||
      lower.contains('actively refused') ||
      lower.contains('connection refused')) {
    return "Couldn't reach the server. It may be offline or blocked on this network.";
  }
  if (lower.contains('all endpoints failed')) {
    return 'None of the available servers responded. Try a different location.';
  }
  return raw;
}

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
