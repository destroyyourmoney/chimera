// Dart-side client for chimera-helper, the persistent Windows service that
// owns full-tunnel network setup (TUN device, routes, DNS, firewall) so
// Connect doesn't need a UAC prompt every time -- see
// internal/nethelper's doc comment (Go side of this same protocol) for the
// full design rationale. One newline-delimited JSON request/response per
// TCP connection to 127.0.0.1:_port, authenticated by a shared-secret token
// file chimera-helper.exe install writes under %ProgramData%\chimera\ --
// readable by any locally logged-in user's unprivileged process (including
// this one), by design; see that file's own doc comment for the tradeoff.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// _port MUST match internal/nethelper.Port (Go). Not shared code across
/// the two languages, so keep them in sync by hand if this ever changes.
const int _port = 47821;

class NetHelperResult {
  const NetHelperResult({
    required this.ok,
    this.error = '',
    this.state = '',
    this.bytesUp = 0,
    this.bytesDown = 0,
    this.server = '',
    this.transport = '',
  });
  final bool ok;
  final String error;
  final String state;

  /// Live throughput/identity of the running tunnel, sourced from
  /// chimera-helper's own read of the chimera.exe tun child's status file --
  /// zero/empty when nothing is running or Handle didn't attach them (see
  /// internal/nethelper.Server.fillStats).
  final int bytesUp;
  final int bytesDown;
  final String server;
  final String transport;

  bool get isRunning => state == 'running';
}

class NetHelperClient {
  Future<String?> _readToken() async {
    final programData = Platform.environment['ProgramData'];
    if (programData == null || programData.isEmpty) return null;
    final file = File('$programData\\chimera\\helper.token');
    if (!await file.exists()) return null;
    try {
      return (await file.readAsString()).trim();
    } catch (_) {
      return null;
    }
  }

  Future<NetHelperResult> _call(
    Map<String, dynamic> req, {
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final token = await _readToken();
    if (token == null) {
      return const NetHelperResult(
        ok: false,
        error: 'chimera-helper is not installed',
      );
    }
    Socket? socket;
    try {
      socket = await Socket.connect(
        '127.0.0.1',
        _port,
        timeout: const Duration(seconds: 3),
      );
      socket.write(jsonEncode({...req, 'token': token}));
      await socket.flush();

      final line = await socket
          .cast<List<int>>()
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .first
          .timeout(timeout);
      final decoded = jsonDecode(line) as Map<String, dynamic>;
      return NetHelperResult(
        ok: decoded['ok'] as bool? ?? false,
        error: decoded['error'] as String? ?? '',
        state: decoded['state'] as String? ?? '',
        bytesUp: (decoded['bytesUp'] as num?)?.toInt() ?? 0,
        bytesDown: (decoded['bytesDown'] as num?)?.toInt() ?? 0,
        server: decoded['server'] as String? ?? '',
        transport: decoded['transport'] as String? ?? '',
      );
    } catch (e) {
      return NetHelperResult(ok: false, error: e.toString());
    } finally {
      unawaited(socket?.close());
    }
  }

  /// ping reports whether chimera-helper is installed, running, and
  /// authenticates this app's token -- the three things that all have to be
  /// true before Connect can hand it a full-tunnel request.
  Future<NetHelperResult> ping() => _call({'cmd': 'ping'});

  /// start (re)configures the full-tunnel: creates the TUN device, applies
  /// OS routes/DNS/firewall for [mode] ('dnsLeakGuard' or 'killswitch'), and
  /// connects the carrier to [server]. Safe to call while already running --
  /// the previous tunnel is torn down first (see cmd/chimera-helper's
  /// procRunner.Start).
  Future<NetHelperResult> start({
    required String server,
    required String pbk,
    required String mode,
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '', // control-plane capability token, ROADMAP2 §1
  }) => _call({
    'cmd': 'start',
    'server': server,
    'pbk': pbk,
    'mode': mode,
    if (sni.isNotEmpty) 'sni': sni,
    if (sid.isNotEmpty) 'sid': sid,
    if (dns.isNotEmpty) 'dns': dns,
    if (transport.isNotEmpty) 'transport': transport,
    // 'capabilityToken', not 'token' -- that key is already taken by the
    // chimera-helper shared secret _call adds below (see nethelper.Request's
    // two distinct token fields).
    if (token.isNotEmpty) 'capabilityToken': token,
  }, timeout: const Duration(seconds: 15));

  /// stop tears down the full-tunnel and restores normal OS routing. Always
  /// reports ok:true from the service side (see internal/nethelper.Server's
  /// doc comment) as long as the service itself is reachable.
  Future<NetHelperResult> stop() => _call({'cmd': 'stop'});
}
