import 'dart:async';
import 'dart:convert';
import 'dart:io';

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

  Future<NetHelperResult> ping() => _call({'cmd': 'ping'});

  Future<NetHelperResult> start({
    required String server,
    required String pbk,
    required String mode,
    String sni = '',
    String sid = '',
    List<String> dns = const [],
    String transport = '',
    String token = '',
  }) => _call({
    'cmd': 'start',
    'server': server,
    'pbk': pbk,
    'mode': mode,
    if (sni.isNotEmpty) 'sni': sni,
    if (sid.isNotEmpty) 'sid': sid,
    if (dns.isNotEmpty) 'dns': dns,
    if (transport.isNotEmpty) 'transport': transport,

    if (token.isNotEmpty) 'capabilityToken': token,
  }, timeout: const Duration(seconds: 15));

  Future<NetHelperResult> stop() => _call({'cmd': 'stop'});
}
