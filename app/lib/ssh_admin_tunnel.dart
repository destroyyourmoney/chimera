// Opens a local-forwarded SSH tunnel to a managed server's loopback-only
// users-admin API (internal/admin, normally bound to 127.0.0.1:<adminApiPort>
// on the server -- see cmd/chimera's -admin-listen). The admin API is never
// exposed on the server's public interface: an extra open port would itself
// be a signal a passive/active observer could use to tell this host apart
// from a plain HTTPS server, which is exactly what the rest of CHIMERA goes
// out of its way to avoid. Reaching it the same way an operator's `ssh -L`
// would is the point, not a workaround.
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';

/// SshAdminTunnel owns one SSH connection plus a local TCP listener that
/// forwards every accepted connection to the remote admin API over that SSH
/// connection (the `ssh -L <local>:127.0.0.1:<adminApiPort>` pattern). Callers
/// talk plain HTTP to `http://127.0.0.1:<localPort>/...` as returned by
/// [open]; [close] tears down both the listener and the SSH connection.
class SshAdminTunnel {
  SSHClient? _client;
  ServerSocket? _localServer;

  /// open connects over SSH to host:sshPort as user/password, starts a local
  /// listener on an OS-assigned loopback port, and forwards every connection
  /// accepted there to 127.0.0.1:adminApiPort on the remote host. Returns the
  /// local port to connect the HTTP client to.
  Future<int> open({
    required String host,
    required int sshPort,
    required String user,
    required String password,
    required int adminApiPort,
  }) async {
    final socket = await SSHSocket.connect(
      host,
      sshPort,
      timeout: const Duration(seconds: 15),
    );
    final client = SSHClient(
      socket,
      username: user,
      onPasswordRequest: () => password,
    );
    _client = client;

    final localServer = await ServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    _localServer = localServer;

    localServer.listen((conn) async {
      try {
        final forward = await client.forwardLocal('127.0.0.1', adminApiPort);
        conn.listen(
          (data) => forward.sink.add(data),
          onDone: () => forward.sink.close(),
          onError: (_) => forward.sink.close(),
          cancelOnError: true,
        );
        forward.stream.listen(
          (data) => conn.add(data),
          onDone: () => conn.close(),
          onError: (_) => conn.close(),
          cancelOnError: true,
        );
      } catch (_) {
        conn.destroy();
      }
    });

    return localServer.port;
  }

  Future<void> close() async {
    await _localServer?.close();
    _localServer = null;
    _client?.close();
    _client = null;
  }
}
