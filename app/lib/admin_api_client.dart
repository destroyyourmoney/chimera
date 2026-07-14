// Thin client for the internal/admin HTTP API (list/add/revoke chimera://
// users on a server you manage). Talks to whatever base URL it's given --
// normally 127.0.0.1:<local forwarded port> from an SshAdminTunnel, since the
// real API only ever listens on the server's loopback interface.
import 'dart:convert';
import 'dart:io';

class AdminUser {
  AdminUser({required this.sid, required this.label});

  factory AdminUser.fromJson(Map<String, dynamic> json) => AdminUser(
    sid: json['SID'] as String? ?? json['sid'] as String? ?? '',
    label: json['Label'] as String? ?? json['label'] as String? ?? '',
  );

  final String sid;
  final String label;
}

class AdminApiError implements Exception {
  AdminApiError(this.message);
  final String message;
  @override
  String toString() => message;
}

class AdminApiClient {
  AdminApiClient({required this.localPort, required this.token});

  final int localPort;
  final String token;

  Uri _uri(String path) => Uri.parse('http://127.0.0.1:$localPort$path');

  Future<T> _send<T>(
    String method,
    String path,
    T Function(int status, String body) onResponse, {
    Object? jsonBody,
  }) async {
    final client = HttpClient();
    try {
      final req = await client.openUrl(method, _uri(path));
      req.headers.set('Authorization', 'Bearer $token');
      if (jsonBody != null) {
        req.headers.set('Content-Type', 'application/json');
        req.write(jsonEncode(jsonBody));
      }
      final resp = await req.close();
      final body = await resp.transform(utf8.decoder).join();
      return onResponse(resp.statusCode, body);
    } finally {
      client.close(force: true);
    }
  }

  Future<List<AdminUser>> listUsers() {
    return _send('GET', '/v1/users', (status, body) {
      if (status != 200) throw AdminApiError('list users: HTTP $status');
      final decoded = jsonDecode(body) as List<dynamic>;
      return decoded
          .map((e) => AdminUser.fromJson(e as Map<String, dynamic>))
          .toList();
    });
  }

  Future<AdminUser> addUser(String label) {
    return _send('POST', '/v1/users', (status, body) {
      if (status != 201) {
        throw AdminApiError('add user: HTTP $status: $body');
      }
      return AdminUser.fromJson(jsonDecode(body) as Map<String, dynamic>);
    }, jsonBody: {'label': label});
  }

  Future<void> removeUser(String sid) {
    return _send('DELETE', '/v1/users/$sid', (status, body) {
      if (status != 204 && status != 404) {
        throw AdminApiError('remove user: HTTP $status: $body');
      }
    });
  }
}
