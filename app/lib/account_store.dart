import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart' as http_io;
import 'package:path_provider/path_provider.dart';

const _kSecureStorage = FlutterSecureStorage();
const _kTokenKey = 'chimera_token';

const Map<String, String> kMirrorCertPins = {};

http.Client _buildPinnedClient() {
  final inner = HttpClient();
  inner.badCertificateCallback = (cert, host, port) {
    final pin = kMirrorCertPins[host];
    if (pin == null) return false;
    final actual = sha256.convert(cert.der).toString();
    return actual == pin;
  };
  return http_io.IOClient(inner);
}

const _kAlphabet = '23456789ABCDEFGHJKMNPQRSTVWXYZ';
final _kGroupPattern = '[$_kAlphabet]{4}';
final _kKeyPattern = RegExp(
  '^$_kGroupPattern-$_kGroupPattern-$_kGroupPattern-$_kGroupPattern\$',
);

String normalizeAccountNumber(String raw) {
  final stripped = raw.toUpperCase().replaceAll(RegExp(r'[\s-]'), '');
  final groups = <String>[];
  for (var i = 0; i < stripped.length; i += 4) {
    groups.add(stripped.substring(i, min(i + 4, stripped.length)));
  }
  return groups.join('-');
}

bool isValidAccountNumber(String normalized) =>
    _kKeyPattern.hasMatch(normalized);

enum AccountStatus { active, expired, revoked }

AccountStatus _statusFromJson(String? v) {
  switch (v) {
    case 'revoked':
      return AccountStatus.revoked;
    default:
      return AccountStatus.active;
  }
}

class AccountInfo {
  AccountInfo({
    required this.numberMasked,
    required this.status,
    required this.expiresAt,
    required this.deviceCount,
    required this.deviceLimit,
    required this.token,
    required this.tokenIssuedAt,
    this.shortIdHex = '',
  });

  factory AccountInfo.fromJson(Map<String, dynamic> json) => AccountInfo(
    numberMasked: json['numberMasked'] as String,
    status: AccountStatus.values.firstWhere(
      (s) => s.name == json['status'],
      orElse: () => AccountStatus.active,
    ),
    expiresAt: DateTime.parse(json['expiresAt'] as String),
    deviceCount: json['deviceCount'] as int? ?? 1,
    deviceLimit: json['deviceLimit'] as int? ?? 5,
    token: json['token'] as String? ?? '',
    tokenIssuedAt: DateTime.parse(json['tokenIssuedAt'] as String),
    shortIdHex: json['shortIdHex'] as String? ?? '',
  );

  final String numberMasked;
  final AccountStatus status;
  final DateTime expiresAt;
  final int deviceCount;
  final int deviceLimit;

  final String token;
  final DateTime tokenIssuedAt;

  final String shortIdHex;

  bool get tokenExpired =>
      DateTime.now().difference(tokenIssuedAt) > const Duration(hours: 24);

  AccountInfo copyWith({
    AccountStatus? status,
    DateTime? expiresAt,
    int? deviceCount,
    int? deviceLimit,
    String? token,
    DateTime? tokenIssuedAt,
    String? shortIdHex,
  }) => AccountInfo(
    numberMasked: numberMasked,
    status: status ?? this.status,
    expiresAt: expiresAt ?? this.expiresAt,
    deviceCount: deviceCount ?? this.deviceCount,
    deviceLimit: deviceLimit ?? this.deviceLimit,
    token: token ?? this.token,
    tokenIssuedAt: tokenIssuedAt ?? this.tokenIssuedAt,
    shortIdHex: shortIdHex ?? this.shortIdHex,
  );

  Map<String, dynamic> toJson() => {
    'numberMasked': numberMasked,
    'status': status.name,
    'expiresAt': expiresAt.toIso8601String(),
    'deviceCount': deviceCount,
    'deviceLimit': deviceLimit,
    'token': token,
    'tokenIssuedAt': tokenIssuedAt.toIso8601String(),
    'shortIdHex': shortIdHex,
  };
}

class RedeemResult {
  RedeemResult.ok(this.account) : error = null;
  RedeemResult.fail(this.error) : account = null;

  final AccountInfo? account;
  final String? error;
  bool get ok => account != null;
}

const kDefaultControlPlaneMirrors = ['http://185.100.157.232:8443'];

bool mirrorIsInsecure(String mirror) => !mirror.startsWith('https://');

class AccountStore {
  AccountStore({List<String>? mirrors})
    : mirrors = mirrors ?? List.of(kDefaultControlPlaneMirrors);

  final List<String> mirrors;
  File? _file;
  final http.Client _client = _buildPinnedClient();

  bool get usesInsecureTransport => mirrors.any(mirrorIsInsecure);

  http.Client get client => _client;

  void dispose() => _client.close();

  Future<File> _path() async {
    if (_file != null) return _file!;
    final dir = await getApplicationSupportDirectory();
    _file = File('${dir.path}/chimera_account.json');
    return _file!;
  }

  Future<AccountInfo?> load() async {
    final f = await _path();
    if (!await f.exists()) return null;
    try {
      final json = jsonDecode(await f.readAsString()) as Map<String, dynamic>;
      final token = await _kSecureStorage.read(key: _kTokenKey) ?? '';
      return AccountInfo.fromJson(json).copyWith(token: token);
    } catch (_) {
      return null;
    }
  }

  Future<void> _save(AccountInfo info) async {
    final f = await _path();
    final json = info.toJson()..remove('token');
    await f.writeAsString(jsonEncode(json));
    await _kSecureStorage.write(key: _kTokenKey, value: info.token);
  }

  Future<bool> hasValidToken() async {
    final info = await load();
    return info != null &&
        info.status == AccountStatus.active &&
        !info.tokenExpired &&
        info.expiresAt.isAfter(DateTime.now());
  }

  Future<http.Response> _postAnyMirror(
    String path,
    Map<String, dynamic> body,
  ) async {
    Object? lastError;
    for (final base in mirrors) {
      try {
        return await _client
            .post(
              Uri.parse('$base$path'),
              headers: {'Content-Type': 'application/json'},
              body: jsonEncode(body),
            )
            .timeout(const Duration(seconds: 10));
      } catch (e) {
        lastError = e;
        continue;
      }
    }
    throw lastError ?? Exception('no control-plane mirrors configured');
  }

  Future<http.Response> _getAnyMirror(String path, String bearerToken) async {
    Object? lastError;
    for (final base in mirrors) {
      try {
        return await _client
            .get(
              Uri.parse('$base$path'),
              headers: {'Authorization': 'Bearer $bearerToken'},
            )
            .timeout(const Duration(seconds: 10));
      } catch (e) {
        lastError = e;
        continue;
      }
    }
    throw lastError ?? Exception('no control-plane mirrors configured');
  }

  Future<RedeemResult> redeem(String rawNumber) async {
    final normalized = normalizeAccountNumber(rawNumber);
    if (!isValidAccountNumber(normalized)) {
      return RedeemResult.fail(
        'Invalid key. Expected 16 characters, groups of 4 (e.g. 7K2M-9PQR-4TZS-XW3H).',
      );
    }

    final devicePubKey = await _devicePubKey();
    http.Response resp;
    try {
      resp = await _postAnyMirror('/v1/session/redeem', {
        'account_number': normalized,
        'device_pubkey': devicePubKey,
      });
    } catch (e) {
      return RedeemResult.fail('Could not reach the account service: $e');
    }

    final decoded = jsonDecode(resp.body) as Map<String, dynamic>;
    if (resp.statusCode != 200) {
      return RedeemResult.fail(decoded['error'] as String? ?? 'redeem failed');
    }
    final token = decoded['token'] as String;
    final shortIdHex = decoded['short_id_hex'] as String? ?? '';

    final masked =
        '•••• •••• •••• ${normalized.substring(normalized.length - 4)}';
    var info = AccountInfo(
      numberMasked: masked,
      status: AccountStatus.active,
      expiresAt: DateTime.now().add(const Duration(days: 365)),
      deviceCount: 1,
      deviceLimit: 5,
      token: token,
      tokenIssuedAt: DateTime.now(),
      shortIdHex: shortIdHex,
    );
    info = await _refreshAccountInfo(info) ?? info;
    await _save(info);
    return RedeemResult.ok(info);
  }

  Future<AccountInfo?> _refreshAccountInfo(AccountInfo info) async {
    try {
      final resp = await _getAnyMirror('/v1/account', info.token);
      if (resp.statusCode != 200) return null;
      final decoded = jsonDecode(resp.body) as Map<String, dynamic>;
      return info.copyWith(
        status: _statusFromJson(decoded['status'] as String?),
        expiresAt: DateTime.fromMillisecondsSinceEpoch(
          (decoded['expires_at'] as int) * 1000,
        ),
        deviceCount: decoded['device_count'] as int?,
        deviceLimit: decoded['device_limit'] as int?,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> refresh() async {
    final info = await load();
    if (info == null) return;
    http.Response resp;
    try {
      resp = await _postAnyMirror('/v1/session/refresh', {'token': info.token});
    } catch (_) {
      return;
    }
    if (resp.statusCode != 200) return;
    final decoded = jsonDecode(resp.body) as Map<String, dynamic>;
    var refreshed = info.copyWith(
      token: decoded['token'] as String,
      tokenIssuedAt: DateTime.now(),
      shortIdHex: decoded['short_id_hex'] as String? ?? info.shortIdHex,
    );
    refreshed = await _refreshAccountInfo(refreshed) ?? refreshed;
    await _save(refreshed);
  }

  Future<void> logout() async {
    final f = await _path();
    if (await f.exists()) await f.delete();
    await _kSecureStorage.delete(key: _kTokenKey);
  }

  Future<String> _devicePubKey() async {
    final dir = await getApplicationSupportDirectory();
    final f = File('${dir.path}/chimera_device_key');
    if (await f.exists()) {
      final existing = (await f.readAsString()).trim();
      if (existing.isNotEmpty) return existing;
    }

    await dir.create(recursive: true);
    final bytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    final encoded = base64Encode(bytes);
    await f.writeAsString(encoded, flush: true);
    return encoded;
  }
}
