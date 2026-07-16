// Local persistence + control-plane client for the account-key gate
// (ROADMAP2 §1/§4). Talks to the real `cmd/chimera-control` HTTP API
// (POST /v1/session/redeem, /v1/session/refresh, GET /v1/account) --
// this used to be a client-side mock before the Go control-plane existed;
// now it's the real thing, with the same mirror-list fallback shape
// ROADMAP2 §0.1 п.5 calls for (try each configured address in turn until
// one answers).
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;
import 'package:path_provider/path_provider.dart';

/// Crockford base32 (no 0/O/1/I), matching ROADMAP2 §1 and the Go side's
/// internal/controlplane.keyAlphabet exactly -- the two must agree
/// byte-for-byte or a key valid on one side would be rejected by the other.
const _kAlphabet = '23456789ABCDEFGHJKMNPQRSTVWXYZ';
final _kGroupPattern = '[$_kAlphabet]{4}';
final _kKeyPattern = RegExp('^$_kGroupPattern-$_kGroupPattern-$_kGroupPattern-$_kGroupPattern\$');

/// Normalizes pasted/typed input into the canonical `XXXX-XXXX-XXXX-XXXX`
/// grouping -- strips whitespace/hyphens, uppercases, then re-groups so a
/// key pasted without hyphens still validates.
String normalizeAccountNumber(String raw) {
  final stripped = raw
      .toUpperCase()
      .replaceAll(RegExp(r'[\s-]'), '');
  final groups = <String>[];
  for (var i = 0; i < stripped.length; i += 4) {
    groups.add(stripped.substring(i, min(i + 4, stripped.length)));
  }
  return groups.join('-');
}

bool isValidAccountNumber(String normalized) => _kKeyPattern.hasMatch(normalized);

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

  /// The signed capability token (ROADMAP2 §1) presented to data-plane
  /// servers running -auth-mode controlplane -- threaded into
  /// carrier.Config.Token via ServerEntry once catalog_page.dart connects
  /// through a curated server instead of a BYO link.
  final String token;
  final DateTime tokenIssuedAt;

  /// This device's control-plane short ID (hex), returned alongside the
  /// token by /v1/session/redeem and /v1/session/refresh. A -auth-mode
  /// controlplane server matches the token's embedded short ID against the
  /// short ID recovered from the *connecting client's own ClientHello*
  /// (internal/server/server.go's checkToken) -- so this is what
  /// PrimaryServer.sid must carry when dialing through a catalog server,
  /// not any value from the server's own chimera:// link (catalog links
  /// carry no sid= at all; that field only makes sense per-device, not
  /// per-server). See main.dart's _connect/_setNetworkProtection.
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

/// Control-plane entry points to try in order (ROADMAP2 §0.1 п.5): the
/// primary address first, then mirrors, so a blocked primary domain
/// doesn't strand someone who can't even redeem a key. Overridable per
/// build/deployment. Points at the deployed chimera-control instance
/// (185.100.157.232:8443, plain HTTP -- no TLS until it sits behind a
/// domain); swap back to http://127.0.0.1:8443 for local
/// `chimera-control serve` development.
const kDefaultControlPlaneMirrors = ['http://185.100.157.232:8443'];

/// AccountStore loads/saves `chimera_account.json` under the platform's
/// application-support directory -- same convention as [SettingsStore] --
/// and is the HTTP client for the control-plane API.
class AccountStore {
  AccountStore({List<String>? mirrors})
    : mirrors = mirrors ?? List.of(kDefaultControlPlaneMirrors);

  final List<String> mirrors;
  File? _file;

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
      return AccountInfo.fromJson(
        jsonDecode(await f.readAsString()) as Map<String, dynamic>,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> _save(AccountInfo info) async {
    final f = await _path();
    await f.writeAsString(jsonEncode(info.toJson()));
  }

  Future<bool> hasValidToken() async {
    final info = await load();
    return info != null &&
        info.status == AccountStatus.active &&
        !info.tokenExpired &&
        info.expiresAt.isAfter(DateTime.now());
  }

  /// POSTs body to path on each configured mirror in turn, returning the
  /// first response that isn't a connection failure -- the client-side
  /// half of ROADMAP2 §0.1 п.5's blocked-primary-domain resilience.
  Future<http.Response> _postAnyMirror(String path, Map<String, dynamic> body) async {
    Object? lastError;
    for (final base in mirrors) {
      try {
        return await http
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
        return await http
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

  /// Redeems an account key against `POST /v1/session/redeem`, then fetches
  /// account-level display fields from `GET /v1/account` using the freshly
  /// issued token. Device identity is a fresh random key generated once per
  /// install and reused across redeem/refresh -- persisted as part of the
  /// saved account so a re-redeem (e.g. after logout+login on the same
  /// device) is idempotent server-side (see internal/controlplane.Redeem).
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

    final masked = '•••• •••• •••• ${normalized.substring(normalized.length - 4)}';
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

  /// Calls `GET /v1/account` to fill in status/expiry/device counts the
  /// redeem/refresh response itself doesn't carry -- best-effort: on
  /// failure (e.g. control-plane briefly unreachable) the caller falls
  /// back to whatever was already known, since a stale display is far
  /// better than blocking the whole redeem/refresh flow on this call.
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

  /// Calls `POST /v1/session/refresh` to extend the token's TTL, then
  /// re-fetches account info. Called from a background timer (see
  /// main.dart) well before the current token's 24h TTL runs out, so the
  /// VPN keeps working across control-plane hiccups between refreshes
  /// (ROADMAP2 §1.2).
  Future<void> refresh() async {
    final info = await load();
    if (info == null) return;
    http.Response resp;
    try {
      resp = await _postAnyMirror('/v1/session/refresh', {'token': info.token});
    } catch (_) {
      return; // offline: keep the existing (still possibly-valid) token
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
  }

  /// A stable per-install device identifier. Not a cryptographic key pair
  /// (ROADMAP2 §1 leaves the device_pubkey's exact scheme open) -- a random
  /// 32-byte value generated once and persisted is sufficient for the
  /// device_limit bookkeeping /v1/session/redeem needs, without depending
  /// on the app's chimera_bindings FFI just to size an account key.
  Future<String> _devicePubKey() async {
    final dir = await getApplicationSupportDirectory();
    final f = File('${dir.path}/chimera_device_key');
    if (await f.exists()) {
      return (await f.readAsString()).trim();
    }
    final bytes = List<int>.generate(32, (_) => Random.secure().nextInt(256));
    final encoded = base64Encode(bytes);
    await f.writeAsString(encoded);
    return encoded;
  }
}
