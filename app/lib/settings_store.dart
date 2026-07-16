// Local JSON settings persistence for the tray app: saved servers, the
// assembled subscription text, the SOCKS listen address and misc toggles.
// Replaces the old single "paste one link into a text file" persistence with
// a small structured document so multi-server / per-server-fingerprint UI
// (Phase B/C) has somewhere to live.
import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'catalog_page.dart' show CatalogListener;

/// ServerEntry is one saved endpoint: an operator-facing [label] plus the
/// underlying `chimera://` link exactly as produced by [link.Build] /
/// entered by the user.
///
/// The `admin*` fields are optional and only present for a server you deployed
/// yourself and want to invite other people to: they let the app open an SSH
/// tunnel to that server's loopback-only users-admin API (see
/// internal/admin + internal/useracl) to add/revoke sids and hand out fresh
/// chimera:// links without touching a terminal. A server added via a plain
/// pasted link never has these set and just works as before.
///
/// Caveat: like [ChimeraSettings.signKeyHex] already stored here, these are
/// persisted in plain JSON on disk, not OS keychain/secure storage -- treat
/// this file as sensitive.
class ServerEntry {
  ServerEntry({
    required this.id,
    required this.label,
    required this.link,
    this.adminSshHost,
    this.adminSshPort = 22,
    this.adminSshUser,
    this.adminSshPassword,
    this.adminApiPort = 8901,
    this.adminToken,
    List<CatalogListener>? catalogListeners,
  }) : catalogListeners = catalogListeners ?? const [];

  factory ServerEntry.fromJson(Map<String, dynamic> json) => ServerEntry(
    id: json['id'] as String,
    label: json['label'] as String? ?? '',
    link: json['link'] as String? ?? '',
    adminSshHost: json['adminSshHost'] as String?,
    adminSshPort: json['adminSshPort'] as int? ?? 22,
    adminSshUser: json['adminSshUser'] as String?,
    adminSshPassword: json['adminSshPassword'] as String?,
    adminApiPort: json['adminApiPort'] as int? ?? 8901,
    adminToken: json['adminToken'] as String?,
    catalogListeners: (json['catalogListeners'] as List<dynamic>? ?? const [])
        .map((e) => CatalogListener.fromJson(e as Map<String, dynamic>))
        .toList(),
  );

  final String id;
  String label;
  String link;
  String? adminSshHost;
  int adminSshPort;
  String? adminSshUser;
  String? adminSshPassword;
  int adminApiPort;
  String? adminToken;

  /// Every transport listener the catalog reported for this server at the
  /// time it was picked/last mode-switched (ROADMAP2 §3/§4 multi-transport
  /// support) -- empty for BYO/legacy entries, which only ever have the one
  /// transport baked into their link. Lets
  /// [ChimeraSettings.applyObfuscationModeToCatalogServers] rewrite both the
  /// `mode=` param *and* the actual host:port when the global Anti-
  /// censorship setting changes, since different transports can live on
  /// different ports on the same physical server.
  List<CatalogListener> catalogListeners;

  /// hasAdmin reports whether enough is configured to attempt opening the
  /// users-admin tunnel for this server.
  bool get hasAdmin =>
      (adminSshHost?.isNotEmpty ?? false) &&
      (adminSshUser?.isNotEmpty ?? false) &&
      (adminToken?.isNotEmpty ?? false);

  Map<String, dynamic> toJson() => {
    'id': id,
    'label': label,
    'link': link,
    'adminSshHost': adminSshHost,
    'adminSshPort': adminSshPort,
    'adminSshUser': adminSshUser,
    'adminSshPassword': adminSshPassword,
    'adminApiPort': adminApiPort,
    'adminToken': adminToken,
    'catalogListeners': catalogListeners
        .map((l) => {'transport': l.transport, 'port': l.port})
        .toList(),
  };
}

/// One app in the split-tunnel picker: [id] is the stable key persisted in
/// `apps` (on Windows, the shortcut/AppID `Get-StartApps` reports -- not a
/// filesystem path, which can move on update); [name] is display-only.
class SplitTunnelApp {
  SplitTunnelApp({required this.id, required this.name});

  factory SplitTunnelApp.fromJson(Map<String, dynamic> json) =>
      SplitTunnelApp(
        id: json['id'] as String,
        name: json['name'] as String? ?? '',
      );

  final String id;
  final String name;

  Map<String, dynamic> toJson() => {'id': id, 'name': name};
}

enum SplitTunnelMode { include, exclude }

/// Tiered OS-level network protection, applied through the elevated
/// `chimera tun -setup-os ...` helper (see `network_protection.dart`).
/// The tray app is TUN-only (no SOCKS5 fallback), so [dnsLeakGuard] is the
/// floor -- there's no "off" tier anymore, since with no SOCKS path a
/// disabled TUN device would mean no connection at all:
///  - [dnsLeakGuard]: blocks outbound DNS (UDP/TCP 53) on non-tunnel
///    interfaces only (`internal/winnet` `Firewall`).
///  - [killswitch]: blocks ALL outbound traffic except the TUN device,
///    loopback, and the resolved server endpoints (`internal/winnet`
///    `Killswitch`) -- DNS is covered as a side effect of the full block.
enum NetworkProtectionMode { dnsLeakGuard, killswitch }

NetworkProtectionMode _networkProtectionModeFromJson(String? v) {
  switch (v) {
    case 'killswitch':
      return NetworkProtectionMode.killswitch;
    // Absent key, 'dnsLeakGuard', or a stored 'off' from a settings file
    // saved before SOCKS5 was removed all migrate to the same floor tier --
    // 'off' has no meaning anymore now that TUN is the only connect path.
    default:
      return NetworkProtectionMode.dnsLeakGuard;
  }
}

String _networkProtectionModeToJson(NetworkProtectionMode m) {
  switch (m) {
    case NetworkProtectionMode.killswitch:
      return 'killswitch';
    case NetworkProtectionMode.dnsLeakGuard:
      return 'dnsLeakGuard';
  }
}

const kDefaultCustomDns = ['1.1.1.1', '8.8.8.8'];

/// The 4 anti-censorship transports offered on `anticensorship_page.dart`
/// (ROADMAP2 §3). This is the *global default* picker -- it replaces the old
/// per-server "transport-mode" field as the primary UI, though that
/// per-server field still wins if a saved `ServerEntry` sets one explicitly.
enum ObfuscationMode { reality, quicH3, shadowsocksAead, dnsOverTcp }

ObfuscationMode _obfuscationModeFromJson(String? v) {
  switch (v) {
    case 'quicH3':
      return ObfuscationMode.quicH3;
    case 'shadowsocksAead':
      return ObfuscationMode.shadowsocksAead;
    case 'dnsOverTcp':
      return ObfuscationMode.dnsOverTcp;
    default:
      return ObfuscationMode.reality;
  }
}

String _obfuscationModeToJson(ObfuscationMode m) {
  switch (m) {
    case ObfuscationMode.reality:
      return 'reality';
    case ObfuscationMode.quicH3:
      return 'quicH3';
    case ObfuscationMode.shadowsocksAead:
      return 'shadowsocksAead';
    case ObfuscationMode.dnsOverTcp:
      return 'dnsOverTcp';
  }
}

/// The `mode=` query-param value a catalog-built `chimera://` link needs for
/// [mode] -- what `internal/subscription.Parse` reads into `carrier.Config
/// .Transport` server-side (empty/absent means "auto", which picks Reality
/// over plain TCP; see subscription.go). Shared by `_upsertCuratedServer`
/// (bakes this in when a server is first picked) and
/// [ChimeraSettings.applyObfuscationModeToCatalogServers] (rewrites it when
/// the mode changes afterwards) so the two can never drift out of sync.
String obfuscationModeQueryParam(ObfuscationMode m) {
  switch (m) {
    case ObfuscationMode.reality:
      return '';
    case ObfuscationMode.quicH3:
      return 'quic';
    case ObfuscationMode.shadowsocksAead:
      return 'ss';
    case ObfuscationMode.dnsOverTcp:
      return 'dot';
  }
}

/// Persisted split-tunnel selection (docs/app/platform-features.md §2).
/// This is the picker's state only -- on the desktop tray (TUN-less SOCKS5,
/// see `main.dart` header comment) there is no OS-level enforcement yet, so
/// toggling `enabled` here does not itself change what's actually tunneled
/// until the elevated-helper per-app routing (Phase 3, ROADMAP §4) lands.
class SplitTunnelSettings {
  SplitTunnelSettings({
    this.enabled = false,
    this.mode = SplitTunnelMode.exclude,
    List<SplitTunnelApp>? apps,
    this.template,
  }) : apps = apps ?? [];

  factory SplitTunnelSettings.fromJson(Map<String, dynamic> json) {
    final rawApps = json['apps'] as List<dynamic>? ?? const [];
    return SplitTunnelSettings(
      enabled: json['enabled'] as bool? ?? false,
      mode: (json['mode'] as String? ?? 'exclude') == 'include'
          ? SplitTunnelMode.include
          : SplitTunnelMode.exclude,
      apps: rawApps
          .map((e) => SplitTunnelApp.fromJson(e as Map<String, dynamic>))
          .toList(),
      template: json['template'] as String?,
    );
  }

  bool enabled;
  SplitTunnelMode mode;
  final List<SplitTunnelApp> apps;
  String? template;

  Map<String, dynamic> toJson() => {
    'enabled': enabled,
    'mode': mode == SplitTunnelMode.include ? 'include' : 'exclude',
    'apps': apps.map((a) => a.toJson()).toList(),
    'template': template,
  };
}

class ChimeraSettings {
  ChimeraSettings({
    List<ServerEntry>? servers,
    this.signKeyHex = '',
    this.autostart = false,
    this.networkProtection = NetworkProtectionMode.dnsLeakGuard,
    List<String>? customDns,
    this.lastConnectedServerId,
    SplitTunnelSettings? splitTunnel,
    this.nethelperDeclined = false,
    this.obfuscationMode = ObfuscationMode.reality,
    List<String>? favoriteServerIds,
  }) : servers = servers ?? [],
       customDns = customDns ?? List.of(kDefaultCustomDns),
       splitTunnel = splitTunnel ?? SplitTunnelSettings(),
       favoriteServerIds = favoriteServerIds ?? [];

  factory ChimeraSettings.fromJson(Map<String, dynamic> json) {
    final rawServers = json['servers'] as List<dynamic>? ?? const [];
    final rawSplitTunnel = json['splitTunnel'] as Map<String, dynamic>?;
    final rawDns = json['customDns'] as List<dynamic>?;
    final rawFavorites = json['favoriteServerIds'] as List<dynamic>?;
    return ChimeraSettings(
      servers: rawServers
          .map((e) => ServerEntry.fromJson(e as Map<String, dynamic>))
          .toList(),
      signKeyHex: json['signKeyHex'] as String? ?? '',
      autostart: json['autostart'] as bool? ?? false,
      networkProtection: _networkProtectionModeFromJson(
        json['networkProtection'] as String?,
      ),
      customDns: rawDns?.map((e) => e as String).toList(),
      lastConnectedServerId: json['lastConnectedServerId'] as String?,
      splitTunnel: rawSplitTunnel == null
          ? null
          : SplitTunnelSettings.fromJson(rawSplitTunnel),
      nethelperDeclined: json['nethelperDeclined'] as bool? ?? false,
      obfuscationMode: _obfuscationModeFromJson(
        json['obfuscationMode'] as String?,
      ),
      favoriteServerIds: rawFavorites?.map((e) => e as String).toList(),
    );
  }

  final List<ServerEntry> servers;
  String signKeyHex;
  bool autostart;
  NetworkProtectionMode networkProtection;
  List<String> customDns;
  String? lastConnectedServerId;
  SplitTunnelSettings splitTunnel;
  ObfuscationMode obfuscationMode;

  /// IDs (`CatalogServer.id`) starred on `catalog_page.dart`. Catalog-scoped,
  /// not tied to any one saved BYO server.
  final List<String> favoriteServerIds;

  /// Set once the user dismisses the "enable full VPN protection" onboarding
  /// prompt (see main.dart's _connect) without installing chimera-helper, so
  /// Connect stops asking every time -- they can still turn it on later from
  /// Settings, which always offers the install regardless of this flag.
  bool nethelperDeclined;

  Map<String, dynamic> toJson() => {
    'servers': servers.map((s) => s.toJson()).toList(),
    'signKeyHex': signKeyHex,
    'autostart': autostart,
    'networkProtection': _networkProtectionModeToJson(networkProtection),
    'customDns': customDns,
    'lastConnectedServerId': lastConnectedServerId,
    'splitTunnel': splitTunnel.toJson(),
    'nethelperDeclined': nethelperDeclined,
    'obfuscationMode': _obfuscationModeToJson(obfuscationMode),
    'favoriteServerIds': favoriteServerIds,
  };

  /// subscriptionText assembles all saved servers into one
  /// `#!chimera-subscription-v1` document (one `chimera://` link per line,
  /// in list order) -- the format `internal/api.NewSessionFromSubscription`
  /// parses server-side. A single server is a valid one-line subscription.
  ///
  /// Catalog-picked entries (see `_upsertCuratedServer`) are saved without a
  /// `tok=` or `sid=` param on purpose: `sid=` is per-device/per-account (a
  /// catalog link describes a server, not a device -- see
  /// AccountInfo.shortIdHex's doc comment), and `tok=` would go stale before
  /// the token refreshes on its own ~24h TTL. So [token] and [shortIdHex] --
  /// live values read from AccountStore at connect time, same as
  /// `main.dart`'s `_effectiveSid` does for the real engage call -- are
  /// stitched onto those links here. Without *both*, the reachability check
  /// this text feeds (`chimeramobile.Tunnel.Connect` / `api.Session.Connect`)
  /// either sends no token, or embeds the wrong (empty) short ID into the
  /// Reality handshake (see `carrier.transport_reality.go`'s ClientWrap) --
  /// either way a -auth-mode controlplane server's checkToken can't verify
  /// it and closes the connection, surfacing as "unexpected EOF" on every
  /// endpoint.
  String subscriptionText({String? token, String? shortIdHex}) {
    final buf = StringBuffer('#!chimera-subscription-v1\n');
    for (final s in servers) {
      buf.writeln(_linkWithAccountParams(s, token, shortIdHex));
    }
    return buf.toString();
  }

  String _linkWithAccountParams(ServerEntry s, String? token, String? shortIdHex) {
    if (!s.id.startsWith('catalog-')) return s.link;
    final uri = Uri.parse(s.link);
    final params = Map<String, String>.from(uri.queryParameters);
    var changed = false;
    if ((token ?? '').isNotEmpty && (params['tok'] ?? '').isEmpty) {
      params['tok'] = token!;
      changed = true;
    }
    if ((shortIdHex ?? '').isNotEmpty && (params['sid'] ?? '').isEmpty) {
      params['sid'] = shortIdHex!;
      changed = true;
    }
    if (!changed) return s.link;
    return uri.replace(queryParameters: params).toString();
  }

  /// Rewrites the `mode=` param -- and, when the server's catalog listeners
  /// are known, the actual host **port** too -- on every already-saved
  /// catalog server link to match [mode]. Keeps them in sync with a later
  /// Anti-censorship change.
  ///
  /// `_upsertCuratedServer` only bakes the obfuscation mode into a server's
  /// link once, at the moment it's picked in the catalog. Without this,
  /// changing the global Anti-censorship setting afterwards updates
  /// [obfuscationMode] but never touches the already-saved link, so
  /// `_resolvePrimaryServer` (which parses that link's `mode=`/port at
  /// connect time) keeps dialing with whatever transport was selected when
  /// the server was first chosen -- the switch silently has no effect on
  /// the next Connect. BYO/legacy (non-catalog) server links are left
  /// alone: their `mode=`, if any, is an explicit per-server choice, not
  /// the global default.
  ///
  /// A server's different transports can each listen on a *different port*
  /// on the same physical box (ROADMAP2 §3/§4 multi-transport support --
  /// see `ServerEntry.catalogListeners`/`CatalogListener`), so rewriting
  /// `mode=` alone isn't enough once more than one transport is offered:
  /// the port has to move too, or the client dials the right protocol on
  /// the wrong port and gets silence/EOF exactly like before this field
  /// existed. If a server's recorded listeners don't include [mode] at all
  /// (it simply isn't deployed there), that entry is left completely
  /// unchanged rather than pointed at a port that can't work -- "no false
  /// promises" applies to what actually gets dialed, not just to the UI
  /// copy on anticensorship_page.dart.
  void applyObfuscationModeToCatalogServers(ObfuscationMode mode) {
    final modeParam = obfuscationModeQueryParam(mode);
    for (final s in servers) {
      if (!s.id.startsWith('catalog-')) continue;
      final uri = Uri.tryParse(s.link);
      if (uri == null) continue;

      int? newPort;
      if (s.catalogListeners.isNotEmpty) {
        newPort = _listenerPort(s.catalogListeners, modeParam);
        if (newPort == null) continue;
      }

      final params = Map<String, String>.from(uri.queryParameters);
      if (modeParam.isEmpty) {
        params.remove('mode');
      } else {
        params['mode'] = modeParam;
      }
      s.link = (newPort == null
              ? uri.replace(queryParameters: params)
              : uri.replace(port: newPort, queryParameters: params))
          .toString();
    }
  }
}

/// The port [listeners] offers for [transportParam] (an
/// `obfuscationModeQueryParam` value), or null if there's no listener for
/// it at all. Mirrors `CatalogServer.portFor` in catalog_page.dart, kept as
/// a free function here so `ChimeraSettings` doesn't need a `CatalogServer`
/// (only its already-extracted `CatalogListener`s survive into
/// `ServerEntry`).
int? _listenerPort(List<CatalogListener> listeners, String transportParam) {
  final wanted = transportParam.isEmpty ? 'reality' : transportParam;
  for (final l in listeners) {
    if (l.transport == wanted) return l.port;
  }
  return null;
}

/// SettingsStore loads/saves [ChimeraSettings] as
/// `chimera_settings.json` under the platform's application-support
/// directory.
class SettingsStore {
  File? _file;

  Future<File> _path() async {
    if (_file != null) return _file!;
    final dir = await getApplicationSupportDirectory();
    _file = File('${dir.path}/chimera_settings.json');
    return _file!;
  }

  Future<ChimeraSettings> load() async {
    final f = await _path();
    if (!await f.exists()) {
      return ChimeraSettings();
    }
    try {
      final decoded =
          jsonDecode(await f.readAsString()) as Map<String, dynamic>;
      return ChimeraSettings.fromJson(decoded);
    } catch (_) {
      // Corrupt/unreadable settings file: start fresh rather than crash the
      // tray app on launch.
      return ChimeraSettings();
    }
  }

  Future<void> save(ChimeraSettings settings) async {
    final f = await _path();
    await f.writeAsString(jsonEncode(settings.toJson()));
  }
}
