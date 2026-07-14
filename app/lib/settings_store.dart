// Local JSON settings persistence for the tray app: saved servers, the
// assembled subscription text, the SOCKS listen address and misc toggles.
// Replaces the old single "paste one link into a text file" persistence with
// a small structured document so multi-server / per-server-fingerprint UI
// (Phase B/C) has somewhere to live.
import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

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
  });

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
/// `chimera tun -setup-os ...` helper (see `network_protection.dart`):
///  - [off]: no elevated helper, TUN-less SOCKS5 only.
///  - [dnsLeakGuard]: blocks outbound DNS (UDP/TCP 53) on non-tunnel
///    interfaces only (`internal/winnet` `Firewall`).
///  - [killswitch]: blocks ALL outbound traffic except the TUN device,
///    loopback, and the resolved server endpoints (`internal/winnet`
///    `Killswitch`) -- DNS is covered as a side effect of the full block.
enum NetworkProtectionMode { off, dnsLeakGuard, killswitch }

NetworkProtectionMode _networkProtectionModeFromJson(String? v) {
  switch (v) {
    case 'killswitch':
      return NetworkProtectionMode.killswitch;
    case 'dnsLeakGuard':
      return NetworkProtectionMode.dnsLeakGuard;
    default:
      return NetworkProtectionMode.off;
  }
}

String _networkProtectionModeToJson(NetworkProtectionMode m) {
  switch (m) {
    case NetworkProtectionMode.killswitch:
      return 'killswitch';
    case NetworkProtectionMode.dnsLeakGuard:
      return 'dnsLeakGuard';
    case NetworkProtectionMode.off:
      return 'off';
  }
}

const kDefaultCustomDns = ['1.1.1.1', '8.8.8.8'];

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
    this.listenAddr = '127.0.0.1:1080',
    this.autostart = false,
    this.networkProtection = NetworkProtectionMode.off,
    List<String>? customDns,
    this.lastConnectedServerId,
    SplitTunnelSettings? splitTunnel,
  }) : servers = servers ?? [],
       customDns = customDns ?? List.of(kDefaultCustomDns),
       splitTunnel = splitTunnel ?? SplitTunnelSettings();

  factory ChimeraSettings.fromJson(Map<String, dynamic> json) {
    final rawServers = json['servers'] as List<dynamic>? ?? const [];
    final rawSplitTunnel = json['splitTunnel'] as Map<String, dynamic>?;
    final rawDns = json['customDns'] as List<dynamic>?;
    return ChimeraSettings(
      servers: rawServers
          .map((e) => ServerEntry.fromJson(e as Map<String, dynamic>))
          .toList(),
      signKeyHex: json['signKeyHex'] as String? ?? '',
      listenAddr: json['listenAddr'] as String? ?? '127.0.0.1:1080',
      autostart: json['autostart'] as bool? ?? false,
      networkProtection: _networkProtectionModeFromJson(
        json['networkProtection'] as String?,
      ),
      customDns: rawDns?.map((e) => e as String).toList(),
      lastConnectedServerId: json['lastConnectedServerId'] as String?,
      splitTunnel: rawSplitTunnel == null
          ? null
          : SplitTunnelSettings.fromJson(rawSplitTunnel),
    );
  }

  final List<ServerEntry> servers;
  String signKeyHex;
  String listenAddr;
  bool autostart;
  NetworkProtectionMode networkProtection;
  List<String> customDns;
  String? lastConnectedServerId;
  SplitTunnelSettings splitTunnel;

  Map<String, dynamic> toJson() => {
    'servers': servers.map((s) => s.toJson()).toList(),
    'signKeyHex': signKeyHex,
    'listenAddr': listenAddr,
    'autostart': autostart,
    'networkProtection': _networkProtectionModeToJson(networkProtection),
    'customDns': customDns,
    'lastConnectedServerId': lastConnectedServerId,
    'splitTunnel': splitTunnel.toJson(),
  };

  /// subscriptionText assembles all saved servers into one
  /// `#!chimera-subscription-v1` document (one `chimera://` link per line,
  /// in list order) -- the format `internal/api.NewSessionFromSubscription`
  /// parses server-side. A single server is a valid one-line subscription.
  String subscriptionText() {
    final buf = StringBuffer('#!chimera-subscription-v1\n');
    for (final s in servers) {
      buf.writeln(s.link);
    }
    return buf.toString();
  }
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
