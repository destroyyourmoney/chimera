import 'dart:convert';
import 'dart:io';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

import 'catalog_page.dart' show CatalogListener;

const _kSecureStorage = FlutterSecureStorage();
const _kSignKeyStorageKey = 'chimera_sign_key_hex';
String _adminSshPasswordKey(String serverId) =>
    'chimera_admin_ssh_password_$serverId';
String _adminTokenKey(String serverId) => 'chimera_admin_token_$serverId';

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

  List<CatalogListener> catalogListeners;

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

class SplitTunnelApp {
  SplitTunnelApp({required this.id, required this.name});

  factory SplitTunnelApp.fromJson(Map<String, dynamic> json) => SplitTunnelApp(
    id: json['id'] as String,
    name: json['name'] as String? ?? '',
  );

  final String id;
  final String name;

  Map<String, dynamic> toJson() => {'id': id, 'name': name};
}

enum SplitTunnelMode { include, exclude }

enum NetworkProtectionMode { dnsLeakGuard, killswitch }

NetworkProtectionMode _networkProtectionModeFromJson(String? v) {
  switch (v) {
    case 'killswitch':
      return NetworkProtectionMode.killswitch;

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
    this.networkProtection = NetworkProtectionMode.killswitch,
    List<String>? customDns,
    this.lastConnectedServerId,
    SplitTunnelSettings? splitTunnel,
    this.nethelperDeclined = false,
    this.obfuscationMode = ObfuscationMode.reality,
    List<String>? favoriteServerIds,
    this.minimizeToTray = true,
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
      minimizeToTray: json['minimizeToTray'] as bool? ?? true,
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

  bool minimizeToTray;

  final List<String> favoriteServerIds;

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
    'minimizeToTray': minimizeToTray,
  };

  String subscriptionText({String? token, String? shortIdHex}) {
    final buf = StringBuffer('#!chimera-subscription-v1\n');
    for (final s in servers) {
      buf.writeln(_linkWithAccountParams(s, token, shortIdHex));
    }
    return buf.toString();
  }

  String _linkWithAccountParams(
    ServerEntry s,
    String? token,
    String? shortIdHex,
  ) {
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
      s.link =
          (newPort == null
                  ? uri.replace(queryParameters: params)
                  : uri.replace(port: newPort, queryParameters: params))
              .toString();
    }
  }
}

int? _listenerPort(List<CatalogListener> listeners, String transportParam) {
  final wanted = transportParam.isEmpty ? 'reality' : transportParam;
  for (final l in listeners) {
    if (l.transport == wanted) return l.port;
  }
  return null;
}

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
    ChimeraSettings settings;
    try {
      final decoded =
          jsonDecode(await f.readAsString()) as Map<String, dynamic>;
      settings = ChimeraSettings.fromJson(decoded);
    } catch (_) {
      return ChimeraSettings();
    }
    settings.signKeyHex =
        await _kSecureStorage.read(key: _kSignKeyStorageKey) ?? '';
    for (final s in settings.servers) {
      s.adminSshPassword = await _kSecureStorage.read(
        key: _adminSshPasswordKey(s.id),
      );
      s.adminToken = await _kSecureStorage.read(key: _adminTokenKey(s.id));
    }
    return settings;
  }

  Future<void> clearServerSelectionState() async {
    final settings = await load();
    settings.servers.clear();
    settings.favoriteServerIds.clear();
    settings.lastConnectedServerId = null;
    await save(settings);
  }

  Future<void> save(ChimeraSettings settings) async {
    final f = await _path();
    final json = settings.toJson();
    json['signKeyHex'] = '';
    final rawServers = json['servers'] as List<dynamic>;
    for (var i = 0; i < settings.servers.length; i++) {
      final entry = rawServers[i] as Map<String, dynamic>;
      entry['adminSshPassword'] = null;
      entry['adminToken'] = null;
    }
    await f.writeAsString(jsonEncode(json));

    await _kSecureStorage.write(
      key: _kSignKeyStorageKey,
      value: settings.signKeyHex,
    );
    for (final s in settings.servers) {
      if (s.adminSshPassword != null) {
        await _kSecureStorage.write(
          key: _adminSshPasswordKey(s.id),
          value: s.adminSshPassword,
        );
      } else {
        await _kSecureStorage.delete(key: _adminSshPasswordKey(s.id));
      }
      if (s.adminToken != null) {
        await _kSecureStorage.write(
          key: _adminTokenKey(s.id),
          value: s.adminToken,
        );
      } else {
        await _kSecureStorage.delete(key: _adminTokenKey(s.id));
      }
    }
  }
}
