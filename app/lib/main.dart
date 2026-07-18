import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:launch_at_startup/launch_at_startup.dart';
import 'package:local_notifier/local_notifier.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'account_entry_page.dart';
import 'account_store.dart';
import 'app_info.dart';
import 'catalog_page.dart';
import 'chimera_service.dart';
import 'diagnostics.dart';
import 'full_window_shell.dart';
import 'network_protection.dart';
import 'settings_store.dart';
import 'theme.dart';

String _iconAssetPath(String fileName) {
  final exeDir = File(Platform.resolvedExecutable).parent.path;
  return [
    exeDir,
    'data',
    'flutter_assets',
    'assets',
    'icons',
    fileName,
  ].join(Platform.pathSeparator);
}

class _BootstrapTrayListener with TrayListener {
  @override
  void onTrayIconMouseDown() => _toggleVisibility();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
        windowManager.show();
        windowManager.focus();
        break;
      case 'quit':
        exit(0);
    }
  }

  Future<void> _toggleVisibility() async {
    if (await windowManager.isVisible()) {
      await windowManager.hide();
    } else {
      await windowManager.show();
      await windowManager.focus();
    }
  }
}

final _bootstrapTrayListener = _BootstrapTrayListener();

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  if (Platform.isWindows || Platform.isLinux) {
    await localNotifier.setup(appName: 'CHIMERA');
  }

  launchAtStartup.setup(
    appName: 'CHIMERA',
    appPath: Platform.resolvedExecutable,
  );

  const windowOptions = WindowOptions(
    size: Size(1040, 700),
    minimumSize: Size(760, 520),
    skipTaskbar: false,
    titleBarStyle: TitleBarStyle.hidden,
    windowButtonVisibility: false,
  );
  await windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.setResizable(true);
    await windowManager.setMinimizable(true);
    await windowManager.setMaximizable(true);
    await windowManager.setAlwaysOnTop(false);
    await windowManager.show();
    await windowManager.focus();
  });

  try {
    await trayManager.setIcon(_iconAssetPath('app_icon_disconnected.ico'));
    await trayManager.setToolTip('CHIMERA - starting…');
    await trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(key: 'open', label: 'Open'),
          MenuItem.separator(),
          MenuItem(key: 'quit', label: 'Quit'),
        ],
      ),
    );
    trayManager.addListener(_bootstrapTrayListener);
  } catch (_) {}

  runApp(const ChimeraTrayApp());
}

class ChimeraTrayApp extends StatelessWidget {
  const ChimeraTrayApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CHIMERA',
      debugShowCheckedModeBanner: false,
      theme: chimeraLightTheme,
      darkTheme: chimeraDarkTheme,
      themeMode: ThemeMode.system,
      home: const AccountGate(),
    );
  }
}

class AccountGate extends StatefulWidget {
  const AccountGate({super.key});

  @override
  State<AccountGate> createState() => _AccountGateState();
}

class _AccountGateState extends State<AccountGate> {
  bool? _hasValidToken;

  @override
  void initState() {
    super.initState();

    AccountStore().hasValidToken().then((v) {
      if (mounted) setState(() => _hasValidToken = v);
    });
  }

  void _goHome(BuildContext context) {
    Navigator.of(context).pushAndRemoveUntil(
      ChimeraPageRoute(builder: (_) => const HomePage()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_hasValidToken == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_hasValidToken == false) {
      return AccountEntryPage(onRedeemed: (_) async => _goHome(context));
    }
    return const HomePage();
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

enum _TrayIcon { disconnected, connected, error }

class _HomePageState extends State<HomePage> with TrayListener, WindowListener {
  TunnelService? _service;
  String? _initError;
  final _store = SettingsStore();
  ChimeraSettings _settings = ChimeraSettings();
  ChimeraState _state = ChimeraState.disconnected();
  StreamSubscription<ChimeraState>? _stateSub;
  bool _busy = false;
  bool _loaded = false;

  _TrayIcon? _currentTrayIcon;
  DateTime? _lastPollTime;
  int _lastBytesUp = 0;
  int _lastBytesDown = 0;
  final List<double> _upSamples = [];
  final List<double> _downSamples = [];
  static const _maxSamples = 30;

  @override
  void initState() {
    super.initState();

    trayManager.removeListener(_bootstrapTrayListener);
    trayManager.addListener(this);
    windowManager.addListener(this);
    try {
      _service = TunnelService();
      _stateSub = _service!.stateUpdates.listen(_onStateUpdate);
    } catch (e) {
      _initError = '$e';
    }
    _init();
  }

  Future<void> _init() async {
    await windowManager.setPreventClose(true);
    await _initTray();
    _settings = await _store.load();
    setState(() => _loaded = true);

    if (_settings.autostart && _settings.servers.isNotEmpty) {
      unawaited(_connect());
    }
  }

  Future<void> _initTray() async {
    await _setTrayIcon(_TrayIcon.disconnected, force: true);
    await trayManager.setToolTip('CHIMERA - disconnected');
    await _rebuildMenu();
  }

  Future<void> _setTrayIcon(_TrayIcon icon, {bool force = false}) async {
    if (!force && icon == _currentTrayIcon) return;
    _currentTrayIcon = icon;
    final name = switch (icon) {
      _TrayIcon.disconnected => 'app_icon_disconnected.ico',
      _TrayIcon.connected => 'app_icon_connected.ico',
      _TrayIcon.error => 'app_icon_error.ico',
    };
    await trayManager.setIcon(_iconAssetPath(name));
  }

  void _onStateUpdate(ChimeraState s) {
    final prev = _state;
    setState(() {
      _updateSpeedSamples(s);
      _state = s;
    });
    _updateTray(prev, s);
  }

  void _updateSpeedSamples(ChimeraState s) {
    final now = DateTime.now();
    if (s.isConnected && _lastPollTime != null) {
      final dt = now.difference(_lastPollTime!).inMilliseconds / 1000.0;
      if (dt > 0) {
        _pushSample(_upSamples, (s.bytesUp - _lastBytesUp) / dt);
        _pushSample(_downSamples, (s.bytesDown - _lastBytesDown) / dt);
      }
    } else if (!s.isConnected) {
      _upSamples.clear();
      _downSamples.clear();
    }
    _lastPollTime = now;
    _lastBytesUp = s.bytesUp;
    _lastBytesDown = s.bytesDown;
  }

  void _pushSample(List<double> samples, double v) {
    samples.add(v < 0 ? 0 : v);
    if (samples.length > _maxSamples) samples.removeAt(0);
  }

  Future<void> _rebuildMenu() async {
    await trayManager.setContextMenu(
      Menu(
        items: [
          MenuItem(
            key: 'status',
            label:
                'Status: ${_state.state}'
                '${_state.isConnected ? " (${_state.transport}, "
                          "${_fmtBytes(_state.bytesUp)} up / "
                          "${_fmtBytes(_state.bytesDown)} down)" : ""}',
            disabled: true,
          ),
          MenuItem.separator(),
          MenuItem(
            key: 'toggle',
            label: _state.isConnected ? 'Disconnect' : 'Connect',
          ),
          MenuItem(key: 'settings', label: 'Settings...'),
          MenuItem.separator(),
          MenuItem(key: 'quit', label: 'Quit'),
        ],
      ),
    );
  }

  Future<void> _updateTray(ChimeraState prev, ChimeraState next) async {
    final icon = next.isConnected
        ? _TrayIcon.connected
        : (next.lastError.isNotEmpty
              ? _TrayIcon.error
              : _TrayIcon.disconnected);
    await _setTrayIcon(icon);
    await trayManager.setToolTip(
      next.isConnected
          ? 'CHIMERA - connected (${next.transport})'
          : 'CHIMERA - disconnected',
    );
    await _rebuildMenu();
    await _maybeNotify(prev, next);
  }

  Future<void> _maybeNotify(ChimeraState prev, ChimeraState next) async {
    if (prev.state == next.state) return;
    String? title;
    String? body;
    if (next.isConnected) {
      title = 'CHIMERA connected';
      body = 'Transport: ${next.transport}';
    } else if (prev.isConnected) {
      title = 'CHIMERA disconnected';
      body = next.lastError.isNotEmpty
          ? friendlyConnectError(next.lastError)
          : null;
    } else if (next.lastError.isNotEmpty) {
      title = 'CHIMERA connect failed';
      body = friendlyConnectError(next.lastError);
    }
    if (title == null) return;
    if (!(Platform.isWindows || Platform.isLinux || Platform.isMacOS)) return;
    try {
      await LocalNotification(title: title, body: body).show();
    } catch (_) {}
  }

  String _fmtBytes(int n) {
    if (n < 1024) return '$n B';
    if (n < 1024 * 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
    return '${(n / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  Future<void> _persist() => _store.save(_settings);

  Future<void> _connect() async {
    if (_busy) return;
    if (_service == null) {
      await windowManager.show();
      await windowManager.focus();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('CHIMERA engine failed to load: $_initError')),
        );
      }
      return;
    }
    if (_settings.servers.isEmpty) {
      await windowManager.show();
      await windowManager.focus();
      return;
    }
    setState(() => _busy = true);
    try {
      if (!_settings.nethelperDeclined &&
          !await NetworkProtection.isHelperInstalled()) {
        final install = await _offerNethelperInstall();
        if (install == false) {
          setState(() => _settings.nethelperDeclined = true);
          await _persist();
        } else if (install == true) {
          final installResult = await NetworkProtection.installHelper();
          if (!installResult.ok && mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(
                  'Could not install chimera-helper: ${installResult.error}',
                ),
              ),
            );
          }
        }
      }

      final resolved = _resolvePrimaryServer();
      if (!resolved.ok) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Connect failed: ${resolved.error}')),
          );
        }
        return;
      }

      final account = await AccountStore().load();

      final err = await _service!.connect(
        _settings.subscriptionText(
          token: account?.token,
          shortIdHex: account?.shortIdHex,
        ),
        primaryServer: PrimaryServer(
          host: resolved.host,
          port: resolved.port,
          pbk: resolved.pbk,
          sni: resolved.sni,
          sid: _effectiveSid(resolved.sid, account),
          transport: resolved.transport,
          token: account?.token ?? '',
        ),
        signKeyHex: _settings.signKeyHex,
        mode: _settings.networkProtection,
        dns: _settings.customDns,
      );
      if (err != null && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Connect failed: ${friendlyConnectError(err)}'),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<bool?> _offerNethelperInstall() {
    return showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Enable full VPN protection?'),
        content: const Text(
          'CHIMERA can install a small background helper (one-time, needs '
          'administrator approval) so Connect can bring up the tunnel '
          'without an administrator prompt every time. Skipping this still '
          'lets you connect -- it just asks for approval on every Connect.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Skip'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Install'),
          ),
        ],
      ),
    );
  }

  ({
    bool ok,
    String error,
    String host,
    String port,
    String pbk,
    String sni,
    String sid,
    String transport,
  })
  _parseChimeraLink(String link) {
    Uri uri;
    try {
      uri = Uri.parse(link.trim());
    } catch (e) {
      return (
        ok: false,
        error: 'invalid server link: $e',
        host: '',
        port: '',
        pbk: '',
        sni: '',
        sid: '',
        transport: '',
      );
    }
    if (uri.scheme != 'chimera' || uri.host.isEmpty) {
      return (
        ok: false,
        error: 'invalid server link: not a chimera:// URI',
        host: '',
        port: '',
        pbk: '',
        sni: '',
        sid: '',
        transport: '',
      );
    }
    final q = uri.queryParameters;
    return (
      ok: true,
      error: '',
      host: uri.host,
      port: uri.hasPort ? uri.port.toString() : '',
      pbk: q['pbk'] ?? '',
      sni: q['sni'] ?? '',
      sid: q['sid'] ?? '',
      transport: q['mode'] ?? '',
    );
  }

  ({
    bool ok,
    String error,
    String host,
    String port,
    String pbk,
    String sni,
    String sid,
    String transport,
  })
  _resolvePrimaryServer() {
    if (_settings.servers.isEmpty) {
      return (
        ok: false,
        error: 'no saved servers',
        host: '',
        port: '',
        pbk: '',
        sni: '',
        sid: '',
        transport: '',
      );
    }
    return _parseChimeraLink(_settings.servers.first.link);
  }

  String _effectiveSid(String linkSid, AccountInfo? account) =>
      linkSid.isNotEmpty ? linkSid : (account?.shortIdHex ?? '');

  Future<void> _toggleConnection() async {
    if (_busy) return;
    if (_state.isConnected) {
      setState(() => _busy = true);
      try {
        await _service?.disconnect();
      } finally {
        if (mounted) setState(() => _busy = false);
      }
    } else {
      await _connect();
    }
  }

  void _upsertCuratedServer(CatalogServer server) {
    final preferred = obfuscationModeQueryParam(_settings.obfuscationMode);
    final port = server.portFor(preferred) ?? server.portFor('') ?? server.port;
    final mode = server.portFor(preferred) != null ? preferred : '';
    final query = <String>[
      'pbk=${Uri.encodeQueryComponent(server.pubKey)}',
      if (server.sni.isNotEmpty) 'sni=${Uri.encodeQueryComponent(server.sni)}',
      if (mode.isNotEmpty) 'mode=$mode',
      if (server.fingerprint.isNotEmpty)
        'fp=${Uri.encodeQueryComponent(server.fingerprint)}',
    ].join('&');
    final link = 'chimera://${server.host}:$port?$query#${server.id}';

    final existingIndex = _settings.servers.indexWhere(
      (s) => s.id == 'catalog-${server.id}',
    );
    final entry = ServerEntry(
      id: 'catalog-${server.id}',
      label: '${server.city}, ${server.country}',
      link: link,
      catalogListeners: server.listeners,
    );
    if (existingIndex >= 0) {
      _settings.servers[existingIndex] = entry;
    } else {
      _settings.servers.insert(0, entry);
    }
  }

  Set<String>? _primaryServerAvailableTransports() {
    if (_settings.servers.isEmpty) return null;
    final listeners = _settings.servers.first.catalogListeners;
    if (listeners.isEmpty) return null;
    return listeners
        .map((l) => l.transport == 'reality' ? '' : l.transport)
        .toSet();
  }

  Future<void> _toggleAutostart(bool value) async {
    setState(() => _settings.autostart = value);
    await _persist();
    if (value) {
      await launchAtStartup.enable();
    } else {
      await launchAtStartup.disable();
    }
  }

  Future<bool> _setNetworkProtection(NetworkProtectionMode mode) async {
    if (_settings.servers.isEmpty) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Add a server first')));
      return false;
    }
    setState(() => _busy = true);
    try {
      final resolved = _resolvePrimaryServer();
      final account = resolved.ok ? await AccountStore().load() : null;
      final result = resolved.ok
          ? await NetworkProtection.enable(
              mode: mode,
              server: '${resolved.host}:${resolved.port}',
              pbk: resolved.pbk,
              sni: resolved.sni,
              sid: _effectiveSid(resolved.sid, account),
              dns: _settings.customDns,
              transport: resolved.transport,
              token: account?.token ?? '',
            )
          : NetworkProtectionResult(ok: false, error: resolved.error);
      if (result.ok) {
        setState(() => _settings.networkProtection = mode);
        await _persist();
      } else if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Network protection failed: ${friendlyConnectError(result.error)}',
            ),
          ),
        );
      }
      return result.ok;
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _setCustomDns(List<String> dns) async {
    setState(() => _settings.customDns = dns);
    await _persist();
  }

  String _buildDiagnosticsReport() => Diagnostics.buildReport(
    settings: _settings,
    state: _state,
    appVersion: kAppVersion,
  );

  Future<void> _disconnectAndQuit() async {
    if (_state.isConnected) {
      await _service?.disconnect();
    }
    _service?.dispose();
    await trayManager.destroy();
    exit(0);
  }

  @override
  void onTrayIconMouseDown() => _showWindow();

  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  Future<void> _showWindow() async {
    if (await windowManager.isVisible()) {
      await windowManager.hide();
    } else {
      await windowManager.show();
      await windowManager.focus();
    }
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    switch (menuItem.key) {
      case 'toggle':
        await _toggleConnection();
        break;
      case 'settings':
        await windowManager.show();
        await windowManager.focus();
        break;
      case 'quit':
        await _service?.disconnect();
        _service?.dispose();
        await trayManager.destroy();
        exit(0);
    }
  }

  @override
  void onWindowClose() async {
    if (_settings.minimizeToTray) {
      await windowManager.hide();
      return;
    }
    await _disconnectAndQuit();
  }

  @override
  void dispose() {
    trayManager.removeListener(this);
    windowManager.removeListener(this);
    _stateSub?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!_loaded) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return FullWindowShell(
      initError: _initError,
      state: _state,
      busy: _busy,
      settings: _settings,
      onToggleConnection: _toggleConnection,
      selectedServer: _selectedServerDisplay(),
      onToggleFavorite: (id) async {
        setState(() {
          if (_settings.favoriteServerIds.contains(id)) {
            _settings.favoriteServerIds.remove(id);
          } else {
            _settings.favoriteServerIds.add(id);
          }
        });
        await _persist();
      },
      onSelectServer: (server) async {
        setState(() {
          _settings.lastConnectedServerId = server.id;
          _upsertCuratedServer(server);
        });
        await _persist();
      },
      onSetObfuscationMode: (mode) async {
        setState(() {
          _settings.obfuscationMode = mode;
          _settings.applyObfuscationModeToCatalogServers(mode);
        });
        await _persist();
      },
      availableTransportParams: _primaryServerAvailableTransports(),
      onSplitTunnelChanged: () async {
        setState(() {});
        await _persist();
      },
      onLoggedOut: () async {
        await Navigator.of(context).pushAndRemoveUntil(
          ChimeraPageRoute(builder: (_) => const AccountGate()),
          (route) => false,
        );
      },
      onPersist: _persist,
      onToggleAutostart: _toggleAutostart,
      onSetNetworkProtection: _setNetworkProtection,
      onSetCustomDns: _setCustomDns,
      buildDiagnosticsReport: _buildDiagnosticsReport,
      onDisconnectAndQuit: _disconnectAndQuit,
      onSetMinimizeToTray: (v) async {
        setState(() => _settings.minimizeToTray = v);
        await _persist();
      },
      downSamples: _downSamples,
    );
  }

  ({String city, String country, String flag})? _selectedServerDisplay() {
    final id = _settings.lastConnectedServerId;
    if (id == null) return null;
    ServerEntry? entry;
    for (final s in _settings.servers) {
      if (s.id == 'catalog-$id') {
        entry = s;
        break;
      }
    }
    if (entry == null) return null;
    final parts = entry.label.split(',');
    if (parts.isEmpty) return null;
    final city = parts.first.trim();
    final country = parts.length > 1 ? parts.sublist(1).join(',').trim() : '';
    return (city: city, country: country, flag: flagForCountry(country));
  }
}
