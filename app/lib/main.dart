// CHIMERA tray app (Windows): tray icon + Connect/Disconnect over a
// full-tunnel TUN device (see chimera_service.dart's TunnelService and
// network_protection.dart) -- no SOCKS5 fallback; a real elevated-helper
// per-app killswitch integration beyond the tiered network-protection
// toggle, and mobile targets, are later phases per
// docs/app/build-runbook.md, not built here).
// Settings hold a list of saved servers assembled into one
// `#!chimera-subscription-v1` document, persisted locally; the tray menu and
// the Settings hub (small gear icon on Home) show live connection state
// (endpoint health, throughput) and let the user manage servers, network
// protection, split tunneling, and autostart, or Disconnect & quit.
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:launch_at_startup/launch_at_startup.dart';
import 'package:local_notifier/local_notifier.dart';
import 'package:screen_retriever/screen_retriever.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:window_manager/window_manager.dart';

import 'account_entry_page.dart';
import 'account_page.dart';
import 'account_store.dart';
import 'anticensorship_page.dart';
import 'app_info.dart';
import 'catalog_page.dart';
import 'chimera_service.dart';
import 'diagnostics.dart';
import 'network_protection.dart';
import 'settings_hub_page.dart';
import 'settings_store.dart';
import 'speed_sparkline.dart';
import 'theme.dart';

/// Filesystem path to a bundled tray/window icon. tray_manager needs a real
/// filesystem path, not a Flutter asset bundle key. Flutter always stages
/// assets under data/flutter_assets next to the running executable (true for
/// `flutter run` and for a packaged build alike) -- unlike a path relative to
/// windows/runner/resources, which only exists in the source tree and is
/// never copied into a build output, silently breaking the tray icon outside
/// `flutter run`.
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

/// Owns the tray icon from the moment the app starts until `_HomePageState`
/// hands it off (see `_HomePageState.initState`). Without this, the tray
/// icon/menu only came into existence inside `_HomePageState._initTray()`
/// -- which is only reached once `AccountGate` resolves to a signed-in
/// user. On a fresh install (no saved account key yet), that point is never
/// reached: the process stays alive with no tray icon and a window that's
/// hidden by `main()` and never shown, i.e. running invisibly with no way
/// for the user to interact with it at all.
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

  // Mullvad-style popover: no native title bar / min / max / close buttons,
  // fixed size, always anchored next to the tray icon (see _showAtTray) --
  // never centered, never user-moved or user-resized.
  const windowOptions = WindowOptions(
    size: Size(380, 560),
    skipTaskbar: true,
    titleBarStyle: TitleBarStyle.hidden,
    windowButtonVisibility: false,
  );
  await windowManager.waitUntilReadyToShow(windowOptions, () async {
    // Start hidden -- the app lives in the tray until its icon is clicked.
    // Hide first: applying the style locks below before hiding was observed
    // to make the native Show()/Hide() pair leave the window visible.
    await windowManager.hide();
    await windowManager.setResizable(false);
    await windowManager.setMinimizable(false);
    await windowManager.setMaximizable(false);
    await windowManager.setAlwaysOnTop(true);
  });

  // Get a tray icon on screen immediately, before AccountGate/HomePage have
  // had a chance to load -- see _BootstrapTrayListener's doc comment.
  // _HomePageState._initTray() overwrites the icon/tooltip/menu and takes
  // the listener over once it mounts.
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
  } catch (_) {
    // Best-effort: if this fails (e.g. icon asset missing), fall through --
    // _HomePageState._initTray() will retry once it mounts. Never block
    // startup on tray setup.
  }

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

/// First widget shown on launch (ROADMAP2 §4): decides between the
/// account-key entry screen and HomePage based on whether a still-valid
/// local token exists (`AccountStore.hasValidToken` -- currently a local
/// mock of the real control-plane redeem/refresh flow, see
/// account_store.dart). Both branches clear the navigation stack down to
/// themselves so logging in/out never leaves a stale screen behind it.
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
      if (v == false) {
        // No saved account key: there's no tray-driven flow that would ever
        // lead the user to AccountEntryPage on its own (unlike HomePage,
        // which the tray icon toggles), so show the window outright instead
        // of leaving it hidden with nothing on screen to click.
        windowManager.show();
        windowManager.focus();
      }
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

/// Status/home screen: connection state, quick access to Servers/Settings,
/// endpoint health. Also owns the tray icon/menu state machine, since the
/// tray reflects the same [ChimeraState] this screen renders.
class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

enum _TrayIcon { disconnected, connected, error }

class _HomePageState extends State<HomePage> with TrayListener, WindowListener {
  // Nullable + constructed inside initState (not a field initializer): a
  // field initializer runs during State construction, before initState --
  // if TunnelService() (which loads chimera.dll via ChimeraBindings.open())
  // threw there, the whole widget tree would fail to build with nothing on
  // screen to show it (window starts hidden, tray icon doesn't exist yet),
  // leaving the process running invisibly. Constructing it in initState lets
  // us catch that and surface a visible error instead.
  TunnelService? _service;
  String? _initError;
  final _store = SettingsStore();
  ChimeraSettings _settings = ChimeraSettings();
  ChimeraState _state = ChimeraState.disconnected();
  StreamSubscription<ChimeraState>? _stateSub;
  bool _busy = false;
  bool _loaded = false;

  _TrayIcon? _currentTrayIcon;
  DateTime? _lastBlurHideAt;
  DateTime? _lastPollTime;
  int _lastBytesUp = 0;
  int _lastBytesDown = 0;
  final List<double> _upSamples = [];
  final List<double> _downSamples = [];
  static const _maxSamples = 30;

  @override
  void initState() {
    super.initState();
    // Hand the tray icon over from the app-startup bootstrap listener
    // (main.dart's _bootstrapTrayListener) to this page's full
    // Connect/Disconnect/Settings/Quit menu -- both must never be
    // registered at once, or a single click would toggle the window twice.
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
    // Intercept the window's close ("X") button so it hides to the tray
    // instead of exiting the whole app -- only the tray menu's Quit exits.
    await windowManager.setPreventClose(true);
    await _initTray();
    _settings = await _store.load();
    setState(() => _loaded = true);

    if (_settings.autostart && _settings.servers.isNotEmpty) {
      // Silent background reconnect on login/reboot -- makes the autostart
      // toggle actually useful instead of just opening a hidden idle window.
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
      body = next.lastError.isNotEmpty ? next.lastError : null;
    } else if (next.lastError.isNotEmpty) {
      title = 'CHIMERA connect failed';
      body = next.lastError;
    }
    if (title == null) return;
    if (!(Platform.isWindows || Platform.isLinux || Platform.isMacOS)) return;
    try {
      await LocalNotification(title: title, body: body).show();
    } catch (_) {
      // Notifications are a nice-to-have; never let a platform channel
      // failure disrupt the connect/disconnect flow.
    }
  }

  String _obfuscationLabel(ObfuscationMode mode) {
    switch (mode) {
      case ObfuscationMode.reality:
        return 'Reality';
      case ObfuscationMode.quicH3:
        return 'QUIC / H3';
      case ObfuscationMode.shadowsocksAead:
        return 'Shadowsocks-AEAD';
      case ObfuscationMode.dnsOverTcp:
        return 'DNS-over-TCP';
    }
  }

  String _fmtBytes(int n) {
    if (n < 1024) return '$n B';
    if (n < 1024 * 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
    return '${(n / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  String _fmtRate(double bytesPerSec) => '${_fmtBytes(bytesPerSec.round())}/s';

  Future<void> _persist() => _store.save(_settings);

  Future<void> _connect() async {
    if (_busy) return;
    if (_service == null) {
      await _showAtTray();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('CHIMERA engine failed to load: $_initError')),
        );
      }
      return;
    }
    if (_settings.servers.isEmpty) {
      await _showAtTray();
      return;
    }
    setState(() => _busy = true);
    try {
      // Offer to install chimera-helper so this and future Connects don't
      // UAC-prompt every time. Declining doesn't block Connect -- it just
      // means NetworkProtection.enable (inside TunnelService.connect) falls
      // back to one elevated CLI call per connect instead.
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

      // Read live rather than baked into the saved server entry -- the
      // capability token refreshes on its own ~24h TTL (AccountStore's
      // background refresh), so a value captured once at "Choose server"
      // time would go stale. Empty for BYO/legacy servers with no account.
      final account = await AccountStore().load();

      final err = await _service!.connect(
        _settings.subscriptionText(),
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
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Connect failed: $err')));
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Returns true (install), false (skip, remember the choice), or null
  /// (dialog dismissed without an explicit choice -- ask again next Connect).
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

  /// Parses a chimera:// link into the fields NetworkProtection.enable
  /// needs, in pure Dart (mirrors internal/link.Parse's field set: host,
  /// port, pbk, sni, sid, mode). Deliberately not routed through
  /// ChimeraBindings/chimera.dll -- that FFI layer only exists on Windows
  /// (ChimeraBindings.open() throws on Android), and a chimera:// link is
  /// plain enough that dart:core's Uri handles it without any native call
  /// on either platform.
  ({bool ok, String error, String host, String port, String pbk, String sni, String sid, String transport})
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

  /// Resolves the first saved server -- the same "primary server" convention
  /// both _connect and the Settings hub's manual toggle use.
  ({bool ok, String error, String host, String port, String pbk, String sni, String sid, String transport})
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

  /// The short ID to dial with: a catalog-built chimera:// link never
  /// carries `sid=` (that field is per-device, not per-server -- see
  /// AccountInfo.shortIdHex's doc comment), so a -auth-mode controlplane
  /// server needs the account's own control-plane short ID here instead of
  /// the (empty) one parsed from the link. Legacy/BYO links that do embed a
  /// literal sid= (useracl-mode servers) keep using that value unchanged.
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

  /// Curated list (ROADMAP2 §2/§4) -- the sole way to pick a server in the
  /// regular build. The old BYO screen (manual link entry, SSH auto-deploy,
  /// per-server user management) is removed from the UI entirely per §4 --
  /// the underlying Go logic (internal/provision, internal/admin) still
  /// serves chimera-control-cli, it's just no longer reachable from here.
  Future<void> _openCatalog() async {
    await Navigator.of(context).push(
      ChimeraPageRoute(
        builder: (_) => CatalogPage(
          favoriteIds: _settings.favoriteServerIds,
          selectedId: _settings.lastConnectedServerId,
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
          onSelect: (server) async {
            setState(() {
              _settings.lastConnectedServerId = server.id;
              _upsertCuratedServer(server);
            });
            await _persist();
            if (mounted) Navigator.of(context).pop();
          },
        ),
      ),
    );
    setState(() {});
  }

  /// Builds a `chimera://` link (same format `internal/link.Build` produces)
  /// from a picked catalog entry and saves it as the primary server -- the
  /// same "first saved server is what Connect uses" convention
  /// _resolvePrimaryServer already relies on. This is what makes "Choose
  /// server" actually wire up to a real connect target instead of just
  /// recording a cosmetic pick.
  ///
  /// Deliberately does NOT embed the account's capability token here (no
  /// `tok=` param) even though internal/link.Profile.Token/carrier.Config.Token
  /// exist for it: the token refreshes on its own ~24h TTL (AccountStore's
  /// background refresh), so baking one in at selection time would go stale
  /// long before the server is deselected. _connect/_setNetworkProtection
  /// read the live token from AccountStore instead, at connect time.
  void _upsertCuratedServer(CatalogServer server) {
    final mode = switch (_settings.obfuscationMode) {
      ObfuscationMode.reality => '',
      ObfuscationMode.quicH3 => 'quic',
      ObfuscationMode.shadowsocksAead => 'ss',
      ObfuscationMode.dnsOverTcp => 'dot',
    };
    final query = <String>[
      'pbk=${Uri.encodeQueryComponent(server.pubKey)}',
      if (server.sni.isNotEmpty) 'sni=${Uri.encodeQueryComponent(server.sni)}',
      if (mode.isNotEmpty) 'mode=$mode',
      if (server.fingerprint.isNotEmpty)
        'fp=${Uri.encodeQueryComponent(server.fingerprint)}',
    ].join('&');
    final link = 'chimera://${server.host}:${server.port}?$query#${server.id}';

    final existingIndex = _settings.servers.indexWhere(
      (s) => s.id == 'catalog-${server.id}',
    );
    final entry = ServerEntry(
      id: 'catalog-${server.id}',
      label: '${server.city}, ${server.country}',
      link: link,
    );
    if (existingIndex >= 0) {
      _settings.servers[existingIndex] = entry;
    } else {
      _settings.servers.insert(0, entry);
    }
  }

  Future<void> _openAnticensorship() async {
    await Navigator.of(context).push(
      ChimeraPageRoute(
        builder: (_) => AnticensorshipPage(
          current: _settings.obfuscationMode,
          onChanged: (mode) async {
            setState(() => _settings.obfuscationMode = mode);
            await _persist();
          },
        ),
      ),
    );
  }

  Future<void> _openAccount() async {
    final account = await AccountStore().load();
    if (account == null || !mounted) return;
    await Navigator.of(context).push(
      ChimeraPageRoute(
        builder: (_) => AccountPage(
          account: account,
          onLoggedOut: () async {
            if (!mounted) return;
            await Navigator.of(context).pushAndRemoveUntil(
              ChimeraPageRoute(builder: (_) => const AccountGate()),
              (route) => false,
            );
          },
        ),
      ),
    );
  }

  Future<void> _openSettingsHub() async {
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => SettingsHubPage(
          settings: _settings,
          busy: _busy,
          isConnected: _state.isConnected,
          onPersist: _persist,
          onToggleAutostart: _toggleAutostart,
          onSetNetworkProtection: _setNetworkProtection,
          onSetCustomDns: _setCustomDns,
          buildDiagnosticsReport: _buildDiagnosticsReport,
          onDisconnectAndQuit: _disconnectAndQuit,
        ),
      ),
    );
    setState(() {});
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

  /// Switches the network-protection tier against the first saved server --
  /// same "primary server" convention _connect uses. UAC-free once
  /// chimera-helper is installed (see NetworkProtection.enable); otherwise
  /// one elevated UAC prompt per call. There's no "off" tier anymore -- the
  /// app is TUN-only, so this always brings the tunnel up at the chosen
  /// tier, live, independent of whether Connect/Disconnect has been pressed.
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
          SnackBar(content: Text('Network protection failed: ${result.error}')),
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

  /// Best-effort SNI (fallback: host) of the primary server, for the
  /// connected-state subtitle ("Disguised as HTTPS to {sni or host}").
  /// Display-only derivation; does not touch connection state.
  String _disguiseHost() {
    if (_settings.servers.isEmpty) return '';
    final p = _parseChimeraLink(_settings.servers.first.link);
    if (!p.ok) return '';
    return p.sni.isNotEmpty ? p.sni : p.host;
  }

  // Left click: toggle the popover open/closed, like Mullvad/Windows tray
  // flyouts -- never a context menu (that's reserved for right click).
  @override
  void onTrayIconMouseDown() => _toggleWindow();

  // Right click: the actual context menu (Connect/Disconnect, Settings, Quit).
  @override
  void onTrayIconRightMouseDown() => trayManager.popUpContextMenu();

  Future<void> _toggleWindow() async {
    if (await windowManager.isVisible()) {
      await windowManager.hide();
      return;
    }
    // A click on the tray icon while the popover is open first steals native
    // focus -- onWindowBlur() fires and hides the window -- and only then
    // delivers this same click as onTrayIconMouseDown(). Without this guard,
    // isVisible() above would already read false (blur got there first) and
    // this click would immediately re-show the window it was meant to
    // close. Absorb any toggle that follows a blur-hide within one click's
    // worth of time as "that was the close", not "now open it again".
    final blurredAt = _lastBlurHideAt;
    final sinceBlur = blurredAt == null
        ? null
        : DateTime.now().difference(blurredAt);
    if (sinceBlur != null && sinceBlur < const Duration(milliseconds: 400)) {
      return;
    }
    await _showAtTray();
  }

  /// Anchors the popover just above (or, if the taskbar isn't at the
  /// bottom, below) the tray icon's own bounds, clamped to the work area of
  /// the display the icon lives on -- a fixed position derived fresh from
  /// the icon every time, never wherever the OS last left the window.
  Future<void> _showAtTray() async {
    final trayBounds = await trayManager.getBounds();
    if (trayBounds != null) {
      final winSize = await windowManager.getSize();
      const margin = 8.0;
      var left = trayBounds.left + trayBounds.width / 2 - winSize.width / 2;
      var top = trayBounds.top - winSize.height - margin;
      final workArea = await _workAreaContaining(
        Offset(trayBounds.left, trayBounds.top),
      );
      if (top < workArea.top) {
        // Taskbar on top/side of the screen: drop below the icon instead.
        top = trayBounds.bottom + margin;
      }
      left = left.clamp(
        workArea.left + margin,
        workArea.left + workArea.width - winSize.width - margin,
      );
      top = top.clamp(
        workArea.top + margin,
        workArea.top + workArea.height - winSize.height - margin,
      );
      await windowManager.setPosition(Offset(left, top));
    }
    await windowManager.show();
    await windowManager.focus();
  }

  /// The work-area (screen bounds minus taskbar) of the display containing
  /// [point], falling back to the primary display if lookup fails.
  Future<Rect> _workAreaContaining(Offset point) async {
    try {
      final displays = await screenRetriever.getAllDisplays();
      for (final d in displays) {
        final pos = d.visiblePosition;
        final size = d.visibleSize ?? d.size;
        if (pos == null) continue;
        final rect = Rect.fromLTWH(pos.dx, pos.dy, size.width, size.height);
        if (rect.contains(point)) return rect;
      }
      final primary = await screenRetriever.getPrimaryDisplay();
      final pos = primary.visiblePosition ?? Offset.zero;
      final size = primary.visibleSize ?? primary.size;
      return Rect.fromLTWH(pos.dx, pos.dy, size.width, size.height);
    } catch (_) {
      return Rect.fromLTWH(0, 0, 1920, 1080);
    }
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    switch (menuItem.key) {
      case 'toggle':
        await _toggleConnection();
        break;
      case 'settings':
        await _showAtTray();
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
    // No native close button exists, but Alt+F4 etc. still fires this --
    // hide back to the tray instead of exiting. Only the tray menu's Quit
    // (or Disconnect & quit in Settings) actually exits.
    await windowManager.hide();
  }

  @override
  void onWindowBlur() async {
    // Clicking away from the popover closes it, matching the tray-flyout
    // convention (Mullvad, Windows volume/network flyouts, etc.).
    _lastBlurHideAt = DateTime.now();
    await windowManager.hide();
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
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      body: SafeArea(
        child: ListView(
          padding: const EdgeInsets.fromLTRB(20, 20, 20, 24),
          children: [
            _buildBrandRow(context, tokens),
            if (_initError != null) ...[
              const SizedBox(height: 12),
              _buildEngineErrorBanner(context, tokens),
            ],
            const SizedBox(height: 20),
            _buildStatusCard(context, tokens),
            const SizedBox(height: 20),
            _buildSectionLabel(context, tokens, 'Quick access'),
            const SizedBox(height: 8),
            _buildNavRow(
              context,
              tokens,
              title: 'Choose server',
              subtitle: _settings.lastConnectedServerId ?? 'Curated locations',
              onTap: _openCatalog,
            ),
            const SizedBox(height: 8),
            _buildNavRow(
              context,
              tokens,
              title: 'Anti-censorship',
              subtitle: _obfuscationLabel(_settings.obfuscationMode),
              onTap: _openAnticensorship,
            ),
            const SizedBox(height: 8),
            _buildNavRow(
              context,
              tokens,
              title: 'Account',
              subtitle: 'Key, expiry, devices',
              onTap: _openAccount,
            ),
            if (_state.isConnected && _state.endpoints.isNotEmpty) ...[
              const SizedBox(height: 20),
              _buildSectionLabel(context, tokens, 'Endpoint health'),
              const SizedBox(height: 8),
              _buildEndpointHealth(context, tokens),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildBrandRow(BuildContext context, ChimeraTokens tokens) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Container(
          width: 26,
          height: 26,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(7),
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [scheme.primary, scheme.primary, tokens.surface2],
              stops: const [0.0, 0.4, 0.4],
            ),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'CHIMERA',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontWeight: FontWeight.w600,
                  fontSize: 15,
                  color: scheme.onSurface,
                ),
              ),
              Text(
                'Looks like HTTPS. Isn\'t.',
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontSize: 11.5,
                  color: tokens.textFaint,
                ),
              ),
            ],
          ),
        ),
        Tooltip(
          message: 'Settings',
          child: SizedBox(
            width: 30,
            height: 30,
            child: IconButton(
              icon: Icon(Icons.settings_outlined, size: 18, color: tokens.textMuted),
              padding: EdgeInsets.zero,
              onPressed: _openSettingsHub,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildEngineErrorBanner(BuildContext context, ChimeraTokens tokens) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.error.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(11),
        border: Border.all(color: scheme.error.withValues(alpha: 0.4)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, size: 18, color: scheme.error),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'CHIMERA engine failed to load, so Connect is unavailable: '
              '$_initError',
              style: TextStyle(
                fontFamily: 'Plex Sans',
                fontSize: 12,
                color: scheme.error,
                height: 1.35,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatusCard(BuildContext context, ChimeraTokens tokens) {
    final scheme = Theme.of(context).colorScheme;
    final connected = _state.isConnected;
    final connecting = !connected && _busy;
    final statusWord = connecting
        ? 'Connecting…'
        : (connected ? 'Connected' : 'Disconnected');
    final dotColor = connected ? scheme.primary : tokens.textFaint;
    final host = _disguiseHost();

    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: connected ? tokens.accentSoft : tokens.surface2,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: connected
              ? scheme.primary.withValues(alpha: 0.4)
              : Theme.of(context).dividerColor,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 9,
                height: 9,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: dotColor,
                  boxShadow: connected
                      ? [
                          BoxShadow(
                            color: scheme.primary.withValues(alpha: 0.6),
                            blurRadius: 6,
                            spreadRadius: 1,
                          ),
                        ]
                      : null,
                ),
              ),
              const SizedBox(width: 8),
              Text(
                statusWord,
                style: TextStyle(
                  fontFamily: 'Plex Sans',
                  fontWeight: FontWeight.w600,
                  fontSize: 20,
                  color: scheme.onSurface,
                ),
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            connected
                ? 'Disguised as HTTPS to ${host.isNotEmpty ? host : "your server"} '
                      '· transport ${_state.transport}'
                : 'Your traffic is not protected. Connect to disguise it as '
                      'an ordinary HTTPS session to your configured host.',
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 12.5,
              color: tokens.textMuted,
              height: 1.35,
            ),
          ),
          if (connected) ...[
            const SizedBox(height: 14),
            Row(
              children: [
                Expanded(
                  child: _buildMetric(
                    context,
                    tokens,
                    label: 'UPLOAD',
                    value: _upSamples.isEmpty
                        ? '0 B/s'
                        : _fmtRate(_upSamples.last),
                    arrow: '↑',
                  ),
                ),
                Expanded(
                  child: _buildMetric(
                    context,
                    tokens,
                    label: 'DOWNLOAD',
                    value: _downSamples.isEmpty
                        ? '0 B/s'
                        : _fmtRate(_downSamples.last),
                    arrow: '↓',
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            SpeedSparkline(samples: _downSamples, color: scheme.primary),
          ],
          const SizedBox(height: 14),
          SizedBox(
            width: double.infinity,
            child: connected
                ? OutlinedButton(
                    onPressed: _busy ? null : _toggleConnection,
                    child: const Text('Disconnect'),
                  )
                : ElevatedButton(
                    onPressed: _busy ? null : _toggleConnection,
                    child: Text(connecting ? 'Connecting…' : 'Connect'),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildMetric(
    BuildContext context,
    ChimeraTokens tokens, {
    required String label,
    required String value,
    required String arrow,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: TextStyle(
            fontFamily: 'Plex Sans',
            fontSize: 11,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.4,
            color: tokens.textFaint,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          '$arrow $value',
          style: monoStyle(
            fontSize: 15,
            weight: FontWeight.w500,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
      ],
    );
  }

  Widget _buildSectionLabel(
    BuildContext context,
    ChimeraTokens tokens,
    String text,
  ) {
    return Text(
      text.toUpperCase(),
      style: TextStyle(
        fontFamily: 'Plex Sans',
        fontSize: 11,
        fontWeight: FontWeight.w600,
        letterSpacing: 0.6,
        color: tokens.textFaint,
      ),
    );
  }

  Widget _buildNavRow(
    BuildContext context,
    ChimeraTokens tokens, {
    required String title,
    required String subtitle,
    required VoidCallback onTap,
  }) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(11),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(11),
            border: Border.all(color: Theme.of(context).dividerColor),
          ),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontSize: 13.5,
                        fontWeight: FontWeight.w500,
                        color: Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                    Text(
                      subtitle,
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontSize: 12,
                        color: tokens.textFaint,
                      ),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right, color: tokens.textFaint, size: 20),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildEndpointHealth(BuildContext context, ChimeraTokens tokens) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(11),
        border: Border.all(color: Theme.of(context).dividerColor),
      ),
      child: Column(
        children: [
          for (var i = 0; i < _state.endpoints.length; i++) ...[
            if (i > 0)
              Divider(height: 1, color: Theme.of(context).dividerColor),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              child: Row(
                children: [
                  Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: _state.endpoints[i].healthy
                          ? scheme.primary
                          : scheme.error,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      _state.endpoints[i].server,
                      overflow: TextOverflow.ellipsis,
                      style: monoStyle(fontSize: 12.5, color: scheme.onSurface),
                    ),
                  ),
                  Text(
                    '${_state.endpoints[i].rttMs} ms',
                    style: monoStyle(fontSize: 12, color: tokens.textMuted),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }
}
