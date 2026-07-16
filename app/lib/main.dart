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
import 'signal_core.dart';
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

/// Anchors the popover just above (or, if the taskbar isn't at the bottom,
/// below) the tray icon's own bounds, clamped to the work area of the
/// display the icon lives on -- a fixed position derived fresh from the
/// icon every time, never wherever the OS last left the window. Shared by
/// _HomePageState (post-login) and AccountGate's first-run key-entry
/// screen, so neither path ever leaves the window sitting at the runner's
/// hardcoded (10, 10) startup origin (windows/runner/main.cpp) with no way
/// to move, minimize, or dismiss it -- the window is deliberately
/// non-resizable/non-minimizable everywhere (Mullvad-style popover, see
/// main()'s windowOptions), so anchoring is the only way it ever ends up
/// somewhere the user can reach and click away from to dismiss.
Future<void> _showWindowAtTray() async {
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
        // of leaving it hidden with nothing on screen to click. Anchor it
        // next to the tray icon like every other popover show -- a plain
        // show()/focus() here left the window at the runner's hardcoded
        // (10, 10) startup position, and since the popover is deliberately
        // non-resizable/non-minimizable/always-on-top, that made it
        // impossible to move, minimize, or reach to dismiss.
        _showWindowAtTray();
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

  /// Label for a transport by its `obfuscationModeQueryParam` value (`''`
  /// for Reality, else `quic`/`ss`/`dot`) rather than by [ObfuscationMode] --
  /// used where the actually-resolved transport for the selected server
  /// (which can differ from the global `_settings.obfuscationMode` when that
  /// server doesn't offer it -- see `_upsertCuratedServer`'s fallback) needs
  /// a display name, not just the user's global preference.
  String _transportLabelFromParam(String param) {
    switch (param) {
      case 'quic':
        return 'QUIC / H3';
      case 'ss':
        return 'Shadowsocks-AEAD';
      case 'dot':
        return 'DNS-over-TCP';
      default:
        return 'Reality';
    }
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
  ///
  /// Different transports can live on different ports on the same server
  /// (ROADMAP2 §3/§4 multi-transport support -- see `CatalogServer.portFor`),
  /// so this dials whichever port the *currently selected* Anti-censorship
  /// mode actually listens on, not always `server.port`. If this server has
  /// no listener at all for that mode (not every server runs all 4
  /// transports), it falls back to the server's Reality listener rather
  /// than building a link that's guaranteed to fail -- "no false promises"
  /// means Connect should work with whatever was actually picked, even if
  /// that's not the globally preferred transport for this one server.
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

  /// The transports the primary (first-saved) server actually has listeners
  /// for, or null if unknown (no server saved yet, or a BYO/legacy link with
  /// no recorded catalog listeners) -- see AnticensorshipPage's doc comment
  /// on availableTransportParams.
  Set<String>? _primaryServerAvailableTransports() {
    if (_settings.servers.isEmpty) return null;
    final listeners = _settings.servers.first.catalogListeners;
    if (listeners.isEmpty) return null;
    return listeners
        .map((l) => l.transport == 'reality' ? '' : l.transport)
        .toSet();
  }

  Future<void> _openAnticensorship() async {
    await Navigator.of(context).push(
      ChimeraPageRoute(
        builder: (_) => AnticensorshipPage(
          current: _settings.obfuscationMode,
          availableTransportParams: _primaryServerAvailableTransports(),
          onChanged: (mode) async {
            setState(() {
              _settings.obfuscationMode = mode;
              // Keep any already-picked catalog server's link in sync --
              // otherwise this switch has no effect on the next Connect
              // until the server is reselected. See
              // ChimeraSettings.applyObfuscationModeToCatalogServers.
              _settings.applyObfuscationModeToCatalogServers(mode);
            });
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
          state: _state,
          downSamples: _downSamples,
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

  /// Anchors the popover next to the tray icon -- see the top-level
  /// _showWindowAtTray, shared with AccountGate's first-run key-entry show.
  Future<void> _showAtTray() => _showWindowAtTray();

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
    // Layout mirrors the redesign artifact's Windows popover frame exactly:
    // brand row -> signal core -> status row -> server card -> transport/
    // latency pills -> Connect/Disconnect pinned to the bottom via the
    // Expanded/scroll split below (the artifact's `.spacer{flex:1}`).
    // Upload/download throughput and per-endpoint RTT used to render here
    // too; the artifact's Home has neither, so that live detail moved to
    // Support (see settings_hub_page.dart/support_page.dart).
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(20, 20, 20, 24),
          child: Column(
            children: [
              _buildBrandRow(context, tokens),
              if (_initError != null) ...[
                const SizedBox(height: 12),
                _buildEngineErrorBanner(context, tokens),
              ],
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    children: [
                      const SizedBox(height: 6),
                      SignalCore(active: _state.isConnected),
                      _buildStatusRow(context, tokens),
                      const SizedBox(height: 20),
                      _buildServerCard(context, tokens),
                      const SizedBox(height: 14),
                      _buildPillsRow(context, tokens),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 14),
              _buildConnectButton(context),
            ],
          ),
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
          message: 'Account',
          child: SizedBox(
            width: 30,
            height: 30,
            child: IconButton(
              icon: Icon(Icons.person_outline, size: 18, color: tokens.textMuted),
              padding: EdgeInsets.zero,
              onPressed: _openAccount,
            ),
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

  /// Status label under the signal core -- "Protected" only while actually
  /// connected, matching the artifact's frame exactly (it never shows a
  /// connected-but-unhealthy state here; that detail lives in Support's
  /// endpoint health list now).
  Widget _buildStatusRow(BuildContext context, ChimeraTokens tokens) {
    final scheme = Theme.of(context).colorScheme;
    final connected = _state.isConnected;
    final connecting = !connected && _busy;
    final label = connecting
        ? 'Connecting…'
        : (connected ? 'Protected' : 'Not protected');
    return Column(
      children: [
        Text(
          'STATUS',
          style: monoStyle(
            fontSize: 11.5,
            weight: FontWeight.w500,
            color: tokens.textFaint,
          ).copyWith(letterSpacing: 1.2),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(
            fontFamily: 'Plex Sans',
            fontWeight: FontWeight.w600,
            fontSize: 19,
            color: connected ? scheme.primary : scheme.onSurface,
          ),
        ),
      ],
    );
  }

  /// Best-effort city/country/flag for the currently selected (last
  /// connected) catalog server, read off the saved `ServerEntry.label`
  /// ("City, Country") that `_upsertCuratedServer` writes -- null before any
  /// server has ever been picked.
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

  /// Compact server card (artifact: `.card.server-card`) -- the sole way to
  /// see/change the selected location on Home, replacing the old
  /// "Choose server" Quick-access row. Tapping it always opens the catalog,
  /// whether or not a server is selected yet.
  Widget _buildServerCard(BuildContext context, ChimeraTokens tokens) {
    final info = _selectedServerDisplay();
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: _openCatalog,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
          decoration: BoxDecoration(
            color: tokens.surface2,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Theme.of(context).dividerColor),
          ),
          child: Row(
            children: [
              if (info != null) ...[
                SizedBox(
                  width: 26,
                  child: Text(info.flag, style: const TextStyle(fontSize: 16)),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        info.city,
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontWeight: FontWeight.w600,
                          fontSize: 13.5,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                      Text(
                        info.country,
                        style: TextStyle(
                          fontFamily: 'Plex Sans',
                          fontSize: 11.5,
                          color: tokens.textMuted,
                        ),
                      ),
                    ],
                  ),
                ),
              ] else
                Expanded(
                  child: Text(
                    'Choose a location',
                    style: TextStyle(
                      fontFamily: 'Plex Sans',
                      fontWeight: FontWeight.w600,
                      fontSize: 13.5,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                  ),
                ),
              Icon(Icons.chevron_right, color: tokens.textFaint, size: 18),
            ],
          ),
        ),
      ),
    );
  }

  /// Average RTT across healthy endpoints, for the latency pill -- null
  /// (pill hidden) until connected with at least one measured endpoint.
  String? _latencyLabel() {
    if (!_state.isConnected) return null;
    final rtts = _state.endpoints
        .map((e) => e.rttMs)
        .where((v) => v > 0)
        .toList();
    if (rtts.isEmpty) return null;
    final avg = rtts.reduce((a, b) => a + b) ~/ rtts.length;
    return '$avg ms';
  }

  /// Transport + latency pills (artifact: `.pill` / `.pill.muted`). The
  /// transport pill is tappable -- it's the replacement for the old
  /// "Anti-censorship" Quick-access row.
  ///
  /// Shows the transport the primary server's *saved link* actually resolves
  /// to, not blindly `_settings.obfuscationMode` -- when that server doesn't
  /// offer the globally preferred transport, `_upsertCuratedServer` already
  /// fell back to one it does, and this pill has to agree with what Connect
  /// will really dial (see that method's doc comment: "no false promises"
  /// applies to what actually happens, not just to the picker's copy).
  Widget _buildPillsRow(BuildContext context, ChimeraTokens tokens) {
    final latency = _latencyLabel();
    final resolved = _resolvePrimaryServer();
    final transportLabel = _transportLabelFromParam(
      resolved.ok ? resolved.transport : obfuscationModeQueryParam(_settings.obfuscationMode),
    );
    return Row(
      children: [
        _pill(
          context,
          tokens,
          text: transportLabel,
          accent: true,
          onTap: _openAnticensorship,
        ),
        if (latency != null) ...[
          const SizedBox(width: 8),
          _pill(context, tokens, text: latency, accent: false),
        ],
      ],
    );
  }

  Widget _pill(
    BuildContext context,
    ChimeraTokens tokens, {
    required String text,
    required bool accent,
    VoidCallback? onTap,
  }) {
    final scheme = Theme.of(context).colorScheme;
    final child = Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: accent ? tokens.accentSoft : tokens.neutralPill,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        text,
        style: monoStyle(
          fontSize: 10.5,
          weight: FontWeight.w500,
          color: accent ? scheme.primary : tokens.textMuted,
        ),
      ),
    );
    if (onTap == null) return child;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(999),
        onTap: onTap,
        child: child,
      ),
    );
  }

  Widget _buildConnectButton(BuildContext context) {
    final connected = _state.isConnected;
    final connecting = !connected && _busy;
    return SizedBox(
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
    );
  }
}
