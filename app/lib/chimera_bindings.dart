// Typed dart:ffi bindings for chimera.dll (built from desktop/cffi via
// `-buildmode=c-shared`). Mirrors mobile.Tunnel's lifecycle (see
// desktop/cffi/main.go's doc comment): every Pointer<Utf8> this library
// returns is heap-allocated on the Go side and MUST be freed via
// ChimeraFreeString once its contents are copied out -- callers in this file
// do that immediately, so nothing above this layer ever touches a raw
// pointer's lifetime.
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

typedef _NewTunnelNative =
    Pointer<Utf8> Function(
      Pointer<Utf8> subscriptionText,
      Pointer<Utf8> signKeyHex,
    );
typedef _NewTunnelDart =
    Pointer<Utf8> Function(
      Pointer<Utf8> subscriptionText,
      Pointer<Utf8> signKeyHex,
    );

typedef _NewTunnelFromLinkNative = Pointer<Utf8> Function(Pointer<Utf8> uri);
typedef _NewTunnelFromLinkDart = Pointer<Utf8> Function(Pointer<Utf8> uri);

typedef _ConnectNative = Pointer<Utf8> Function(Int64 handle);
typedef _ConnectDart = Pointer<Utf8> Function(int handle);

typedef _StartFDNative =
    Pointer<Utf8> Function(Int64 handle, Int32 fd, Int32 mtu);
typedef _StartFDDart = Pointer<Utf8> Function(int handle, int fd, int mtu);

typedef _StartSocksNative =
    Pointer<Utf8> Function(Int64 handle, Pointer<Utf8> listen);
typedef _StartSocksDart =
    Pointer<Utf8> Function(int handle, Pointer<Utf8> listen);

typedef _StopNative = Void Function(Int64 handle);
typedef _StopDart = void Function(int handle);

typedef _StateJSONNative = Pointer<Utf8> Function(Int64 handle);
typedef _StateJSONDart = Pointer<Utf8> Function(int handle);

typedef _ParseLinkNative = Pointer<Utf8> Function(Pointer<Utf8> uri);
typedef _ParseLinkDart = Pointer<Utf8> Function(Pointer<Utf8> uri);

typedef _DeployServerNative = Pointer<Utf8> Function(Pointer<Utf8> specJson);
typedef _DeployServerDart = Pointer<Utf8> Function(Pointer<Utf8> specJson);

typedef _TeardownServerNative = Pointer<Utf8> Function(Pointer<Utf8> specJson);
typedef _TeardownServerDart = Pointer<Utf8> Function(Pointer<Utf8> specJson);

typedef _FreeHandleNative = Void Function(Int64 handle);
typedef _FreeHandleDart = void Function(int handle);

typedef _FreeStringNative = Void Function(Pointer<Utf8> s);
typedef _FreeStringDart = void Function(Pointer<Utf8> s);

/// ChimeraNativeApi is the interface ChimeraService and other callers depend
/// on, so tests can inject a fake instead of loading the real chimera.dll
/// (which isn't present in the `flutter test` working directory, and which
/// makes an actual native call per invocation).
abstract class ChimeraNativeApi {
  String newTunnel(String subscriptionText, String signKeyHex);
  String newTunnelFromLink(String uri);
  String connect(int handle);
  String startFD(int handle, int fd, int mtu);
  String startSocks(int handle, String listen);
  void stop(int handle);
  String stateJSON(int handle);
  String parseLink(String uri);

  /// deployServer bootstraps a CHIMERA server on a bare VPS over SSH (see
  /// ChimeraDeployServer in desktop/cffi/main.go). It blocks for the whole
  /// deployment (installing Docker + building an image can take minutes) --
  /// callers MUST invoke this on a background isolate, never the UI isolate.
  String deployServer(String specJson);

  /// teardownServer removes any CHIMERA-managed Docker container(s) from a
  /// VPS over SSH (see ChimeraTeardownServer in desktop/cffi/main.go) -- the
  /// counterpart to deployServer, called when a server is deleted from the
  /// app. Same "background isolate only" contract as deployServer.
  String teardownServer(String specJson);
  void freeHandle(int handle);
}

/// Android has no chimera.dll to preflight against -- [ChimeraBindings.open]
/// throws on this platform. That preflight (newTunnel/connect/freeHandle in
/// TunnelService._connectOnce, see chimera_service.dart) exists to verify
/// reachability fast before engaging the real TUN device; on Android that
/// same check already happens inside `chimeramobile.Tunnel.connect()`,
/// called synchronously by ChimeraVpnService.kt's RealGoTunnel.start before
/// it opens the tunnel. So this stub just reports success unconditionally
/// and lets AndroidNetworkProtectionController.engage (network_protection.dart)
/// do the real work end to end.
class AndroidNoPreflightNativeApi implements ChimeraNativeApi {
  const AndroidNoPreflightNativeApi();

  @override
  String newTunnel(String subscriptionText, String signKeyHex) => '{"handle":0,"error":""}';
  @override
  String newTunnelFromLink(String uri) => '{"handle":0,"error":""}';
  @override
  String connect(int handle) => '';
  @override
  String startFD(int handle, int fd, int mtu) => '';
  @override
  String startSocks(int handle, String listen) => '';
  @override
  void stop(int handle) {}
  @override
  String stateJSON(int handle) => '{}';
  @override
  String parseLink(String uri) => '{}';
  @override
  String deployServer(String specJson) =>
      '{"error":"server deploy is CLI-operator only, not available on Android (ROADMAP2 §2)"}';
  @override
  String teardownServer(String specJson) =>
      '{"error":"server teardown is CLI-operator only, not available on Android (ROADMAP2 §2)"}';
  @override
  void freeHandle(int handle) {}
}

/// ChimeraBindings loads chimera.dll (resolved relative to the running
/// executable, same directory dart:ffi's DynamicLibrary.open searches by
/// default on Windows) and exposes the exported C functions with Dart
/// types instead of raw FFI signatures.
class ChimeraBindings implements ChimeraNativeApi {
  ChimeraBindings._(DynamicLibrary lib)
    : _newTunnelNative = lib.lookupFunction<_NewTunnelNative, _NewTunnelDart>(
        'ChimeraNewTunnel',
      ),
      _newTunnelFromLinkNative = lib
          .lookupFunction<_NewTunnelFromLinkNative, _NewTunnelFromLinkDart>(
            'ChimeraNewTunnelFromLink',
          ),
      _connectNative = lib.lookupFunction<_ConnectNative, _ConnectDart>(
        'ChimeraConnect',
      ),
      _startFDNative = lib.lookupFunction<_StartFDNative, _StartFDDart>(
        'ChimeraStartFD',
      ),
      _startSocksNative = lib
          .lookupFunction<_StartSocksNative, _StartSocksDart>(
            'ChimeraStartSocks',
          ),
      _stopNative = lib.lookupFunction<_StopNative, _StopDart>('ChimeraStop'),
      _stateJSONNative = lib.lookupFunction<_StateJSONNative, _StateJSONDart>(
        'ChimeraStateJSON',
      ),
      _parseLinkNative = lib.lookupFunction<_ParseLinkNative, _ParseLinkDart>(
        'ChimeraParseLink',
      ),
      _deployServerNative = lib
          .lookupFunction<_DeployServerNative, _DeployServerDart>(
            'ChimeraDeployServer',
          ),
      _teardownServerNative = lib
          .lookupFunction<_TeardownServerNative, _TeardownServerDart>(
            'ChimeraTeardownServer',
          ),
      _freeHandleNative = lib
          .lookupFunction<_FreeHandleNative, _FreeHandleDart>(
            'ChimeraFreeHandle',
          ),
      _freeStringNative = lib
          .lookupFunction<_FreeStringNative, _FreeStringDart>(
            'ChimeraFreeString',
          );

  final _NewTunnelDart _newTunnelNative;
  final _NewTunnelFromLinkDart _newTunnelFromLinkNative;
  final _ConnectDart _connectNative;
  final _StartFDDart _startFDNative;
  final _StartSocksDart _startSocksNative;
  final _StopDart _stopNative;
  final _StateJSONDart _stateJSONNative;
  final _ParseLinkDart _parseLinkNative;
  final _DeployServerDart _deployServerNative;
  final _TeardownServerDart _teardownServerNative;
  final _FreeHandleDart _freeHandleNative;
  final _FreeStringDart _freeStringNative;

  static ChimeraBindings? _instance;

  /// open loads chimera.dll once and caches the bindings. Each isolate that
  /// calls a blocking function (StartFD/StartSocks) must call this again --
  /// DynamicLibrary handles aren't shared across isolates, only the plain-int
  /// tunnel handle is (see ChimeraService).
  factory ChimeraBindings.open() {
    return _instance ??= ChimeraBindings._(_loadLibrary());
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isWindows) {
      return DynamicLibrary.open('chimera.dll');
    }
    throw UnsupportedError(
      'ChimeraBindings: only Windows is wired up (desktop/cffi Windows-only for this cut)',
    );
  }

  /// _takeString copies a native UTF-8 string to Dart and frees the native
  /// buffer -- the ownership contract every export in desktop/cffi/main.go
  /// documents.
  String _takeString(Pointer<Utf8> p) {
    final s = p.toDartString();
    _freeStringNative(p);
    return s;
  }

  @override
  String newTunnel(String subscriptionText, String signKeyHex) {
    final subPtr = subscriptionText.toNativeUtf8();
    final keyPtr = signKeyHex.toNativeUtf8();
    try {
      return _takeString(_newTunnelNative(subPtr, keyPtr));
    } finally {
      calloc.free(subPtr);
      calloc.free(keyPtr);
    }
  }

  @override
  String newTunnelFromLink(String uri) {
    final uriPtr = uri.toNativeUtf8();
    try {
      return _takeString(_newTunnelFromLinkNative(uriPtr));
    } finally {
      calloc.free(uriPtr);
    }
  }

  @override
  String connect(int handle) => _takeString(_connectNative(handle));

  @override
  String startFD(int handle, int fd, int mtu) =>
      _takeString(_startFDNative(handle, fd, mtu));

  @override
  String startSocks(int handle, String listen) {
    final listenPtr = listen.toNativeUtf8();
    try {
      return _takeString(_startSocksNative(handle, listenPtr));
    } finally {
      calloc.free(listenPtr);
    }
  }

  @override
  void stop(int handle) => _stopNative(handle);

  @override
  String stateJSON(int handle) => _takeString(_stateJSONNative(handle));

  @override
  String parseLink(String uri) {
    final uriPtr = uri.toNativeUtf8();
    try {
      return _takeString(_parseLinkNative(uriPtr));
    } finally {
      calloc.free(uriPtr);
    }
  }

  @override
  String deployServer(String specJson) {
    final specPtr = specJson.toNativeUtf8();
    try {
      return _takeString(_deployServerNative(specPtr));
    } finally {
      calloc.free(specPtr);
    }
  }

  @override
  String teardownServer(String specJson) {
    final specPtr = specJson.toNativeUtf8();
    try {
      return _takeString(_teardownServerNative(specPtr));
    } finally {
      calloc.free(specPtr);
    }
  }

  @override
  void freeHandle(int handle) => _freeHandleNative(handle);
}
