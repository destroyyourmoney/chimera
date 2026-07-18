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

abstract class ChimeraNativeApi {
  String newTunnel(String subscriptionText, String signKeyHex);
  String newTunnelFromLink(String uri);
  String connect(int handle);
  String startFD(int handle, int fd, int mtu);
  String startSocks(int handle, String listen);
  void stop(int handle);
  String stateJSON(int handle);
  String parseLink(String uri);

  String deployServer(String specJson);

  String teardownServer(String specJson);
  void freeHandle(int handle);
}

class AndroidNoPreflightNativeApi implements ChimeraNativeApi {
  const AndroidNoPreflightNativeApi();

  @override
  String newTunnel(String subscriptionText, String signKeyHex) =>
      '{"handle":0,"error":""}';
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
