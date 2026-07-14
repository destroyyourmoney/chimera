// Command cffi is the C ABI boundary CHIMERA's desktop Flutter app calls via
// dart:ffi (docs/app/build-runbook.md Phase 3). It is a thin cgo wrapper
// around mobile.Tunnel — the same facade already bound into the Android AAR
// via gomobile (mobile/bind.go) — so both platforms share one lifecycle and
// one JSON state-snapshot shape; only the FFI mechanism differs.
//
// Build (produces chimera.h + chimera.a/.lib next to this file):
//
//	CGO_ENABLED=1 go build -buildmode=c-archive \
//	  -tags "chimera_utls chimera_quic chimera_netstack" \
//	  -o chimera.a ./desktop/cffi
//
// Requires a C compiler (CGO_ENABLED=1) — this package cannot build with the
// default CGO_ENABLED=0 toolchain, same as any cgo package.
//
// Handle lifecycle: ChimeraNewTunnel/ChimeraNewTunnelFromLink return an
// envelope carrying an opaque int64 handle; every other handle-taking
// function accepts that value. ChimeraFreeHandle stops the tunnel and
// releases the handle — call it exactly once when the Dart side is done with
// a tunnel. Every *C.char this package returns is heap-allocated with
// C.CString and MUST be released by the caller via ChimeraFreeString once
// its contents have been copied out (standard cgo/dart:ffi convention).
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"runtime/cgo"
	"unsafe"

	mobile "chimera/mobile"
)

func main() {}

// cString allocates a C string the caller must free via ChimeraFreeString.
func cString(s string) *C.char { return C.CString(s) }

// cGoString and cLonglong are tiny cgo-type helpers so tests in this package
// don't need their own "import C" (and its C preamble) duplicated.
func cGoString(s *C.char) string   { return C.GoString(s) }
func cLonglong(h int64) C.longlong { return C.longlong(h) }

// handleEnvelope is the JSON shape returned by the two constructors: a
// positive handle on success, or a zero handle with an error message.
type handleEnvelope struct {
	Handle int64  `json:"handle"`
	Error  string `json:"error"`
}

func newHandleJSON(t *mobile.Tunnel, err error) *C.char {
	env := handleEnvelope{}
	if err != nil {
		env.Error = err.Error()
	} else {
		env.Handle = int64(cgo.NewHandle(t))
	}
	b, _ := json.Marshal(env) // handleEnvelope always marshals cleanly
	return cString(string(b))
}

// tunnelFor resolves a handle to its *mobile.Tunnel, or nil if the handle is
// unknown/already freed (cgo.Handle panics on an invalid handle, so this
// recovers rather than letting a stale handle crash the caller).
func tunnelFor(h C.longlong) (t *mobile.Tunnel, ok bool) {
	defer func() {
		if recover() != nil {
			t, ok = nil, false
		}
	}()
	v := cgo.Handle(h).Value()
	t, ok = v.(*mobile.Tunnel)
	return t, ok
}

//export ChimeraNewTunnel
func ChimeraNewTunnel(subscriptionText, signKeyHex *C.char) *C.char {
	t, err := mobile.NewTunnel(C.GoString(subscriptionText), C.GoString(signKeyHex))
	return newHandleJSON(t, err)
}

//export ChimeraNewTunnelFromLink
func ChimeraNewTunnelFromLink(uri *C.char) *C.char {
	t, err := mobile.NewTunnelFromLink(C.GoString(uri))
	return newHandleJSON(t, err)
}

//export ChimeraConnect
func ChimeraConnect(handle C.longlong) *C.char {
	t, ok := tunnelFor(handle)
	if !ok {
		return cString("cffi: unknown handle")
	}
	if err := t.Connect(); err != nil {
		return cString(err.Error())
	}
	return cString("")
}

//export ChimeraStartFD
func ChimeraStartFD(handle C.longlong, fd, mtu C.int) *C.char {
	t, ok := tunnelFor(handle)
	if !ok {
		return cString("cffi: unknown handle")
	}
	if err := t.StartFD(int(fd), int(mtu)); err != nil {
		return cString(err.Error())
	}
	return cString("")
}

//export ChimeraStartSocks
func ChimeraStartSocks(handle C.longlong, listen *C.char) *C.char {
	t, ok := tunnelFor(handle)
	if !ok {
		return cString("cffi: unknown handle")
	}
	if err := t.StartSocks(C.GoString(listen)); err != nil {
		return cString(err.Error())
	}
	return cString("")
}

//export ChimeraStop
func ChimeraStop(handle C.longlong) {
	if t, ok := tunnelFor(handle); ok {
		t.Stop()
	}
}

//export ChimeraStateJSON
func ChimeraStateJSON(handle C.longlong) *C.char {
	t, ok := tunnelFor(handle)
	if !ok {
		return cString(`{"state":"disconnected","endpoints":[]}`)
	}
	return cString(t.StateJSON())
}

// linkEnvelope is the JSON shape ChimeraParseLink returns.
type linkEnvelope struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

//export ChimeraParseLink
func ChimeraParseLink(uri *C.char) *C.char {
	result, err := mobile.ParseLink(C.GoString(uri))
	env := linkEnvelope{Result: result}
	if err != nil {
		env.Error = err.Error()
	}
	b, _ := json.Marshal(env) // linkEnvelope always marshals cleanly
	return cString(string(b))
}

// deployEnvelope is the JSON shape ChimeraDeployServer returns.
type deployEnvelope struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

//export ChimeraDeployServer
func ChimeraDeployServer(specJSON *C.char) *C.char {
	result, err := mobile.DeployServer(C.GoString(specJSON))
	env := deployEnvelope{Result: result}
	if err != nil {
		env.Error = err.Error()
	}
	b, _ := json.Marshal(env) // deployEnvelope always marshals cleanly
	return cString(string(b))
}

//export ChimeraFreeHandle
func ChimeraFreeHandle(handle C.longlong) {
	h := cgo.Handle(handle)
	if t, ok := tunnelFor(handle); ok {
		t.Stop()
	}
	defer func() { recover() }() // Delete panics on an already-deleted handle
	h.Delete()
}

//export ChimeraFreeString
func ChimeraFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
