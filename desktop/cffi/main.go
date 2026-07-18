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

func cString(s string) *C.char { return C.CString(s) }

func cGoString(s *C.char) string   { return C.GoString(s) }
func cLonglong(h int64) C.longlong { return C.longlong(h) }

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
	b, _ := json.Marshal(env)
	return cString(string(b))
}

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
	b, _ := json.Marshal(env)
	return cString(string(b))
}

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
	b, _ := json.Marshal(env)
	return cString(string(b))
}

//export ChimeraTeardownServer
func ChimeraTeardownServer(specJSON *C.char) *C.char {
	result, err := mobile.TeardownServer(C.GoString(specJSON))
	env := deployEnvelope{Result: result}
	if err != nil {
		env.Error = err.Error()
	}
	b, _ := json.Marshal(env)
	return cString(string(b))
}

//export ChimeraFreeHandle
func ChimeraFreeHandle(handle C.longlong) {
	h := cgo.Handle(handle)
	if t, ok := tunnelFor(handle); ok {
		t.Stop()
	}
	defer func() { recover() }()
	h.Delete()
}

//export ChimeraFreeString
func ChimeraFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
