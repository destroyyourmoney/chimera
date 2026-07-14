//go:build chimera_quic

package quic

import "chimera/internal/carrier"

// init wires the QUIC carrier into the transport registry. It runs only when the
// binary is built with -tags chimera_quic; the default build leaves the carrier
// hooks nil, and requesting the QUIC transport then reports a clear error.
func init() {
	carrier.QUICDialConnect = DialConnect
	carrier.QUICDialConnectRUDP = DialConnectRUDP
	carrier.QUICPing = Ping
	carrier.QUICServe = Run
	carrier.QUICDialUDP = DialUDP
}
