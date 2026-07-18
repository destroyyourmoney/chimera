//go:build chimera_quic

package quic

import "chimera/internal/carrier"

func init() {
	carrier.QUICDialConnect = DialConnect
	carrier.QUICDialConnectRUDP = DialConnectRUDP
	carrier.QUICPing = Ping
	carrier.QUICServe = Run
	carrier.QUICDialUDP = DialUDP
}
