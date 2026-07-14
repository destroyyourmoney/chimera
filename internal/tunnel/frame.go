// Package tunnel defines the CHIMERA inner request protocol that runs over an
// established carrier connection (after authentication). It is deliberately
// transport-agnostic: in the PoC it runs over the post-handshake TCP stream;
// in production it runs INSIDE the Reality-hijacked TLS session (Phase 1b), so
// none of these bytes are ever visible on the wire.
//
// Each control message (the client's PING/CONNECT request and the server's
// status reply) is wrapped in a seeded-padding frame (package padding) so its
// tiny, fixed length is hidden behind a TLS-record-plausible size. The padding
// stream is derived from the handshake shared secret, one per direction, and
// advances in lockstep with the peer — see ClientSession/ServerSession.
//
// Logical message format (inside the padded frame):
//
//	PING:     0x00
//	CONNECT:  0x01 | hostLen(1) | host | port(2, big-endian)
//
// Reply: single status byte, 0x01 = ok, 0x00 = fail.
package tunnel

import (
	"errors"
	"io"

	"chimera/internal/padding"
)

const (
	CmdPing     byte = 0x00
	CmdConnect  byte = 0x01
	CmdUDPAssoc byte = 0x02 // request a UDP datagram association (RFC 9221 path)
	// CmdConnectRUDP requests a TCP CONNECT whose bulk relay rides the reliable-
	// FEC datagram transport (internal/rudp) over the QUIC DATAGRAM channel
	// instead of a reliable QUIC stream. Same host/port framing as CmdConnect.
	CmdConnectRUDP byte = 0x03

	StatusOK   byte = 0x01
	StatusFail byte = 0x00
)

// AssocIDLen is the prefix length (bytes) for each QUIC datagram payload.
// Format: [assocID(2) | udpPayload...]
const AssocIDLen = 2

var (
	errHostTooLong = errors.New("tunnel: host longer than 255 bytes")
	errBadCommand  = errors.New("tunnel: unknown command")
	errShortFrame  = errors.New("tunnel: truncated control frame")
)

// Session holds the two per-direction padding streams for one carrier.
type Session struct {
	send *padding.Stream
	recv *padding.Stream
}

// ClientSession derives the client's view: it sends on the client→server stream
// and receives on the server→client stream.
func ClientSession(secret []byte) *Session {
	return &Session{
		send: padding.New(secret, padding.ClientToServer),
		recv: padding.New(secret, padding.ServerToClient),
	}
}

// ServerSession derives the mirror view used by the server.
func ServerSession(secret []byte) *Session {
	return &Session{
		send: padding.New(secret, padding.ServerToClient),
		recv: padding.New(secret, padding.ClientToServer),
	}
}

// WritePing sends a padded liveness probe (used by the client PoC).
func (s *Session) WritePing(w io.Writer) error {
	return padding.WriteFrame(w, s.send, []byte{CmdPing})
}

// WriteConnect sends a padded CONNECT request for host:port.
func (s *Session) WriteConnect(w io.Writer, host string, port uint16) error {
	return s.writeAddrCmd(w, CmdConnect, host, port)
}

// WriteConnectRUDP sends a padded CmdConnectRUDP request for host:port (the bulk
// relay will ride the reliable-FEC datagram transport, not a QUIC stream).
func (s *Session) WriteConnectRUDP(w io.Writer, host string, port uint16) error {
	return s.writeAddrCmd(w, CmdConnectRUDP, host, port)
}

// writeAddrCmd frames a command byte plus host:port (the shared CONNECT layout).
func (s *Session) writeAddrCmd(w io.Writer, cmd byte, host string, port uint16) error {
	if len(host) > 255 {
		return errHostTooLong
	}
	b := make([]byte, 0, 4+len(host))
	b = append(b, cmd, byte(len(host)))
	b = append(b, host...)
	b = append(b, byte(port>>8), byte(port))
	return padding.WriteFrame(w, s.send, b)
}

// ReadRequest reads one padded inner request from the carrier.
func (s *Session) ReadRequest(r io.Reader) (cmd byte, host string, port uint16, err error) {
	payload, err := padding.ReadFrame(r, s.recv)
	if err != nil {
		return 0, "", 0, err
	}
	if len(payload) < 1 {
		return 0, "", 0, errShortFrame
	}
	cmd = payload[0]
	switch cmd {
	case CmdPing:
		return cmd, "", 0, nil
	case CmdConnect, CmdUDPAssoc, CmdConnectRUDP:
		if len(payload) < 4 {
			return 0, "", 0, errShortFrame
		}
		hl := int(payload[1])
		if len(payload) != 2+hl+2 {
			return 0, "", 0, errShortFrame
		}
		host = string(payload[2 : 2+hl])
		port = uint16(payload[2+hl])<<8 | uint16(payload[3+hl])
		return cmd, host, port, nil
	default:
		return 0, "", 0, errBadCommand
	}
}

// WriteUDPAssoc sends a padded UDP association request for host:port.
// The server allocates a UDP socket and replies with WriteUDPAssocReply.
func (s *Session) WriteUDPAssoc(w io.Writer, host string, port uint16) error {
	if len(host) > 255 {
		return errHostTooLong
	}
	b := make([]byte, 0, 4+len(host))
	b = append(b, CmdUDPAssoc, byte(len(host)))
	b = append(b, host...)
	b = append(b, byte(port>>8), byte(port))
	return padding.WriteFrame(w, s.send, b)
}

// WriteUDPAssocReply sends the server's reply to a CmdUDPAssoc:
// assocID=0 on failure; the 16-bit assocID for use as datagram prefix on success.
// ok=false sends StatusFail with assocID=0.
func (s *Session) WriteUDPAssocReply(w io.Writer, ok bool, assocID uint16) error {
	var b [3]byte
	if ok {
		b[0] = StatusOK
		b[1] = byte(assocID >> 8)
		b[2] = byte(assocID)
	} else {
		b[0] = StatusFail
	}
	return padding.WriteFrame(w, s.send, b[:])
}

// ReadUDPAssocReply reads the server's reply to a CmdUDPAssoc.
// Returns ok=false on failure or parse error.
func (s *Session) ReadUDPAssocReply(r io.Reader) (ok bool, assocID uint16, err error) {
	payload, err := padding.ReadFrame(r, s.recv)
	if err != nil {
		return false, 0, err
	}
	if len(payload) < 1 {
		return false, 0, errShortFrame
	}
	if payload[0] != StatusOK {
		return false, 0, nil
	}
	if len(payload) < 3 {
		return false, 0, errShortFrame
	}
	assocID = uint16(payload[1])<<8 | uint16(payload[2])
	return true, assocID, nil
}

// WrapDatagram prepends the 2-byte assocID to payload for QUIC datagram sends.
func WrapDatagram(assocID uint16, payload []byte) []byte {
	out := make([]byte, AssocIDLen+len(payload))
	out[0] = byte(assocID >> 8)
	out[1] = byte(assocID)
	copy(out[AssocIDLen:], payload)
	return out
}

// UnwrapDatagram splits a raw QUIC datagram into assocID + payload.
// Returns ok=false if the datagram is too short.
func UnwrapDatagram(raw []byte) (assocID uint16, payload []byte, ok bool) {
	if len(raw) < AssocIDLen {
		return 0, nil, false
	}
	return uint16(raw[0])<<8 | uint16(raw[1]), raw[AssocIDLen:], true
}

// WriteStatus sends the padded single reply byte.
func (s *Session) WriteStatus(w io.Writer, ok bool) error {
	b := StatusFail
	if ok {
		b = StatusOK
	}
	return padding.WriteFrame(w, s.send, []byte{b})
}

// ReadStatus reads the padded reply byte.
func (s *Session) ReadStatus(r io.Reader) (bool, error) {
	payload, err := padding.ReadFrame(r, s.recv)
	if err != nil {
		return false, err
	}
	if len(payload) < 1 {
		return false, errShortFrame
	}
	return payload[0] == StatusOK, nil
}
