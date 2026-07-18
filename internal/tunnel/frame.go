package tunnel

import (
	"errors"
	"io"

	"chimera/internal/padding"
)

const (
	CmdPing     byte = 0x00
	CmdConnect  byte = 0x01
	CmdUDPAssoc byte = 0x02

	CmdConnectRUDP byte = 0x03

	CmdAuthToken byte = 0x04

	StatusOK   byte = 0x01
	StatusFail byte = 0x00
)

const AssocIDLen = 2

var (
	errHostTooLong  = errors.New("tunnel: host longer than 255 bytes")
	errBadCommand   = errors.New("tunnel: unknown command")
	errShortFrame   = errors.New("tunnel: truncated control frame")
	errTokenTooLong = errors.New("tunnel: token longer than 65535 bytes")
)

type Session struct {
	send *padding.Stream
	recv *padding.Stream
}

func ClientSession(secret []byte) *Session {
	return &Session{
		send: padding.New(secret, padding.ClientToServer),
		recv: padding.New(secret, padding.ServerToClient),
	}
}

func ServerSession(secret []byte) *Session {
	return &Session{
		send: padding.New(secret, padding.ServerToClient),
		recv: padding.New(secret, padding.ClientToServer),
	}
}

func (s *Session) WritePing(w io.Writer) error {
	return padding.WriteFrame(w, s.send, []byte{CmdPing})
}

func (s *Session) WriteConnect(w io.Writer, host string, port uint16) error {
	return s.writeAddrCmd(w, CmdConnect, host, port)
}

func (s *Session) WriteConnectRUDP(w io.Writer, host string, port uint16) error {
	return s.writeAddrCmd(w, CmdConnectRUDP, host, port)
}

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

func (s *Session) WriteAuthToken(w io.Writer, token string) error {
	if len(token) > 0xFFFF {
		return errTokenTooLong
	}
	b := make([]byte, 0, 3+len(token))
	b = append(b, CmdAuthToken, byte(len(token)>>8), byte(len(token)))
	b = append(b, token...)
	return padding.WriteFrame(w, s.send, b)
}

func (s *Session) ReadAuthToken(r io.Reader) (token string, err error) {
	payload, err := padding.ReadFrame(r, s.recv)
	if err != nil {
		return "", err
	}
	if len(payload) < 3 || payload[0] != CmdAuthToken {
		return "", errBadCommand
	}
	tokenLen := int(payload[1])<<8 | int(payload[2])
	if len(payload) != 3+tokenLen {
		return "", errShortFrame
	}
	return string(payload[3 : 3+tokenLen]), nil
}

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

func WrapDatagram(assocID uint16, payload []byte) []byte {
	out := make([]byte, AssocIDLen+len(payload))
	out[0] = byte(assocID >> 8)
	out[1] = byte(assocID)
	copy(out[AssocIDLen:], payload)
	return out
}

func UnwrapDatagram(raw []byte) (assocID uint16, payload []byte, ok bool) {
	if len(raw) < AssocIDLen {
		return 0, nil, false
	}
	return uint16(raw[0])<<8 | uint16(raw[1]), raw[AssocIDLen:], true
}

func (s *Session) WriteStatus(w io.Writer, ok bool) error {
	b := StatusFail
	if ok {
		b = StatusOK
	}
	return padding.WriteFrame(w, s.send, []byte{b})
}

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
