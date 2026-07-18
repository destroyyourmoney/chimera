package socks

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"chimera/internal/carrier"
	"chimera/internal/endpoint"
)

const maxUDPDatagram = 65535

type socksTarget struct {
	atyp byte
	host string
	port uint16
}

type udpRelay struct {
	relay *net.UDPConn
	uc    carrier.UDPCarrier

	mu            sync.Mutex
	clientAddr    *net.UDPAddr
	assocByTarget map[string]uint16
	targetByAssoc map[uint16]socksTarget
}

func serveUDPAssoc(ctrl net.Conn, ud endpoint.UDPDialer) {
	localIP := net.IPv4(127, 0, 0, 1)
	if ta, ok := ctrl.LocalAddr().(*net.TCPAddr); ok && ta.IP != nil {
		localIP = ta.IP
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: 0})
	if err != nil {
		_, _ = ctrl.Write([]byte{0x05, repGenFail, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer relay.Close()

	uc, err := ud.DialUDPCarrier()
	if err != nil {
		slog.Warn("socks udp: carrier dial failed", "err", err)
		_, _ = ctrl.Write([]byte{0x05, repGenFail, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer uc.Close()

	if err := writeUDPAssocReply(ctrl, relay.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}

	r := &udpRelay{
		relay:         relay,
		uc:            uc,
		assocByTarget: map[string]uint16{},
		targetByAssoc: map[uint16]socksTarget{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = relay.Close()
		_ = uc.Close()
	}()
	go r.inboundLoop(ctx)
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		cancel()
	}()
	r.outboundLoop()
}

func (r *udpRelay) outboundLoop() {
	buf := make([]byte, maxUDPDatagram)
	for {
		n, src, err := r.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		r.setClient(src)
		atyp, host, port, data, ok := decodeUDPHeader(buf[:n])
		if !ok {
			continue
		}
		assocID, err := r.assocFor(host, port, atyp)
		if err != nil {
			slog.Debug("socks udp: open assoc failed", "target", host, "port", port, "err", err)
			continue
		}
		if err := r.uc.Send(assocID, data); err != nil {
			slog.Debug("socks udp: send failed", "assoc", assocID, "err", err)
		}
	}
}

func (r *udpRelay) inboundLoop(ctx context.Context) {
	for {
		assocID, payload, err := r.uc.Receive(ctx)
		if err != nil {
			return
		}
		tgt, ok := r.targetForAssoc(assocID)
		if !ok {
			continue
		}
		client := r.client()
		if client == nil {
			continue
		}
		_, _ = r.relay.WriteToUDP(encodeUDPHeader(tgt, payload), client)
	}
}

func (r *udpRelay) assocFor(host string, port uint16, atyp byte) (uint16, error) {
	key := net.JoinHostPort(host, strconv.Itoa(int(port)))
	r.mu.Lock()
	if id, ok := r.assocByTarget[key]; ok {
		r.mu.Unlock()
		return id, nil
	}
	r.mu.Unlock()

	id, err := r.uc.OpenAssoc(host, port)
	if err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.assocByTarget[key] = id
	r.targetByAssoc[id] = socksTarget{atyp: atyp, host: host, port: port}
	r.mu.Unlock()
	return id, nil
}

func (r *udpRelay) targetForAssoc(id uint16) (socksTarget, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.targetByAssoc[id]
	return t, ok
}

func (r *udpRelay) setClient(a *net.UDPAddr) {
	r.mu.Lock()
	if r.clientAddr == nil {
		r.clientAddr = a
	}
	r.mu.Unlock()
}

func (r *udpRelay) client() *net.UDPAddr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientAddr
}

func writeUDPAssocReply(ctrl net.Conn, addr *net.UDPAddr) error {
	reply := []byte{0x05, repSucceeded, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		reply = append(reply, atypIPv4)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, atypIPv6)
		reply = append(reply, addr.IP.To16()...)
	}
	reply = append(reply, byte(addr.Port>>8), byte(addr.Port))
	_, err := ctrl.Write(reply)
	return err
}

func decodeUDPHeader(b []byte) (atyp byte, host string, port uint16, data []byte, ok bool) {
	if len(b) < 4 || b[2] != 0x00 {
		return 0, "", 0, nil, false
	}
	atyp = b[3]
	off := 4
	switch atyp {
	case atypIPv4:
		if len(b) < off+4+2 {
			return 0, "", 0, nil, false
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case atypDomain:
		if len(b) < off+1 {
			return 0, "", 0, nil, false
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return 0, "", 0, nil, false
		}
		host = string(b[off : off+l])
		off += l
	case atypIPv6:
		if len(b) < off+16+2 {
			return 0, "", 0, nil, false
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	default:
		return 0, "", 0, nil, false
	}
	port = uint16(b[off])<<8 | uint16(b[off+1])
	off += 2
	return atyp, host, port, b[off:], true
}

func encodeUDPHeader(t socksTarget, data []byte) []byte {
	out := []byte{0x00, 0x00, 0x00, t.atyp}
	switch t.atyp {
	case atypIPv4:
		if ip := net.ParseIP(t.host).To4(); ip != nil {
			out = append(out, ip...)
		} else {
			out = append(out, 0, 0, 0, 0)
		}
	case atypIPv6:
		if ip := net.ParseIP(t.host).To16(); ip != nil {
			out = append(out, ip...)
		} else {
			out = append(out, make([]byte, 16)...)
		}
	case atypDomain:
		out = append(out, byte(len(t.host)))
		out = append(out, t.host...)
	}
	out = append(out, byte(t.port>>8), byte(t.port))
	return append(out, data...)
}
