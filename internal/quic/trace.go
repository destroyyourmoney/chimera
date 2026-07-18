//go:build chimera_quic

package quic

import "sync"

var initialCryptoDataTracer struct {
	sync.RWMutex
	fn func([]byte)
}

var initialPacketTracer struct {
	sync.RWMutex
	fn func(InitialPacketSummary)
}

func SetInitialCryptoDataTracer(fn func([]byte)) func() {
	initialCryptoDataTracer.Lock()
	prev := initialCryptoDataTracer.fn
	initialCryptoDataTracer.fn = fn
	initialCryptoDataTracer.Unlock()
	return func() {
		initialCryptoDataTracer.Lock()
		initialCryptoDataTracer.fn = prev
		initialCryptoDataTracer.Unlock()
	}
}

func currentInitialCryptoDataTracer() func([]byte) {
	initialCryptoDataTracer.RLock()
	fn := initialCryptoDataTracer.fn
	initialCryptoDataTracer.RUnlock()
	if fn == nil {
		return nil
	}
	return func(p []byte) { fn(append([]byte(nil), p...)) }
}

func SetInitialPacketTracer(fn func(InitialPacketSummary)) func() {
	initialPacketTracer.Lock()
	prev := initialPacketTracer.fn
	initialPacketTracer.fn = fn
	initialPacketTracer.Unlock()
	return func() {
		initialPacketTracer.Lock()
		initialPacketTracer.fn = prev
		initialPacketTracer.Unlock()
	}
}

func currentInitialPacketTracer() func(InitialPacketSummary) {
	initialPacketTracer.RLock()
	fn := initialPacketTracer.fn
	initialPacketTracer.RUnlock()
	return fn
}
