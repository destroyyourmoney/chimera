package preconnect

import (
	"net"
	"testing"
	"time"
)

func TestIsAlive_OpenIdleConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(200 * time.Millisecond)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if !isAlive(c) {
		t.Fatal("an open connection with no data waiting must be reported alive")
	}
}

func TestIsAlive_PeerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	time.Sleep(50 * time.Millisecond)
	if isAlive(c) {
		t.Fatal("a connection the peer already closed must be reported dead, not alive")
	}
}

func TestIsAlive_DataAlreadyWaiting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			_, _ = c.Write([]byte("x"))
			time.Sleep(200 * time.Millisecond)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	time.Sleep(50 * time.Millisecond)
	if isAlive(c) {
		t.Fatal("a connection with unsolicited data waiting must not be handed out as-is")
	}
}

func TestIsAlive_ReadDeadlineIsResetAfterCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(100 * time.Millisecond)
			_, _ = c.Write([]byte("late"))
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if !isAlive(c) {
		t.Fatal("expected alive: no data waiting yet at check time")
	}

	buf := make([]byte, 4)
	if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("read after isAlive should not be affected by its short deadline: %v", err)
	}
}
