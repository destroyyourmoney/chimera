package vision

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func makeReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func TestClassify_TLS12ClientHello(t *testing.T) {

	raw := []byte{0x16, 0x03, 0x01, 0x00, 0xf1, 0x01, 0x00, 0x00}
	if got := Classify(makeReader(raw)); got != FlowTLS {
		t.Fatalf("expected FlowTLS, got %v", got)
	}
}

func TestClassify_TLS13ClientHello(t *testing.T) {

	raw := []byte{0x16, 0x03, 0x01, 0x01, 0x00, 0x01}
	if got := Classify(makeReader(raw)); got != FlowTLS {
		t.Fatalf("expected FlowTLS, got %v", got)
	}
}

func TestClassify_PlainHTTP(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n")
	if got := Classify(makeReader(raw)); got != FlowPlain {
		t.Fatalf("expected FlowPlain, got %v", got)
	}
}

func TestClassify_TooShort(t *testing.T) {
	raw := []byte{0x16, 0x03}
	if got := Classify(makeReader(raw)); got != FlowUnknown {
		t.Fatalf("expected FlowUnknown for short input, got %v", got)
	}
}

func TestClassify_DoesNotConsumeBytes(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\n")
	br := makeReader(raw)
	_ = Classify(br)

	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("Classify consumed bytes: got %q want %q", got, raw)
	}
}

func TestClassify_TLSBytesPreservedAfterClassify(t *testing.T) {
	raw := []byte{0x16, 0x03, 0x01, 0x00, 0xf1, 0x01, 0xAA, 0xBB}
	br := makeReader(raw)
	flow := Classify(br)
	if flow != FlowTLS {
		t.Fatalf("expected FlowTLS, got %v", flow)
	}
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("bytes consumed by Classify: got %q want %q", got, raw)
	}
}
