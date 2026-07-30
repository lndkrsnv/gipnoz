package client

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestSocks5HandshakeDomain(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	type result struct {
		addr string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		addr, err := socks5Handshake(p1)
		ch <- result{addr, err}
	}()

	if _, err := p2.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(p2, rep); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("method reply mismatch: %v", rep)
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	req = append(req, "example.com"...)
	req = append(req, 0x01, 0xBB)
	if _, err := p2.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(p2, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("want success reply, got REP=%d", reply[1])
	}

	r := <-ch
	if r.err != nil {
		t.Fatalf("handshake error: %v", r.err)
	}
	if r.addr != "example.com:443" {
		t.Fatalf("target mismatch: %q", r.addr)
	}
}

func TestSocks5HandshakeBadVersion(t *testing.T) {
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	if err := p2.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	ch := make(chan error, 1)
	go func() {
		_, err := socks5Handshake(p1)
		ch <- err
	}()

	if _, err := p2.Write([]byte{0x04, 0x01}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if err := <-ch; err == nil {
		t.Fatal("expected error for SOCKS4 greeting")
	}
}
