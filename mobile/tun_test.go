package mobile

import (
	"bytes"
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	testSrcAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	testDstAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

func tcpPacket(dstAddr tcpip.Address, srcPort, dstPort uint16, seqNum, ackNum uint32, flags header.TCPFlags) []byte {
	tcpSeg := header.TCP(make([]byte, header.TCPMinimumSize))
	tcpSeg.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqNum,
		AckNum:     ackNum,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, testSrcAddr, dstAddr, uint16(len(tcpSeg)))
	tcpSeg.SetChecksum(^tcpSeg.CalculateChecksum(xsum))

	ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + len(tcpSeg)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     testSrcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	return append(ip, tcpSeg...)
}

func inject(linkEP *channel.Endpoint, packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	linkEP.InjectInbound(ipv4.ProtocolNumber, pkt)
}

func TestTCPForwarderHandsConnection(t *testing.T) {
	handled := make(chan string, 1)
	linkEP := channel.New(10, tunMTU, "")
	s, err := newStack(linkEP, func(conn net.Conn, targetAddr string) {
		handled <- targetAddr
		conn.Close()
	}, "")
	if err != nil {
		t.Fatalf("newStack: %v", err)
	}
	defer s.Close()

	inject(linkEP, tcpPacket(testDstAddr, 40000, 80, 1, 0, header.TCPFlagSyn))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := linkEP.ReadContext(ctx)
	if out == nil {
		t.Fatal("no SYN-ACK from the stack")
	}
	synAck := header.TCP(out.TransportHeader().Slice())
	if !synAck.Flags().Contains(header.TCPFlagSyn | header.TCPFlagAck) {
		t.Fatalf("expected SYN-ACK, got flags %s", synAck.Flags())
	}
	out.DecRef()

	inject(linkEP, tcpPacket(testDstAddr, 40000, 80, 2, synAck.SequenceNumber()+1, header.TCPFlagAck))

	select {
	case target := <-handled:
		if target != "10.0.0.2:80" {
			t.Fatalf("unexpected target: %s", target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TCP connection was not handed to the handler")
	}
}

func tunDispatcherRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return bytes.Contains(buf[:n], []byte("fdbased.(*endpoint).dispatchLoop"))
}

func TestTunCloseStopsDispatcher(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer peer.Close()

	tun, err := newTunDevice(fds[0], func(conn net.Conn, _ string) { conn.Close() }, "")
	if err != nil {
		t.Fatalf("newTunDevice: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !tunDispatcherRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tunDispatcherRunning() {
		t.Fatal("tun dispatcher is not running after newTunDevice")
	}

	start := time.Now()
	tun.close()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("close took %v on an idle tunnel", elapsed)
	}
	if tunDispatcherRunning() {
		t.Fatal("tun dispatcher goroutine survived close")
	}
}

func TestTunnelLocalAddressesAreReset(t *testing.T) {
	handled := make(chan string, 1)
	linkEP := channel.New(10, tunMTU, "")
	s, err := newStack(linkEP, func(conn net.Conn, targetAddr string) {
		handled <- targetAddr
		conn.Close()
	}, "")
	if err != nil {
		t.Fatalf("newStack: %v", err)
	}
	defer s.Close()

	dnsAddr := tcpip.AddrFrom4([4]byte{10, 127, 0, 2})
	inject(linkEP, tcpPacket(dnsAddr, 40000, 853, 1, 0, header.TCPFlagSyn))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out := linkEP.ReadContext(ctx)
	if out == nil {
		t.Fatal("no RST from the stack")
	}
	reply := header.TCP(out.TransportHeader().Slice())
	if !reply.Flags().Contains(header.TCPFlagRst) {
		t.Fatalf("expected RST, got flags %s", reply.Flags())
	}
	out.DecRef()

	select {
	case target := <-handled:
		t.Fatalf("connection to tunnel-local address reached the handler: %s", target)
	case <-time.After(300 * time.Millisecond):
	}
}
