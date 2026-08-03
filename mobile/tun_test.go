package mobile

import (
	"context"
	"net"
	"testing"
	"time"

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

func tcpPacket(srcPort, dstPort uint16, seqNum, ackNum uint32, flags header.TCPFlags) []byte {
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
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, testSrcAddr, testDstAddr, uint16(len(tcpSeg)))
	tcpSeg.SetChecksum(^tcpSeg.CalculateChecksum(xsum))

	ip := header.IPv4(make([]byte, header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + len(tcpSeg)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     testSrcAddr,
		DstAddr:     testDstAddr,
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

	inject(linkEP, tcpPacket(40000, 80, 1, 0, header.TCPFlagSyn))

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

	inject(linkEP, tcpPacket(40000, 80, 2, synAck.SequenceNumber()+1, header.TCPFlagAck))

	select {
	case target := <-handled:
		if target != "10.0.0.2:80" {
			t.Fatalf("unexpected target: %s", target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TCP connection was not handed to the handler")
	}
}
