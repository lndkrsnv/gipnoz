package mobile

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	tunMTU = 1500
	tunNIC = tcpip.NICID(1)
)

type tunDevice struct {
	file  *os.File
	stack *stack.Stack
}

func newTunDevice(fd int, handleTCP func(conn net.Conn, targetAddr string), dohURL string) (*tunDevice, error) {
	file := os.NewFile(uintptr(fd), "tun")
	if file == nil {
		return nil, fmt.Errorf("invalid tun fd: %d", fd)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: tunMTU,
	})
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("link endpoint: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if tcpipErr := s.CreateNIC(tunNIC, linkEP); tcpipErr != nil {
		file.Close()
		return nil, fmt.Errorf("create nic: %s", tcpipErr)
	}
	if tcpipErr := s.SetPromiscuousMode(tunNIC, true); tcpipErr != nil {
		file.Close()
		return nil, fmt.Errorf("promiscuous mode: %s", tcpipErr)
	}
	if tcpipErr := s.SetSpoofing(tunNIC, true); tcpipErr != nil {
		file.Close()
		return nil, fmt.Errorf("spoofing: %s", tcpipErr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: tunNIC},
		{Destination: header.IPv6EmptySubnet, NIC: tunNIC},
	})

	dns := newDNSProxy(dohURL)

	tcpForwarder := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		id := r.ID()
		target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go handleTCP(gonet.NewTCPConn(&wq, ep), target)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		if r.ID().LocalPort != 53 {
			return false
		}
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			return true
		}
		go dns.serve(gonet.NewUDPConn(&wq, ep))
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return &tunDevice{file: file, stack: s}, nil
}

func (t *tunDevice) close() {
	t.stack.Close()
	t.file.Close()
}
