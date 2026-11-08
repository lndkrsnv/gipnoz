package mobile

import (
	"fmt"
	"net"
	"os"
	"slices"
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

var tunnelLocalAddrs = []tcpip.Address{
	tcpip.AddrFrom4([4]byte{10, 127, 0, 1}),
	tcpip.AddrFrom4([4]byte{10, 127, 0, 2}),
	tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
}

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

	s, err := newStack(linkEP, handleTCP, dohURL)
	if err != nil {
		file.Close()
		return nil, err
	}
	return &tunDevice{file: file, stack: s}, nil
}

func newStack(linkEP stack.LinkEndpoint, handleTCP func(conn net.Conn, targetAddr string), dohURL string) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if tcpipErr := s.CreateNIC(tunNIC, linkEP); tcpipErr != nil {
		return nil, fmt.Errorf("create nic: %s", tcpipErr)
	}
	if tcpipErr := s.SetPromiscuousMode(tunNIC, true); tcpipErr != nil {
		return nil, fmt.Errorf("promiscuous mode: %s", tcpipErr)
	}
	if tcpipErr := s.SetSpoofing(tunNIC, true); tcpipErr != nil {
		return nil, fmt.Errorf("spoofing: %s", tcpipErr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: tunNIC},
		{Destination: header.IPv6EmptySubnet, NIC: tunNIC},
	})

	dns := newDNSProxy(dohURL)

	tcpForwarder := tcp.NewForwarder(s, 0, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		if slices.Contains(tunnelLocalAddrs, id.LocalAddress) {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		target := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		go guardedRun("handleTCP", func() { handleTCP(gonet.NewTCPConn(&wq, ep), target) })
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
		go guardedRun("dns.serve", func() { dns.serve(gonet.NewUDPConn(&wq, ep)) })
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	return s, nil
}

func (t *tunDevice) close() {
	t.stack.Destroy()
	t.file.Close()
}
