package mobile

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"gipnoz/internal/client"
)

const (
	dnsClassIN        = 1
	dnsTypeA          = 1
	dnsTypeAAAA       = 28
	dnsRcodeOK        = 0
	dnsRcodeFail      = 2
	dnsTTLSeconds     = 60
	dnsMaxMessageLen  = 2048
	dnsResolveTimeout = 5 * time.Second
)

type dnsProxy struct {
	resolve func(ctx context.Context, name string) ([]netip.Addr, error)
}

func newDNSProxy(dohURL string) *dnsProxy {
	if dohURL != "" {
		doh := client.NewDoHResolver(dohURL)
		return &dnsProxy{resolve: func(ctx context.Context, name string) ([]netip.Addr, error) {
			addrs, err := doh.LookupHost(ctx, name)
			if err != nil {
				return nil, err
			}
			return parseIPStrings(addrs)
		}}
	}
	slog.Warn("dns.doh is not configured; DNS queries from the tunnel use the system resolver")
	return &dnsProxy{resolve: func(ctx context.Context, name string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	}}
}

func (p *dnsProxy) serve(conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, dnsMaxMessageLen)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		resp := p.answer(buf[:n])
		if resp == nil {
			continue
		}
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

func (p *dnsProxy) answer(msg []byte) []byte {
	q, err := parseDNSQuery(msg)
	if err != nil {
		slog.Debug("dns proxy: bad query", "err", err)
		return nil
	}
	if q.qtype != dnsTypeA && q.qtype != dnsTypeAAAA {
		return buildDNSResponse(q, nil, dnsRcodeOK)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
	ips, err := p.resolve(ctx, q.name)
	cancel()
	if err != nil {
		slog.Debug("dns proxy: resolve failed", "name", q.name, "err", err)
		return buildDNSResponse(q, nil, dnsRcodeFail)
	}
	return buildDNSResponse(q, ips, dnsRcodeOK)
}

func parseIPStrings(addrs []string) ([]netip.Addr, error) {
	ips := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("parse address %q: %w", a, err)
		}
		ips = append(ips, ip.Unmap())
	}
	return ips, nil
}

type dnsQuery struct {
	id       uint16
	recurse  bool
	name     string
	qtype    uint16
	question []byte
}

func parseDNSQuery(msg []byte) (*dnsQuery, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns message too short: %d bytes", len(msg))
	}
	if qdcount := binary.BigEndian.Uint16(msg[4:6]); qdcount != 1 {
		return nil, fmt.Errorf("unsupported question count: %d", qdcount)
	}
	name, nameLen, err := parseDNSName(msg[12:])
	if err != nil {
		return nil, err
	}
	end := 12 + nameLen + 4
	if len(msg) < end {
		return nil, fmt.Errorf("truncated question")
	}
	return &dnsQuery{
		id:       binary.BigEndian.Uint16(msg[0:2]),
		recurse:  msg[2]&0x01 != 0,
		name:     name,
		qtype:    binary.BigEndian.Uint16(msg[12+nameLen : end]),
		question: msg[12:end],
	}, nil
}

func parseDNSName(data []byte) (string, int, error) {
	var labels []string
	i := 0
	for {
		if i >= len(data) {
			return "", 0, fmt.Errorf("truncated name")
		}
		l := int(data[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 {
			return "", 0, fmt.Errorf("compressed names not supported in queries")
		}
		i++
		if i+l > len(data) {
			return "", 0, fmt.Errorf("truncated label")
		}
		labels = append(labels, string(data[i:i+l]))
		i += l
	}
	return strings.Join(labels, "."), i, nil
}

func buildDNSResponse(q *dnsQuery, ips []netip.Addr, rcode uint16) []byte {
	var answers []netip.Addr
	for _, ip := range ips {
		if q.qtype == dnsTypeA && ip.Is4() || q.qtype == dnsTypeAAAA && ip.Is6() {
			answers = append(answers, ip)
		}
	}

	out := make([]byte, 0, 12+len(q.question)+len(answers)*28)
	out = binary.BigEndian.AppendUint16(out, q.id)
	flags := uint16(0x8000) | rcode
	if q.recurse {
		flags |= 0x0180
	}
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint16(out, 1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(answers)))
	out = append(out, make([]byte, 4)...)
	out = append(out, q.question...)
	for _, ip := range answers {
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, q.qtype)
		out = binary.BigEndian.AppendUint16(out, dnsClassIN)
		out = binary.BigEndian.AppendUint32(out, dnsTTLSeconds)
		if q.qtype == dnsTypeA {
			addr := ip.As4()
			out = binary.BigEndian.AppendUint16(out, 4)
			out = append(out, addr[:]...)
		} else {
			addr := ip.As16()
			out = binary.BigEndian.AppendUint16(out, 16)
			out = append(out, addr[:]...)
		}
	}
	return out
}
