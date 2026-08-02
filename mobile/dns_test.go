package mobile

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func buildTestQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	msg := binary.BigEndian.AppendUint16(nil, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = append(msg, make([]byte, 6)...)
	for _, label := range splitLabels(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	return msg
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func TestDNSRoundtripA(t *testing.T) {
	msg := buildTestQuery(t, 0x1234, "example.com", dnsTypeA)

	q, err := parseDNSQuery(msg)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if q.id != 0x1234 || q.name != "example.com" || q.qtype != dnsTypeA || !q.recurse {
		t.Fatalf("query mismatch: %+v", q)
	}

	ips := []netip.Addr{
		netip.MustParseAddr("93.184.216.34"),
		netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"),
	}
	resp := buildDNSResponse(q, ips, dnsRcodeOK)

	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Fatalf("response id mismatch: %#x", got)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 || flags&0x0100 == 0 {
		t.Fatalf("response flags missing QR/RD: %#x", flags)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Fatalf("want 1 answer (v6 filtered out), got %d", got)
	}
	if string(resp[12:12+len(q.question)]) != string(q.question) {
		t.Fatal("question section not echoed")
	}

	rr := resp[12+len(q.question):]
	if rr[0] != 0xC0 || rr[1] != 0x0C {
		t.Fatalf("answer name must be a pointer to the question: %v", rr[:2])
	}
	if got := binary.BigEndian.Uint16(rr[2:4]); got != dnsTypeA {
		t.Fatalf("answer type mismatch: %d", got)
	}
	if got := binary.BigEndian.Uint16(rr[10:12]); got != 4 {
		t.Fatalf("rdlength mismatch: %d", got)
	}
	if !netip.AddrFrom4([4]byte(rr[12:16])).Is4() || rr[12] != 93 {
		t.Fatalf("answer rdata mismatch: %v", rr[12:16])
	}
}

func TestDNSRoundtripAAAA(t *testing.T) {
	msg := buildTestQuery(t, 0xBEEF, "example.com", dnsTypeAAAA)

	q, err := parseDNSQuery(msg)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}

	ip := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")
	resp := buildDNSResponse(q, []netip.Addr{ip}, dnsRcodeOK)

	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0xBEEF {
		t.Fatalf("response id mismatch: %#x", got)
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Fatalf("want 1 answer, got %d", got)
	}

	rr := resp[12+len(q.question):]
	if got := binary.BigEndian.Uint16(rr[2:4]); got != dnsTypeAAAA {
		t.Fatalf("answer type mismatch: %d", got)
	}
	if got := binary.BigEndian.Uint16(rr[10:12]); got != 16 {
		t.Fatalf("rdlength mismatch: %d", got)
	}
	addr, ok := netip.AddrFromSlice(rr[12:28])
	if !ok || addr != ip {
		t.Fatalf("answer rdata mismatch: %v", rr[12:28])
	}
}

func TestParseDNSQueryRejects(t *testing.T) {
	if _, err := parseDNSQuery([]byte{0, 1, 0}); err == nil {
		t.Fatal("expected error for short message")
	}

	compressed := buildTestQuery(t, 1, "example.com", dnsTypeA)
	compressed[12] = 0xC0
	compressed[13] = 0x0C
	if _, err := parseDNSQuery(compressed); err == nil {
		t.Fatal("expected error for compressed name in query")
	}
}
