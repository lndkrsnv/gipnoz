package routing

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix %q: %v", s, err)
	}
	return p
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr %q: %v", s, err)
	}
	return a
}

func TestCIDRMatcherV4(t *testing.T) {
	m := NewCIDRMatcher()
	if err := m.Add(mustPrefix(t, "10.0.0.0/8")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := m.Add(mustPrefix(t, "192.168.1.0/24")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	for _, ip := range []string{"10.1.2.3", "10.255.255.255", "192.168.1.42"} {
		if !m.Contains(mustAddr(t, ip)) {
			t.Fatalf("want match for %s", ip)
		}
	}
	for _, ip := range []string{"11.0.0.1", "192.168.2.1", "8.8.8.8"} {
		if m.Contains(mustAddr(t, ip)) {
			t.Fatalf("want no match for %s", ip)
		}
	}
}

func TestCIDRMatcherV6(t *testing.T) {
	m := NewCIDRMatcher()
	if err := m.Add(mustPrefix(t, "2001:db8::/32")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	if !m.Contains(mustAddr(t, "2001:db8::1")) {
		t.Fatal("want match inside v6 prefix")
	}
	if m.Contains(mustAddr(t, "2001:db9::1")) {
		t.Fatal("want no match outside v6 prefix")
	}
	if m.Contains(mustAddr(t, "10.0.0.1")) {
		t.Fatal("v4 address must not match v6-only matcher")
	}
}

func TestCIDRMatcherHostPrefix(t *testing.T) {
	m := NewCIDRMatcher()
	if err := m.Add(mustPrefix(t, "1.2.3.4/32")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !m.Contains(mustAddr(t, "1.2.3.4")) {
		t.Fatal("want match for host prefix")
	}
	if m.Contains(mustAddr(t, "1.2.3.5")) {
		t.Fatal("want no match for neighboring address")
	}
}

func TestCIDRMatcherEmpty(t *testing.T) {
	m := NewCIDRMatcher()
	if !m.Empty() {
		t.Fatal("new matcher must be empty")
	}
	if m.Contains(mustAddr(t, "1.2.3.4")) {
		t.Fatal("empty matcher must not match")
	}
}
