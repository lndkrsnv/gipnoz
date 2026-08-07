package routing

import (
	"net/netip"
	"testing"
)

func TestRouterModeDefaults(t *testing.T) {
	cases := []struct {
		mode Mode
		want Action
	}{
		{ModeProxyExceptDirect, Proxy},
		{ModeDirectExceptProxy, Direct},
	}
	for _, tc := range cases {
		r := New(Config{Mode: tc.mode})
		if got := r.Decide("example.com:443"); got != tc.want {
			t.Fatalf("mode %v: want %v, got %v", tc.mode, tc.want, got)
		}
	}
}

func TestRouterRuleOrder(t *testing.T) {
	proxyDomains := NewDomainMatcher()
	proxyDomains.Add("blocked.com")
	directDomains := NewDomainMatcher()
	directDomains.Add("trusted.ru")

	r := New(Config{
		Mode:          ModeDirectExceptProxy,
		ProxyDomains:  proxyDomains,
		DirectDomains: directDomains,
	})

	if got := r.Decide("blocked.com:443"); got != Proxy {
		t.Fatalf("proxy rule: want Proxy, got %v", got)
	}
	if got := r.Decide("www.blocked.com:443"); got != Proxy {
		t.Fatalf("proxy rule subdomain: want Proxy, got %v", got)
	}
	if got := r.Decide("trusted.ru:443"); got != Direct {
		t.Fatalf("direct rule: want Direct, got %v", got)
	}
	if got := r.Decide("other.com:443"); got != Direct {
		t.Fatalf("default: want Direct, got %v", got)
	}
}

func TestRouterGeoIPOnIPTarget(t *testing.T) {
	proxyCIDRs := NewCIDRMatcher()
	if err := proxyCIDRs.Add(mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	r := New(Config{Mode: ModeDirectExceptProxy, ProxyCIDRs: proxyCIDRs})

	if got := r.Decide("203.0.113.10:443"); got != Proxy {
		t.Fatalf("geoip match: want Proxy, got %v", got)
	}
	if got := r.Decide("198.51.100.1:443"); got != Direct {
		t.Fatalf("geoip miss: want Direct, got %v", got)
	}
}

func TestRouterGeoIPOnDomainTarget(t *testing.T) {
	proxyCIDRs := NewCIDRMatcher()
	if err := proxyCIDRs.Add(mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	resolve := func(host string) ([]netip.Addr, error) {
		if host == "blocked.com" {
			return []netip.Addr{mustAddr(t, "203.0.113.5")}, nil
		}
		return []netip.Addr{mustAddr(t, "198.51.100.9")}, nil
	}

	r := New(Config{Mode: ModeDirectExceptProxy, ProxyCIDRs: proxyCIDRs, Resolve: resolve})

	if got := r.Decide("blocked.com:443"); got != Proxy {
		t.Fatalf("resolved geoip match: want Proxy, got %v", got)
	}
	if got := r.Decide("clean.com:443"); got != Direct {
		t.Fatalf("resolved geoip miss: want Direct, got %v", got)
	}
}

func TestRouterNoResolverSkipsGeoIP(t *testing.T) {
	proxyCIDRs := NewCIDRMatcher()
	if err := proxyCIDRs.Add(mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	r := New(Config{Mode: ModeDirectExceptProxy, ProxyCIDRs: proxyCIDRs})

	if got := r.Decide("blocked.com:443"); got != Direct {
		t.Fatalf("domain without resolver must fall to default: want Direct, got %v", got)
	}
}

func TestParseMode(t *testing.T) {
	for name, want := range map[string]Mode{"proxy-except-direct": ModeProxyExceptDirect, "direct-except-proxy": ModeDirectExceptProxy} {
		mode, ok := ParseMode(name)
		if !ok || mode != want {
			t.Fatalf("ParseMode(%q): want %v, got %v (ok=%v)", name, want, mode, ok)
		}
	}
	if _, ok := ParseMode("nonsense"); ok {
		t.Fatal("ParseMode must reject unknown mode")
	}
}
