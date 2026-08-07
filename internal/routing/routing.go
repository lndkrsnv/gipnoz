package routing

import (
	"log/slog"
	"net"
	"net/netip"
)

type Action int

const (
	Direct Action = iota
	Proxy
)

type Mode int

const (
	ModeProxyExceptDirect Mode = iota
	ModeDirectExceptProxy
)

func ParseMode(s string) (Mode, bool) {
	switch s {
	case "proxy-except-direct":
		return ModeProxyExceptDirect, true
	case "direct-except-proxy":
		return ModeDirectExceptProxy, true
	default:
		return ModeProxyExceptDirect, false
	}
}

type Resolver func(host string) ([]netip.Addr, error)

type Router struct {
	mode          Mode
	proxyDomains  *DomainMatcher
	directDomains *DomainMatcher
	proxyCIDRs    *CIDRMatcher
	directCIDRs   *CIDRMatcher
	resolve       Resolver
}

type Config struct {
	Mode          Mode
	ProxyDomains  *DomainMatcher
	DirectDomains *DomainMatcher
	ProxyCIDRs    *CIDRMatcher
	DirectCIDRs   *CIDRMatcher
	Resolve       Resolver
}

func New(cfg Config) *Router {
	return &Router{
		mode:          cfg.Mode,
		proxyDomains:  orEmptyDomains(cfg.ProxyDomains),
		directDomains: orEmptyDomains(cfg.DirectDomains),
		proxyCIDRs:    orEmptyCIDRs(cfg.ProxyCIDRs),
		directCIDRs:   orEmptyCIDRs(cfg.DirectCIDRs),
		resolve:       cfg.Resolve,
	}
}

func orEmptyDomains(m *DomainMatcher) *DomainMatcher {
	if m == nil {
		return NewDomainMatcher()
	}
	return m
}

func orEmptyCIDRs(m *CIDRMatcher) *CIDRMatcher {
	if m == nil {
		return NewCIDRMatcher()
	}
	return m
}

func (r *Router) Decide(targetAddr string) Action {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return r.defaultAction()
	}

	if r.proxyDomains.Match(host) {
		return Proxy
	}
	if r.directDomains.Match(host) {
		return Direct
	}

	if r.hasGeoRules() {
		for _, ip := range r.lookupIPs(host) {
			if r.proxyCIDRs.Contains(ip) {
				return Proxy
			}
			if r.directCIDRs.Contains(ip) {
				return Direct
			}
		}
	}

	return r.defaultAction()
}

func (r *Router) defaultAction() Action {
	if r.mode == ModeDirectExceptProxy {
		return Direct
	}
	return Proxy
}

func (r *Router) hasGeoRules() bool {
	return !r.proxyCIDRs.Empty() || !r.directCIDRs.Empty()
}

func (r *Router) lookupIPs(host string) []netip.Addr {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}
	}
	if r.resolve == nil {
		return nil
	}
	ips, err := r.resolve(host)
	if err != nil {
		slog.Debug("routing resolve failed", "host", host, "err", err)
		return nil
	}
	return ips
}
