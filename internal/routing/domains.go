package routing

import "strings"

type DomainMatcher struct {
	exact  map[string]bool
	suffix map[string]bool
}

func NewDomainMatcher() *DomainMatcher {
	return &DomainMatcher{
		exact:  make(map[string]bool),
		suffix: make(map[string]bool),
	}
}

func (m *DomainMatcher) AddExact(domain string) {
	m.exact[strings.ToLower(domain)] = true
}

func (m *DomainMatcher) Add(domain string) {
	m.suffix[strings.ToLower(domain)] = true
}

func (m *DomainMatcher) Match(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if m.exact[host] {
		return true
	}
	for {
		if m.suffix[host] {
			return true
		}
		dot := strings.IndexByte(host, '.')
		if dot < 0 {
			return false
		}
		host = host[dot+1:]
	}
}
