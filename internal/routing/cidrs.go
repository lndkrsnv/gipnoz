package routing

import (
	"fmt"
	"net/netip"
)

type CIDRMatcher struct {
	v4 *prefixTrie
	v6 *prefixTrie
	n  int
}

func NewCIDRMatcher() *CIDRMatcher {
	return &CIDRMatcher{
		v4: &prefixTrie{},
		v6: &prefixTrie{},
	}
}

func (m *CIDRMatcher) Add(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix %q", prefix)
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		b := prefix.Addr().As4()
		m.v4.insert(b[:], prefix.Bits())
	} else {
		b := prefix.Addr().As16()
		m.v6.insert(b[:], prefix.Bits())
	}
	m.n++
	return nil
}

func (m *CIDRMatcher) Contains(ip netip.Addr) bool {
	if ip.Is4() || ip.Is4In6() {
		b := ip.Unmap().As4()
		return m.v4.lookup(b[:])
	}
	b := ip.As16()
	return m.v6.lookup(b[:])
}

func (m *CIDRMatcher) Empty() bool {
	return m.n == 0
}

func (m *CIDRMatcher) Len() int {
	return m.n
}

type prefixTrie struct {
	children [2]*prefixTrie
	terminal bool
}

func (t *prefixTrie) insert(addr []byte, bits int) {
	node := t
	for i := 0; i < bits; i++ {
		bit := (addr[i/8] >> (7 - i%8)) & 1
		if node.children[bit] == nil {
			node.children[bit] = &prefixTrie{}
		}
		node = node.children[bit]
	}
	node.terminal = true
}

func (t *prefixTrie) lookup(addr []byte) bool {
	node := t
	for i := 0; i < len(addr)*8; i++ {
		if node.terminal {
			return true
		}
		bit := (addr[i/8] >> (7 - i%8)) & 1
		node = node.children[bit]
		if node == nil {
			return false
		}
	}
	return node.terminal
}
