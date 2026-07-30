package routing

import (
	"os"
	"path/filepath"
	"testing"
)

func writeList(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write list: %v", err)
	}
	return path
}

func TestLoadDomainList(t *testing.T) {
	path := writeList(t, `
# comment
example.com
full:exact.example.org
domain:suffix.example.net

keyword:unsupported
`)
	m := NewDomainMatcher()
	err := LoadDomainList(m, path)
	if err == nil {
		t.Fatal("expected error for keyword rule")
	}
}

func TestLoadDomainListFormats(t *testing.T) {
	path := writeList(t, `
# comment
example.com   # inline comment
full:exact.example.org
domain:suffix.example.net
`)
	m := NewDomainMatcher()
	if err := LoadDomainList(m, path); err != nil {
		t.Fatalf("LoadDomainList: %v", err)
	}

	if !m.Match("www.example.com") {
		t.Fatal("plain line must behave as suffix rule")
	}
	if !m.Match("exact.example.org") || m.Match("sub.exact.example.org") {
		t.Fatal("full: rule must match exactly")
	}
	if !m.Match("sub.suffix.example.net") {
		t.Fatal("domain: rule must match subdomains")
	}
}

func TestLoadCIDRList(t *testing.T) {
	path := writeList(t, `
# comment
10.0.0.0/8
deny 192.168.0.0/16;
allow 172.16.0.0/12;
1.2.3.4
2001:db8::/32
`)
	m := NewCIDRMatcher()
	if err := LoadCIDRList(m, path); err != nil {
		t.Fatalf("LoadCIDRList: %v", err)
	}
	if m.Len() != 5 {
		t.Fatalf("want 5 prefixes, got %d", m.Len())
	}

	for _, ip := range []string{"10.1.2.3", "192.168.1.1", "172.16.5.5", "1.2.3.4", "2001:db8::7"} {
		if !m.Contains(mustAddr(t, ip)) {
			t.Fatalf("want match for %s", ip)
		}
	}
	if m.Contains(mustAddr(t, "5.6.7.8")) {
		t.Fatal("want no match for outside address")
	}
}

func TestLoadCIDRListInvalid(t *testing.T) {
	path := writeList(t, "not-a-cidr\n")
	if err := LoadCIDRList(NewCIDRMatcher(), path); err == nil {
		t.Fatal("expected error for invalid line")
	}
}

func TestLoadMissingList(t *testing.T) {
	if err := LoadDomainList(NewDomainMatcher(), "/nonexistent/list.txt"); err == nil {
		t.Fatal("expected error for missing file")
	}
}
