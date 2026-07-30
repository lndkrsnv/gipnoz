package routing

import "testing"

func TestDomainMatcherSuffix(t *testing.T) {
	m := NewDomainMatcher()
	m.Add("example.com")

	for _, host := range []string{"example.com", "www.example.com", "a.b.example.com", "EXAMPLE.COM"} {
		if !m.Match(host) {
			t.Fatalf("want match for %q", host)
		}
	}
	for _, host := range []string{"notexample.com", "example.com.evil.org", "com"} {
		if m.Match(host) {
			t.Fatalf("want no match for %q", host)
		}
	}
}

func TestDomainMatcherExact(t *testing.T) {
	m := NewDomainMatcher()
	m.AddExact("example.com")

	if !m.Match("example.com") {
		t.Fatal("want match for exact domain")
	}
	if m.Match("www.example.com") {
		t.Fatal("exact rule must not match subdomains")
	}
}

func TestDomainMatcherEmpty(t *testing.T) {
	if NewDomainMatcher().Match("example.com") {
		t.Fatal("empty matcher must not match")
	}
}
