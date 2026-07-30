package routing

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

func LoadDomainList(m *DomainMatcher, path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "full:"):
			m.AddExact(strings.TrimPrefix(line, "full:"))
		case strings.HasPrefix(line, "domain:"):
			m.Add(strings.TrimPrefix(line, "domain:"))
		case strings.HasPrefix(line, "keyword:"), strings.HasPrefix(line, "regexp:"), strings.HasPrefix(line, "include:"):
			return fmt.Errorf("%s:%d: unsupported rule type %q", path, i+1, line)
		default:
			m.Add(line)
		}
	}
	return nil
}

func LoadCIDRList(m *CIDRMatcher, path string) error {
	lines, err := readLines(path)
	if err != nil {
		return err
	}
	for i, line := range lines {
		line = strings.TrimPrefix(line, "deny ")
		line = strings.TrimPrefix(line, "allow ")
		line = strings.TrimSuffix(line, ";")
		line = strings.TrimSpace(line)

		if !strings.Contains(line, "/") {
			if ip, err := netip.ParseAddr(line); err == nil {
				line = singleHostPrefix(ip)
			}
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
		if err := m.Add(prefix); err != nil {
			return fmt.Errorf("%s:%d: %w", path, i+1, err)
		}
	}
	return nil
}

func singleHostPrefix(ip netip.Addr) string {
	if ip.Is4() {
		return ip.String() + "/32"
	}
	return ip.String() + "/128"
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open list: %w", err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read list: %w", err)
	}
	return lines, nil
}
