package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	dnsRecordTypeA    = 1
	dnsRecordTypeAAAA = 28
)

type DoHResolver struct {
	url    string
	client *http.Client
}

func NewDoHResolver(url string) *DoHResolver {
	return &DoHResolver{
		url:    url,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (d *DoHResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	reqURL := fmt.Sprintf("%s?name=%s&type=A", d.url, host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("doh request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("doh read: %w", err)
	}

	var result dohResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("doh parse: %w", err)
	}

	var addrs []string
	for _, ans := range result.Answer {
		if ans.Type == dnsRecordTypeA || ans.Type == dnsRecordTypeAAAA {
			addrs = append(addrs, ans.Data)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("doh: no addresses found for %s", host)
	}
	return addrs, nil
}

func (d *DoHResolver) ResolveAddress(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("split host:port: %w", err)
	}
	if net.ParseIP(host) != nil {
		return address, nil
	}
	ips, err := d.LookupHost(ctx, host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ips[0], port), nil
}

type dohResponse struct {
	Answer []dohAnswer `json:"Answer"`
}

type dohAnswer struct {
	Type int    `json:"type"`
	Data string `json:"data"`
}
