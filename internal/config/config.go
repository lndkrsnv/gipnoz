package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ClientConfig struct {
	Server struct {
		Address string `yaml:"address"`
		SNI     string `yaml:"sni"`
	} `yaml:"server"`
	Auth struct {
		PrivateKey      string `yaml:"private_key"`
		ServerPublicKey string `yaml:"server_public_key"`
	} `yaml:"auth"`
	Listen struct {
		SOCKS5 string `yaml:"socks5"`
	} `yaml:"listen"`
	TLS struct {
		Fingerprint string `yaml:"fingerprint"`
		Insecure    bool   `yaml:"insecure"`
	} `yaml:"tls"`
	DNS struct {
		DOH string `yaml:"doh"`
	} `yaml:"dns"`
	Padding  PaddingConfig `yaml:"padding"`
	Timeouts TimeoutConfig `yaml:"timeouts"`
	Routing  RoutingConfig `yaml:"routing"`
}

type RoutingConfig struct {
	Mode   string       `yaml:"mode"`
	Proxy  RoutingRules `yaml:"proxy"`
	Direct RoutingRules `yaml:"direct"`
}

type RoutingRules struct {
	Domains     []string `yaml:"domains"`
	DomainLists []string `yaml:"domain_lists"`
	GeoIPLists  []string `yaml:"geoip_lists"`
}

type ServerConfig struct {
	Listen struct {
		Address string `yaml:"address"`
	} `yaml:"listen"`
	Auth struct {
		PrivateKey string        `yaml:"private_key"`
		Clients    []ClientEntry `yaml:"clients"`
	} `yaml:"auth"`
	SecurityLog string          `yaml:"security_log"`
	Padding     PaddingConfig   `yaml:"padding"`
	Timeouts    TimeoutConfig   `yaml:"timeouts"`
	RateLimit   RateLimitConfig `yaml:"rate_limit"`
}

type ClientEntry struct {
	Name string `yaml:"name"`
	Key  string `yaml:"key"`
}

type PaddingConfig struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

type TimeoutConfig struct {
	ConnectSeconds int `yaml:"connect_seconds"`
	IdleSeconds    int `yaml:"idle_seconds"`
}

type RateLimitConfig struct {
	MaxStreamsPerIP int `yaml:"max_streams_per_ip"`
}

func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseClient(data)
}

func ParseClient(data []byte) (*ClientConfig, error) {
	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen.SOCKS5 == "" {
		cfg.Listen.SOCKS5 = "127.0.0.1:1080"
	}
	if cfg.TLS.Fingerprint == "" {
		cfg.TLS.Fingerprint = "chrome"
	}
	if cfg.Padding.Min == 0 {
		cfg.Padding.Min = 16
	}
	if cfg.Padding.Max == 0 {
		cfg.Padding.Max = 256
	}
	if cfg.Timeouts.ConnectSeconds == 0 {
		cfg.Timeouts.ConnectSeconds = 10
	}
	if cfg.Timeouts.IdleSeconds == 0 {
		cfg.Timeouts.IdleSeconds = 300
	}
	if cfg.Routing.Mode == "" {
		cfg.Routing.Mode = "proxy-except-direct"
	}
	return &cfg, nil
}

func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Listen.Address == "" {
		cfg.Listen.Address = "127.0.0.1:8443"
	}
	if cfg.Padding.Min == 0 {
		cfg.Padding.Min = 16
	}
	if cfg.Padding.Max == 0 {
		cfg.Padding.Max = 256
	}
	if cfg.Timeouts.ConnectSeconds == 0 {
		cfg.Timeouts.ConnectSeconds = 10
	}
	if cfg.Timeouts.IdleSeconds == 0 {
		cfg.Timeouts.IdleSeconds = 300
	}
	if cfg.RateLimit.MaxStreamsPerIP == 0 {
		cfg.RateLimit.MaxStreamsPerIP = 64
	}
	return &cfg, nil
}
