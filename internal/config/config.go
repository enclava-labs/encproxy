package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Server holds HTTP server configuration.
type Server struct {
	ListenAddr       string        `toml:"listen_addr"`
	AdminListenAddr  string        `toml:"admin_listen_addr"`
	ReadTimeout      time.Duration `toml:"read_timeout"`
	WriteTimeout     time.Duration `toml:"write_timeout"`
	MaxRequestBytes  int64         `toml:"max_request_bytes"`
	ConfidentialOnly bool          `toml:"confidential_only"` // Only serve confidential/encrypted models
}

// Database holds SQLite configuration.
type Database struct {
	Path            string        `toml:"path"`
	MaxOpenConns    int           `toml:"max_open_conns"`
	MaxIdleConns    int           `toml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `toml:"conn_max_lifetime"`
}

// Attestation holds attestation service configuration.
type Attestation struct {
	RefreshInterval time.Duration `toml:"refresh_interval"`
	VerdictTTL      time.Duration `toml:"verdict_ttl"`
	PolicyDigest    string        `toml:"policy_digest"`
}

// AttestationConfig is provider-specific attestation configuration.
type AttestationConfig struct {
	Type                   string   `toml:"type"`
	Repo                   string   `toml:"repo,omitempty"`
	ReleaseDigest          string   `toml:"release_digest,omitempty"`
	CodeMeasurementFP      string   `toml:"code_measurement_fp,omitempty"`
	HardwareMeasurementFPs []string `toml:"hardware_measurement_fps,omitempty"`
	BundleURL              string   `toml:"bundle_url,omitempty"`
	APIKey                 string   `toml:"api_key,omitempty"`      // For providers requiring auth
	ManifestURL            string   `toml:"manifest_url,omitempty"` // For PrivateMode manifest
	UseProxy               bool     `toml:"use_proxy,omitempty"`    // For local encryption proxy integrations
}

// Pricing is a map of model -> price per 1M tokens in micro-USD.
type Pricing map[string]int64

// Provider holds a provider configuration.
type Provider struct {
	ID                string            `toml:"id"`
	Name              string            `toml:"name"`
	BaseURL           string            `toml:"base_url"`
	TrustTier         string            `toml:"trust_tier"`
	AttestationConfig AttestationConfig `toml:"attestation_config"`
	Pricing           Pricing           `toml:"pricing"`
}

// Config is the root configuration structure.
type Config struct {
	Server      Server      `toml:"server"`
	Database    Database    `toml:"database"`
	Attestation Attestation `toml:"attestation"`
	Providers   []Provider  `toml:"providers"`
}

// Default returns a default configuration.
func Default() *Config {
	return &Config{
		Server: Server{
			ListenAddr:      "0.0.0.0:8080",
			AdminListenAddr: "127.0.0.1:8081",
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    30 * time.Second,
			MaxRequestBytes: 10 * 1024 * 1024,
		},
		Database: Database{
			Path:            "encproxy.db",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Attestation: Attestation{
			RefreshInterval: 60 * time.Second,
			VerdictTTL:      10 * time.Minute,
		},
		Providers: []Provider{},
	}
}

// Load reads configuration from a TOML file.
func Load(path string) (*Config, error) {
	cfg := Default()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil
	}

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	cfg.ApplyRuntimeProviderOverrides()

	return cfg, nil
}

// ApplyRuntimeProviderOverrides applies environment-backed safety overrides that
// cannot be represented directly in the static TOML.
func (c *Config) ApplyRuntimeProviderOverrides() {
	privateModeProxyURL := strings.TrimRight(os.Getenv("PRIVATEMODE_PROXY_URL"), "/")
	ppqProxyURL := strings.TrimRight(os.Getenv("PPQ_PROXY_URL"), "/")

	for i := range c.Providers {
		provider := &c.Providers[i]

		switch provider.ID {
		case "ppq":
			if ppqProxyURL != "" && !isPPQDirectAPI(ppqProxyURL) {
				provider.BaseURL = ppqProxyURL
				provider.TrustTier = "encrypted"
				provider.AttestationConfig.UseProxy = true
				continue
			}

			// PPQ private models use EHBP against the private endpoint natively.
			if isPPQDirectAPI(provider.BaseURL) && provider.TrustTier == "encrypted" {
				provider.BaseURL = "https://api.ppq.ai/private/v1"
				provider.AttestationConfig.UseProxy = false
				if provider.AttestationConfig.BundleURL == "" || strings.Contains(provider.AttestationConfig.BundleURL, "attestation-bundle") {
					provider.AttestationConfig.BundleURL = "https://api.ppq.ai/private"
				}
			}
		case "privatemode":
			if privateModeProxyURL != "" && !isPrivateModeDirectAPI(privateModeProxyURL) {
				provider.BaseURL = privateModeProxyURL
				provider.TrustTier = "confidential"
				continue
			}

			// Privatemode is only confidential when requests go through the
			// Privatemode Encryption Proxy. Do not route directly to the service API.
			if isPrivateModeDirectAPI(provider.BaseURL) && provider.TrustTier == "confidential" {
				provider.TrustTier = "plaintext"
			}
		default:
			continue
		}
	}
}

func isPrivateModeDirectAPI(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	return host == "api.privatemode.ai"
}

func isPPQDirectAPI(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	return host == "api.ppq.ai"
}

// Validate checks configuration validity.
func (c *Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	if c.Database.Path == "" {
		return fmt.Errorf("database.path is required")
	}
	if c.Attestation.PolicyDigest == "" {
		return fmt.Errorf("attestation.policy_digest is required")
	}

	for i, p := range c.Providers {
		if p.ID == "" {
			return fmt.Errorf("providers[%d].id is required", i)
		}
		if p.BaseURL == "" {
			return fmt.Errorf("providers[%d].base_url is required", i)
		}
		if p.TrustTier == "" {
			return fmt.Errorf("providers[%d].trust_tier is required", i)
		}
		// Attestation config only required for confidential/encrypted providers
		if p.AttestationConfig.Type == "" && p.TrustTier != "plaintext" {
			return fmt.Errorf("providers[%d].attestation_config.type is required for non-plaintext providers", i)
		}
	}

	return nil
}
