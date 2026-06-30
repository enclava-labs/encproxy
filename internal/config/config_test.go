package config

import "testing"

func TestApplyRuntimeProviderOverridesDisablesDirectPrivateModeAPI(t *testing.T) {
	t.Setenv("PRIVATEMODE_PROXY_URL", "")

	cfg := &Config{
		Providers: []Provider{{
			ID:        "privatemode",
			BaseURL:   "https://api.privatemode.ai/v1",
			TrustTier: "confidential",
		}},
	}

	cfg.ApplyRuntimeProviderOverrides()

	if cfg.Providers[0].TrustTier != "plaintext" {
		t.Fatalf("TrustTier = %q, want plaintext", cfg.Providers[0].TrustTier)
	}
}

func TestApplyRuntimeProviderOverridesUsesPrivateModeProxyURL(t *testing.T) {
	t.Setenv("PRIVATEMODE_PROXY_URL", "http://127.0.0.1:8080/v1/")

	cfg := &Config{
		Providers: []Provider{{
			ID:        "privatemode",
			BaseURL:   "https://api.privatemode.ai/v1",
			TrustTier: "confidential",
		}},
	}

	cfg.ApplyRuntimeProviderOverrides()

	if cfg.Providers[0].BaseURL != "http://127.0.0.1:8080/v1" {
		t.Fatalf("BaseURL = %q, want proxy URL", cfg.Providers[0].BaseURL)
	}
	if cfg.Providers[0].TrustTier != "confidential" {
		t.Fatalf("TrustTier = %q, want confidential", cfg.Providers[0].TrustTier)
	}
}

func TestApplyRuntimeProviderOverridesUsesNativePPQPrivateAPI(t *testing.T) {
	t.Setenv("PPQ_PROXY_URL", "")

	cfg := &Config{
		Providers: []Provider{{
			ID:        "ppq",
			BaseURL:   "https://api.ppq.ai/v1",
			TrustTier: "encrypted",
			AttestationConfig: AttestationConfig{
				Type:      "ppq-private",
				BundleURL: "https://api.ppq.ai/private/v1/attestation-bundle",
				UseProxy:  true,
			},
		}},
	}

	cfg.ApplyRuntimeProviderOverrides()

	if cfg.Providers[0].BaseURL != "https://api.ppq.ai/private/v1" {
		t.Fatalf("BaseURL = %q, want native private endpoint", cfg.Providers[0].BaseURL)
	}
	if cfg.Providers[0].TrustTier != "encrypted" {
		t.Fatalf("TrustTier = %q, want encrypted", cfg.Providers[0].TrustTier)
	}
	if cfg.Providers[0].AttestationConfig.UseProxy {
		t.Fatal("UseProxy = true, want false")
	}
	if cfg.Providers[0].AttestationConfig.BundleURL != "https://api.ppq.ai/private" {
		t.Fatalf("BundleURL = %q, want native bundle base", cfg.Providers[0].AttestationConfig.BundleURL)
	}
}

func TestApplyRuntimeProviderOverridesUsesPPQProxyURL(t *testing.T) {
	t.Setenv("PPQ_PROXY_URL", "http://127.0.0.1:8787/v1/")

	cfg := &Config{
		Providers: []Provider{{
			ID:        "ppq",
			BaseURL:   "https://api.ppq.ai/v1",
			TrustTier: "plaintext",
			AttestationConfig: AttestationConfig{
				Type: "ppq-private",
			},
		}},
	}

	cfg.ApplyRuntimeProviderOverrides()

	if cfg.Providers[0].BaseURL != "http://127.0.0.1:8787/v1" {
		t.Fatalf("BaseURL = %q, want proxy URL", cfg.Providers[0].BaseURL)
	}
	if cfg.Providers[0].TrustTier != "encrypted" {
		t.Fatalf("TrustTier = %q, want encrypted", cfg.Providers[0].TrustTier)
	}
	if !cfg.Providers[0].AttestationConfig.UseProxy {
		t.Fatal("UseProxy = false, want true")
	}
}
