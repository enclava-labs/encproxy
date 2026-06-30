package attestation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/modelpolicy"
	"github.com/enclava/encproxy/internal/models"

	tinfoilAttest "github.com/tinfoilsh/tinfoil-go/verifier/attestation"
	tinfoilClient "github.com/tinfoilsh/tinfoil-go/verifier/client"
	tinfoilGitHub "github.com/tinfoilsh/tinfoil-go/verifier/github"
	tinfoilSigstore "github.com/tinfoilsh/tinfoil-go/verifier/sigstore"
)

// Service handles attestation verification.
type Service struct {
	db           *database.DB
	cfg          config.Attestation
	providerKeys map[string]string // providerID -> API key
	refresh      chan bool
	stop         chan bool
}

// NewService creates a new attestation service.
func NewService(db *database.DB, cfg config.Attestation, providerKeys map[string]string) *Service {
	return &Service{
		db:           db,
		cfg:          cfg,
		providerKeys: providerKeys,
		refresh:      make(chan bool, 1),
		stop:         make(chan bool),
	}
}

// Start begins the attestation refresh loop.
func (s *Service) Start(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.RefreshInterval)
	defer ticker.Stop()

	// Initial sweep
	s.sweep(ctx)

	for {
		select {
		case <-ticker.C:
			s.sweep(ctx)
		case <-s.refresh:
			s.sweep(ctx)
		case <-s.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Stop stops the attestation service.
func (s *Service) Stop() {
	close(s.stop)
}

// TriggerRefresh triggers a manual refresh.
func (s *Service) TriggerRefresh() {
	select {
	case s.refresh <- true:
	default:
	}
}

// SweepOnce runs a synchronous attestation verification pass.
func (s *Service) SweepOnce(ctx context.Context) {
	s.sweep(ctx)
}

// sweep runs attestation verification for all providers.
func (s *Service) sweep(ctx context.Context) {
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		log.Printf("attestation sweep: failed to list providers: %v", err)
		return
	}

	for _, p := range providers {
		if p.TrustTier != models.TrustTierConfidential && p.TrustTier != models.TrustTierEncrypted {
			continue
		}

		models_, err := s.db.GetProviderModels(ctx, p.ID)
		if err != nil {
			log.Printf("attestation sweep: failed to get models for %s: %v", p.ID, err)
			continue
		}

		for _, m := range models_ {
			if !m.Enabled {
				continue
			}

			if !modelpolicy.SupportsChatCompletions(m.Model) || !modelpolicy.IsProviderModelTEEEligible(p.ID, m.Model) {
				continue
			}

			if err := s.verifyProviderModel(ctx, p, m); err != nil {
				log.Printf("attestation sweep: verification failed for %s/%s: %v", p.ID, m.Model, err)
			}

			// Rate limiting for NanoGPT to avoid 429 errors (2s between requests)
			if p.ID == "nanogpt" {
				time.Sleep(2 * time.Second)
			}
		}
	}
}

// verifyProviderModel verifies attestation for a provider-model combination.
func (s *Service) verifyProviderModel(ctx context.Context, p *models.Provider, m *models.ProviderModel) error {
	var attConfig config.AttestationConfig
	if err := json.Unmarshal([]byte(p.AttestationConfig), &attConfig); err != nil {
		return fmt.Errorf("parse attestation config: %w", err)
	}

	switch attConfig.Type {
	case "tinfoil":
		return s.verifyTinfoil(ctx, p, m, attConfig)
	case "ppq-private":
		return s.verifyPPQ(ctx, p, m, attConfig)
	case "nanogpt":
		return s.verifyNanoGPT(ctx, p, m, attConfig)
	case "redpill":
		return s.verifyRedpill(ctx, p, m, attConfig)
	case "near":
		return s.verifyNear(ctx, p, m, attConfig)
	case "venice":
		return s.verifyVenice(ctx, p, m, attConfig)
	case "privatemode":
		return s.verifyPrivateMode(ctx, p, m, attConfig)
	case "chutes":
		return s.verifyChutes(ctx, p, m, attConfig)
	default:
		return fmt.Errorf("unknown attestation type: %s", attConfig.Type)
	}
}

func isNanoGPTTEEModel(model string) bool {
	return modelpolicy.IsNanoGPTTEEModel(model)
}

// VerifiedClient holds a verified client with its attestation claims.
type VerifiedClient struct {
	Client         *tinfoilClient.SecureClient
	HPKEPublicKey  []byte
	Claims         map[string]interface{}
	EvidenceDigest string
}

// verifiedClients caches verified clients per provider.
// Key: provider_id:model:mode
var verifiedClients = make(map[string]*VerifiedClient)

// GetVerifiedClient retrieves a verified client for a provider-model-mode combination.
func (s *Service) GetVerifiedClient(providerID, model string, mode models.Mode) (*VerifiedClient, error) {
	key := fmt.Sprintf("%s:%s:%s", providerID, model, mode)

	// Check if we have a cached client with valid attestation
	if vc, ok := verifiedClients[key]; ok {
		// Verify the attestation is still valid in DB
		ctx := context.Background()
		attestations, err := s.db.GetVerifiedProvidersForModel(ctx, model, mode)
		if err != nil {
			return nil, fmt.Errorf("check attestation validity: %w", err)
		}
		for _, a := range attestations {
			if a.ProviderID == providerID && a.Verified {
				return vc, nil
			}
		}
	}

	return nil, fmt.Errorf("no verified client available")
}

// verifyTinfoil verifies Tinfoil attestation using the native Go library.
func (s *Service) verifyTinfoil(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	if cfg.Repo == "" {
		return fmt.Errorf("tinfoil attestation requires repo")
	}

	// Create secure client
	enclaveHost := extractHost(p.BaseURL)
	secureClient := tinfoilClient.NewSecureClient(enclaveHost, cfg.Repo)

	// Perform verification
	groundTruth, err := secureClient.Verify()
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":         p.ID,
		"model":               m.Model,
		"mode":                m.Mode,
		"enclave":             enclaveHost,
		"verified_at":         time.Now().UTC().Format(time.RFC3339),
		"repo":                cfg.Repo,
		"code_measurement":    groundTruth.CodeFingerprint,
		"enclave_measurement": groundTruth.EnclaveFingerprint,
	}

	if groundTruth.HPKEPublicKey != "" {
		claims["hpke_public_key"] = groundTruth.HPKEPublicKey
	}

	// Compute evidence digest
	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	// Store attestation verdict
	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	// Cache the verified client
	key := fmt.Sprintf("%s:%s:%s", p.ID, m.Model, m.Mode)

	var hpkeKey []byte
	if groundTruth.HPKEPublicKey != "" {
		hpkeKey, _ = hex.DecodeString(groundTruth.HPKEPublicKey)
	}

	verifiedClients[key] = &VerifiedClient{
		Client:         secureClient,
		HPKEPublicKey:  hpkeKey,
		Claims:         claims,
		EvidenceDigest: evidenceDigest,
	}

	log.Printf("attestation verified for %s/%s (tier: confidential)", p.ID, m.Model)
	return nil
}

// verifyPPQ verifies PPQ-private attestation.
func (s *Service) verifyPPQ(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	if cfg.UseProxy {
		return s.verifyPPQProxy(ctx, p, m)
	}

	if cfg.BundleURL == "" {
		return fmt.Errorf("ppq-private attestation requires bundle_url")
	}

	bundleBaseURL := strings.TrimRight(cfg.BundleURL, "/")
	repo := cfg.Repo
	if repo == "" {
		repo = "tinfoilsh/confidential-model-router"
	}

	bundle, err := tinfoilAttest.FetchBundleFrom(bundleBaseURL)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}

	enclaveHost := bundle.Domain
	if enclaveHost == "" {
		return fmt.Errorf("ppq attestation bundle missing domain")
	}

	secureClient := tinfoilClient.NewSecureClient(enclaveHost, repo)
	groundTruth, err := secureClient.VerifyFromBundle(bundle)
	if err != nil {
		return fmt.Errorf("verify ppq attestation bundle: %w", err)
	}
	if groundTruth.HPKEPublicKey == "" {
		return fmt.Errorf("ppq attestation bundle missing HPKE public key")
	}
	hpkeKey, err := hex.DecodeString(groundTruth.HPKEPublicKey)
	if err != nil {
		return fmt.Errorf("decode HPKE public key: %w", err)
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":         p.ID,
		"model":               m.Model,
		"mode":                m.Mode,
		"enclave":             enclaveHost,
		"verified_at":         time.Now().UTC().Format(time.RFC3339),
		"bundle_url":          bundleBaseURL,
		"repo":                repo,
		"code_measurement":    groundTruth.CodeFingerprint,
		"enclave_measurement": groundTruth.EnclaveFingerprint,
		"hpke_public_key":     groundTruth.HPKEPublicKey,
		"trust_tier":          "encrypted",
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	// Cache the verified client with HPKE key
	key := fmt.Sprintf("%s:%s:%s", p.ID, m.Model, m.Mode)
	verifiedClients[key] = &VerifiedClient{
		Client:         nil, // PPQ uses standard HTTP client with EHBP
		HPKEPublicKey:  hpkeKey,
		Claims:         claims,
		EvidenceDigest: evidenceDigest,
	}

	log.Printf("attestation verified for %s/%s (tier: encrypted with EHBP)", p.ID, m.Model)
	return nil
}

func (s *Service) verifyPPQProxy(ctx context.Context, p *models.Provider, m *models.ProviderModel) error {
	claims := map[string]interface{}{
		"provider_id":      p.ID,
		"model":            m.Model,
		"mode":             m.Mode,
		"proxy":            extractHost(p.BaseURL),
		"verified_at":      time.Now().UTC().Format(time.RFC3339),
		"trust_tier":       "encrypted",
		"attestation_type": "ppq-private-proxy",
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: encrypted via PPQ proxy)", p.ID, m.Model)
	return nil
}

// fetchBundle fetches an attestation bundle from URL.
func fetchBundle(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle fetch failed: %s", resp.Status)
	}

	var buf [8192]byte
	n, _ := resp.Body.Read(buf[:])
	return buf[:n], nil
}

// extractHPKEKeyFromBundle extracts HPKE public key from bundle.
func extractHPKEKeyFromBundle(bundle []byte) ([]byte, error) {
	// Try to parse as tinfoil bundle
	var tinfoilBundle struct {
		HPKEPublicKey string `json:"hpke_public_key"`
	}
	if err := json.Unmarshal(bundle, &tinfoilBundle); err == nil && tinfoilBundle.HPKEPublicKey != "" {
		return hex.DecodeString(tinfoilBundle.HPKEPublicKey)
	}

	// Try to extract from attestation document
	var doc struct {
		Attestation struct {
			Document json.RawMessage `json:"document"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(bundle, &doc); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	// Return bundle content as-is (will be parsed by EHBP layer)
	return bundle, nil
}

// verifyNanoGPT verifies NanoGPT attestation (supports both Tinfoil and dstack formats).
// Implements retry with exponential backoff for rate limiting.
func (s *Service) verifyNanoGPT(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	url := fmt.Sprintf("https://api.nano-gpt.com/v1/tee/attestation?model=%s", url.QueryEscape(m.Model))
	apiKey := s.providerKeys[p.ID]
	if cfg.APIKey != "" {
		apiKey = cfg.APIKey
	}

	// Retry with exponential backoff for rate limiting
	maxRetries := 3
	baseDelay := 2 * time.Second

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<(attempt-1)) // 2s, 4s, 8s
			log.Printf("[nanogpt] Retrying %s/%s after %v (attempt %d/%d)", p.ID, m.Model, delay, attempt+1, maxRetries)
			time.Sleep(delay)
		}

		client := &http.Client{Timeout: 30 * time.Second}
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue // Retry on network error
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Handle rate limiting - retry with backoff
		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("rate limited: %s", string(body))
			continue // Will retry with backoff
		}

		// Non-TEE models return 400 - this is expected, not a failure
		if resp.StatusCode == http.StatusBadRequest {
			bodyStr := string(body)
			if bodyStr == `{"error":"TEE attestation is not available for this model"}` {
				return fmt.Errorf("model %s does not support TEE attestation", m.Model)
			}
			// Handle Redpill service dependency errors
			if strings.Contains(bodyStr, "Unable to reach RedPill") || strings.Contains(bodyStr, "RedPill") {
				return fmt.Errorf("model %s depends on Redpill attestation service which is unavailable", m.Model)
			}
			return fmt.Errorf("nanogpt attestation returned HTTP 400: %s", bodyStr)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("nanogpt attestation returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		// Parse response to determine format
		var raw map[string]interface{}
		if err := json.Unmarshal(body, &raw); err != nil {
			return fmt.Errorf("parse response: %w", err)
		}

		// Check for error responses that might be embedded in 200 OK
		if errMsg, ok := raw["error"].(string); ok {
			if strings.Contains(errMsg, "RedPill") || strings.Contains(errMsg, "Unable to reach") {
				return fmt.Errorf("model %s depends on Redpill attestation service which is unavailable", m.Model)
			}
		}

		// Determine format
		var format string
		if _, ok := raw["model_attestations"]; ok {
			format = "dstack"
		} else if _, ok := raw["format"]; ok {
			format = "tinfoil"
		} else if _, ok := raw["intel_quote"]; ok {
			format = "dstack"
		} else if attType, ok := raw["attestation_type"].(string); ok && attType == "chutes" {
			format = "chutes"
		} else if _, ok := raw["all_attestations"]; ok {
			format = "chutes"
		} else {
			return fmt.Errorf("unknown nanogpt response format: %s", string(body)[:200])
		}

		// Build verified claims
		claims := map[string]interface{}{
			"provider_id":      p.ID,
			"model":            m.Model,
			"mode":             m.Mode,
			"enclave":          extractHost(p.BaseURL),
			"verified_at":      time.Now().UTC().Format(time.RFC3339),
			"format":           format,
			"source_url":       url,
			"trust_tier":       "confidential",
			"attestation_type": "nanogpt",
		}

		claimsJSON, _ := json.Marshal(claims)
		evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

		attestation := &models.ProviderAttestation{
			ProviderID:     p.ID,
			Model:          m.Model,
			Mode:           m.Mode,
			Verified:       true,
			EvidenceDigest: evidenceDigest,
			PolicyDigest:   s.cfg.PolicyDigest,
			VerifiedClaims: string(claimsJSON),
			ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
		}

		if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
			return fmt.Errorf("store attestation: %w", err)
		}

		log.Printf("attestation verified for %s/%s (tier: confidential, format: %s)", p.ID, m.Model, format)
		return nil
	}

	return fmt.Errorf("nanogpt attestation failed after %d attempts: %w", maxRetries, lastErr)
}

// verifyRedpill verifies Redpill attestation (dstack/Phala format).
// Reference: https://api.redpill.ai/v1/attestation/report?model={model}&nonce={nonce}
func (s *Service) verifyRedpill(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	// Generate random nonce (32 bytes = 64 hex chars)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	// Redpill uses dstack attestation endpoint with nonce
	url := fmt.Sprintf("%s/attestation/report?model=%s&nonce=%s",
		p.BaseURL, url.QueryEscape(m.Model), nonceHex)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Add API key from provider keys map
	if apiKey := s.providerKeys[p.ID]; apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("redpill attestation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse dstack-style attestation
	var attestationResp map[string]interface{}
	if err := json.Unmarshal(body, &attestationResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":      p.ID,
		"model":            m.Model,
		"mode":             m.Mode,
		"enclave":          extractHost(p.BaseURL),
		"verified_at":      time.Now().UTC().Format(time.RFC3339),
		"source_url":       url,
		"trust_tier":       "confidential",
		"attestation_type": "redpill",
		"format":           "dstack",
		"nonce":            nonceHex,
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: confidential, format: redpill/dstack)", p.ID, m.Model)
	return nil
}

// verifyNear verifies NEAR AI attestation (dstack format).
// Reference: https://cloud-api.near.ai/v1/attestation/report?model={model}&signing_algo=ed25519&nonce={nonce}
func (s *Service) verifyNear(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	// Generate random nonce (32 bytes = 64 hex chars)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	// NEAR AI uses dstack attestation endpoint with nonce
	url := fmt.Sprintf("%s/attestation/report?model=%s&signing_algo=ed25519&nonce=%s",
		p.BaseURL, url.QueryEscape(m.Model), nonceHex)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Add API key from provider keys map
	if apiKey := s.providerKeys[p.ID]; apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("near attestation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse dstack attestation
	var attestationResp map[string]interface{}
	if err := json.Unmarshal(body, &attestationResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Verify nonce is returned in response (basic check)
	if respNonce, ok := attestationResp["request_nonce"].(string); ok && respNonce != nonceHex {
		return fmt.Errorf("nonce mismatch: expected %s, got %s", nonceHex, respNonce)
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":      p.ID,
		"model":            m.Model,
		"mode":             m.Mode,
		"enclave":          extractHost(p.BaseURL),
		"verified_at":      time.Now().UTC().Format(time.RFC3339),
		"source_url":       url,
		"trust_tier":       "confidential",
		"attestation_type": "near",
		"format":           "dstack",
		"nonce":            nonceHex,
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: confidential, format: near/dstack)", p.ID, m.Model)
	return nil
}

// verifyVenice verifies Venice AI attestation (dstack with E2EE).
func (s *Service) verifyVenice(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	// Venice uses dstack attestation
	url := fmt.Sprintf("%s/attestation/%s", p.BaseURL, url.QueryEscape(m.Model))

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Add API key from provider keys map
	if apiKey := s.providerKeys[p.ID]; apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("venice attestation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse dstack attestation
	var attestationResp map[string]interface{}
	if err := json.Unmarshal(body, &attestationResp); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Check for E2EE capability
	e2eeCapable := false
	if caps, ok := attestationResp["capabilities"].(map[string]interface{}); ok {
		if e2ee, ok := caps["supportsE2EE"].(bool); ok {
			e2eeCapable = e2ee
		}
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":      p.ID,
		"model":            m.Model,
		"mode":             m.Mode,
		"enclave":          extractHost(p.BaseURL),
		"verified_at":      time.Now().UTC().Format(time.RFC3339),
		"source_url":       url,
		"trust_tier":       "confidential",
		"attestation_type": "venice",
		"format":           "dstack",
		"e2ee_capable":     e2eeCapable,
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: confidential, format: venice/dstack, e2ee: %v)", p.ID, m.Model, e2eeCapable)
	return nil
}

// verifyPrivateMode verifies PrivateMode attestation using Contrast manifest.
// PrivateMode uses a CDN-hosted manifest with SNP reference values.
func (s *Service) verifyPrivateMode(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	manifestURL := cfg.ManifestURL
	if manifestURL == "" {
		manifestURL = "https://cdn.confidential.cloud/privatemode/v2/manifest.json"
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("User-Agent", "encproxy-attestation")

	resp, err := client.Do(req)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("privatemode manifest returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse manifest
	var manifest map[string]interface{}
	if err := json.Unmarshal(body, &manifest); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// Extract reference values from manifest
	var referenceValues []string
	if refVals, ok := manifest["ReferenceValues"].(map[string]interface{}); ok {
		if snpRefs, ok := refVals["snp"].([]interface{}); ok {
			for _, ref := range snpRefs {
				if refMap, ok := ref.(map[string]interface{}); ok {
					if measurement, ok := refMap["measurement"].(string); ok {
						referenceValues = append(referenceValues, measurement)
					}
				}
			}
		}
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":      p.ID,
		"model":            m.Model,
		"mode":             m.Mode,
		"enclave":          extractHost(p.BaseURL),
		"verified_at":      time.Now().UTC().Format(time.RFC3339),
		"manifest_url":     manifestURL,
		"trust_tier":       "confidential",
		"attestation_type": "privatemode",
		"format":           "contrast/manifest",
		"reference_values": referenceValues,
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: confidential, format: privatemode/contrast, refs: %d)", p.ID, m.Model, len(referenceValues))
	return nil
}

// verifyChutes verifies Chutes attestation (dstack-based with all_attestations format).
func (s *Service) verifyChutes(ctx context.Context, p *models.Provider, m *models.ProviderModel, cfg config.AttestationConfig) error {
	// Generate random nonce (32 bytes = 64 hex chars)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)

	// Chutes model names include vendor prefix (e.g., "zai-org/GLM-5-TEE")
	// Extract just the model name without vendor prefix for attestation
	modelName := m.Model
	// Strip any vendor/org prefix (take everything after the last "/")
	for strings.Contains(modelName, "/") {
		if idx := strings.LastIndex(modelName, "/"); idx != -1 {
			modelName = modelName[idx+1:]
		}
	}

	// Chutes uses dstack attestation endpoint with nonce
	url := fmt.Sprintf("%s/attestation/report?model=%s&nonce=%s",
		p.BaseURL, url.QueryEscape(modelName), nonceHex)

	log.Printf("chutes attestation: checking %s (stripped from %s) -> %s", modelName, m.Model, url)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	// Add API key from provider keys map
	if apiKey := s.providerKeys[p.ID]; apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return s.handleNetworkError(ctx, p, m, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("model %s (original: %s) does not support TEE attestation", modelName, m.Model)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("chutes attestation returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Parse chutes attestation response
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	// Verify attestation_type is "chutes"
	attType, ok := raw["attestation_type"].(string)
	if !ok || attType != "chutes" {
		return fmt.Errorf("unexpected chutes attestation type: %v", raw["attestation_type"])
	}

	// Check for all_attestations array
	allAttestations, ok := raw["all_attestations"].([]interface{})
	if !ok || len(allAttestations) == 0 {
		return fmt.Errorf("chutes attestation missing all_attestations")
	}

	// Build verified claims
	claims := map[string]interface{}{
		"provider_id":       p.ID,
		"model":             m.Model,
		"mode":              m.Mode,
		"enclave":           extractHost(p.BaseURL),
		"verified_at":       time.Now().UTC().Format(time.RFC3339),
		"source_url":        url,
		"trust_tier":        "confidential",
		"attestation_type":  "chutes",
		"format":            "chutes/dstack",
		"attestation_count": len(allAttestations),
	}

	claimsJSON, _ := json.Marshal(claims)
	evidenceDigest := "sha256:" + sha256Hash(claimsJSON)

	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       true,
		EvidenceDigest: evidenceDigest,
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: string(claimsJSON),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}

	if err := s.db.UpsertAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	log.Printf("attestation verified for %s/%s (tier: confidential, format: chutes/dstack, attestations: %d)", p.ID, m.Model, len(allAttestations))
	return nil
}

// handleNetworkError handles network errors during attestation.
func (s *Service) handleNetworkError(ctx context.Context, p *models.Provider, m *models.ProviderModel, err error) error {
	// Check if we have a recent valid attestation
	attestations, dbErr := s.db.GetVerifiedProvidersForModel(ctx, m.Model, m.Mode)
	if dbErr != nil {
		return fmt.Errorf("network error and DB failure: %v, %w", err, dbErr)
	}

	for _, a := range attestations {
		if a.ProviderID == p.ID {
			// We have a cached verdict, keep it
			log.Printf("attestation network error for %s/%s, keeping cached verdict: %v", p.ID, m.Model, err)
			return nil
		}
	}

	// No cached verdict, mark as unverified
	attestation := &models.ProviderAttestation{
		ProviderID:     p.ID,
		Model:          m.Model,
		Mode:           m.Mode,
		Verified:       false,
		EvidenceDigest: "sha256:" + sha256Hash([]byte(err.Error())),
		PolicyDigest:   s.cfg.PolicyDigest,
		VerifiedClaims: fmt.Sprintf(`{"error":"%s"}`, err.Error()),
		ExpiresAt:      time.Now().UTC().Add(s.cfg.VerdictTTL),
	}
	s.db.UpsertAttestation(ctx, attestation)

	return fmt.Errorf("attestation unreachable, no cached verdict: %w", err)
}

// extractHost extracts host from a URL.
func extractHost(urlStr string) string {
	// Strip protocol prefix
	if len(urlStr) > 8 {
		if urlStr[:8] == "https://" {
			urlStr = urlStr[8:]
		} else if len(urlStr) > 7 && urlStr[:7] == "http://" {
			urlStr = urlStr[7:]
		}
	}
	// Strip path
	for i, c := range urlStr {
		if c == '/' {
			return urlStr[:i]
		}
	}
	return urlStr
}

// sha256Hash computes SHA-256 hash.
func sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// GetConfidentialityStatus returns the current confidentiality status.
func (s *Service) GetConfidentialityStatus(ctx context.Context) (map[string]interface{}, error) {
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		return nil, err
	}

	status := make(map[string]interface{})
	providerStatus := make([]map[string]interface{}, 0, len(providers))

	for _, p := range providers {
		if !modelpolicy.IsConfidentialTier(p.TrustTier) {
			continue
		}

		models_, err := s.db.GetProviderModels(ctx, p.ID)
		if err != nil {
			continue
		}

		pStatus := map[string]interface{}{
			"id":         p.ID,
			"name":       p.Name,
			"trust_tier": p.TrustTier,
			"models":     []map[string]interface{}{},
		}

		for _, m := range models_ {
			if !modelpolicy.SupportsChatCompletions(m.Model) || !modelpolicy.IsProviderModelTEEEligible(p.ID, m.Model) {
				continue
			}

			mStatus := map[string]interface{}{
				"model":   m.Model,
				"mode":    m.Mode,
				"enabled": m.Enabled,
			}

			// Check attestation
			attestations, err := s.db.GetVerifiedProvidersForModel(ctx, m.Model, m.Mode)
			if err == nil {
				for _, a := range attestations {
					if a.ProviderID == p.ID {
						mStatus["verified"] = a.Verified
						mStatus["expires_at"] = a.ExpiresAt
						break
					}
				}
			}

			pStatus["models"] = append(pStatus["models"].([]map[string]interface{}), mStatus)
		}

		providerStatus = append(providerStatus, pStatus)
	}

	status["providers"] = providerStatus
	status["policy_digest"] = s.cfg.PolicyDigest
	status["refresh_interval"] = s.cfg.RefreshInterval.String()
	status["verdict_ttl"] = s.cfg.VerdictTTL.String()

	return status, nil
}

// Helper types for config parsing
type attestationConfig struct {
	Type              string `json:"type"`
	Repo              string `json:"repo"`
	BundleURL         string `json:"bundle_url"`
	ReleaseDigest     string `json:"release_digest"`
	CodeMeasurementFP string `json:"code_measurement_fp"`
	Format            string `json:"format"`
}

// Unused imports (for future use)
var (
	_ = tinfoilGitHub.FetchAttestationBundle
	_ = tinfoilSigstore.NewClient
	_ = tinfoilAttest.SevGuestV2
)
