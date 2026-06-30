package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/modelpolicy"
	"github.com/enclava/encproxy/internal/models"
)

// ModelFetcher handles fetching models from upstream providers.
type ModelFetcher struct {
	db     *database.DB
	client *http.Client
}

// NewModelFetcher creates a new model fetcher.
func NewModelFetcher(db *database.DB) *ModelFetcher {
	return &ModelFetcher{
		db: db,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ProviderCredentials holds API keys for providers.
type ProviderCredentials struct {
	Tinfoil     string
	PPQ         string
	Redpill     string
	Nanogpt     string
	Near        string
	Chutes      string
	PrivateMode string
}

// FetchAllModels fetches models from all configured providers with credentials.
func (f *ModelFetcher) FetchAllModels(ctx context.Context, creds ProviderCredentials) error {
	providers, err := f.db.ListProviders(ctx)
	if err != nil {
		return fmt.Errorf("list providers: %w", err)
	}

	for _, p := range providers {
		var apiKey string
		switch p.ID {
		case "tinfoil":
			apiKey = creds.Tinfoil
		case "ppq", "ppq-private":
			apiKey = creds.PPQ
		case "redpill":
			apiKey = creds.Redpill
		case "nanogpt":
			apiKey = creds.Nanogpt
		case "near":
			apiKey = creds.Near
		case "chutes":
			apiKey = creds.Chutes
		case "privatemode":
			apiKey = creds.PrivateMode
		}

		if apiKey == "" {
			log.Printf("Skipping model fetch for %s: no API key configured", p.ID)
			continue
		}

		if err := f.FetchProviderModels(ctx, p, apiKey); err != nil {
			log.Printf("Failed to fetch models for %s: %v", p.ID, err)
			// Continue with other providers even if one fails
		}
	}

	return nil
}

// FetchProviderModels fetches models from a single provider.
func (f *ModelFetcher) FetchProviderModels(ctx context.Context, provider *models.Provider, apiKey string) error {
	if provider.ID == "ppq" && provider.TrustTier == models.TrustTierEncrypted && !providerUsesProxy(provider) {
		return f.storePPQPrivateModels(ctx, provider)
	}

	modelsURL := provider.BaseURL + "/models"

	var resp *http.Response
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+apiKey)
		req.Header.Set("Accept", "application/json")

		resp, err = f.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("fetch models: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			break
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastErr = fmt.Errorf("models endpoint returned %d: %s", resp.StatusCode, string(body))
		if !retryableModelFetchStatus(resp.StatusCode) {
			return lastErr
		}
		resp = nil
	}
	if resp == nil {
		return lastErr
	}
	defer resp.Body.Close()

	var response struct {
		Data []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
			Object  string `json:"object"`
		} `json:"data"`
		Object string `json:"object"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// Store each model
	for _, m := range response.Data {
		if m.ID == "" {
			continue
		}
		if provider.ID == "ppq" && provider.TrustTier == models.TrustTierEncrypted && !strings.HasPrefix(strings.ToLower(m.ID), "private/") {
			log.Printf("Skipping non-private PPQ model: %s/%s", provider.ID, m.ID)
			continue
		}
		if modelpolicy.IsConfidentialTier(provider.TrustTier) && !modelpolicy.IsProviderModelTEEEligible(provider.ID, m.ID) {
			log.Printf("Skipping non-TEE model: %s/%s", provider.ID, m.ID)
			continue
		}
		if !SupportsChatCompletions(m.ID) {
			log.Printf("Skipping non-chat model: %s/%s", provider.ID, m.ID)
			continue
		}

		// Create provider-model mapping for chat mode
		pm := &models.ProviderModel{
			ProviderID: provider.ID,
			Model:      m.ID,
			Mode:       models.ModeChat,
			Enabled:    true,
		}

		if err := f.db.UpsertProviderModel(ctx, pm); err != nil {
			log.Printf("Failed to store model %s for %s: %v", m.ID, provider.ID, err)
			continue
		}

		log.Printf("Stored model: %s/%s (mode: chat)", provider.ID, m.ID)
	}

	log.Printf("Fetched %d models from %s", len(response.Data), provider.ID)
	return nil
}

func (f *ModelFetcher) storePPQPrivateModels(ctx context.Context, provider *models.Provider) error {
	for _, modelID := range ppqPrivateModels {
		pm := &models.ProviderModel{
			ProviderID: provider.ID,
			Model:      modelID,
			Mode:       models.ModeChat,
			Enabled:    true,
		}

		if err := f.db.UpsertProviderModel(ctx, pm); err != nil {
			log.Printf("Failed to store model %s for %s: %v", modelID, provider.ID, err)
			continue
		}
		log.Printf("Stored model: %s/%s (mode: chat)", provider.ID, modelID)
	}

	log.Printf("Fetched %d models from %s", len(ppqPrivateModels), provider.ID)
	return nil
}

func providerUsesProxy(provider *models.Provider) bool {
	var attConfig map[string]interface{}
	if err := json.Unmarshal([]byte(provider.AttestationConfig), &attConfig); err == nil {
		if useProxy, ok := attConfig["use_proxy"].(bool); ok && useProxy {
			return true
		}
		if useProxy, ok := attConfig["UseProxy"].(bool); ok && useProxy {
			return true
		}
	}
	return strings.HasPrefix(provider.BaseURL, "http://127.0.0.1:") || strings.HasPrefix(provider.BaseURL, "http://localhost:")
}

var ppqPrivateModels = []string{
	"private/kimi-k2-6",
	"private/gpt-oss-120b",
	"private/llama3-3-70b",
	"private/qwen3-vl-30b",
	"private/glm-5-2",
	"private/gemma4-31b",
}

func retryableModelFetchStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// SupportsChatCompletions returns whether a provider model ID should be exposed
// through the chat completions endpoint.
func SupportsChatCompletions(modelID string) bool {
	return modelpolicy.SupportsChatCompletions(modelID)
}

// FetchAndStoreModels fetches models for all providers with credentials.
func FetchAndStoreModels(ctx context.Context, db *database.DB, creds ProviderCredentials) error {
	fetcher := NewModelFetcher(db)
	return fetcher.FetchAllModels(ctx, creds)
}
