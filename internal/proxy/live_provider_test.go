//go:build live

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/enclava/encproxy/internal/attestation"
	"github.com/enclava/encproxy/internal/authz"
	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/managedproxies"
	"github.com/enclava/encproxy/internal/modelpolicy"
	"github.com/enclava/encproxy/internal/models"
	"github.com/enclava/encproxy/internal/providers"
	"github.com/enclava/encproxy/internal/routing"
	"github.com/enclava/encproxy/internal/usage"
)

func TestLiveProviderRoutingEndToEnd(t *testing.T) {
	if os.Getenv("ENCPROXY_LIVE_E2E") != "1" {
		t.Skip("set ENCPROXY_LIVE_E2E=1 to run live provider verification")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	allowedProviders := splitCSVSet(os.Getenv("ENCPROXY_LIVE_PROVIDERS"))
	ppqAPIKey := os.Getenv("PPQ_API_KEY")
	privateModeAPIKey := os.Getenv("PRIVATEMODE_API_KEY")
	if len(allowedProviders) > 0 {
		if !allowedProviders["ppq"] {
			ppqAPIKey = ""
		}
		if !allowedProviders["privatemode"] {
			privateModeAPIKey = ""
		}
	}

	managedProxyManager := managedproxies.New()
	if err := managedProxyManager.Start(ctx, managedproxies.Credentials{
		PPQ:         ppqAPIKey,
		PrivateMode: privateModeAPIKey,
	}); err != nil {
		t.Fatalf("start managed provider proxies: %v", err)
	}
	defer managedProxyManager.Stop()

	configPath := os.Getenv("ENCPROXY_LIVE_CONFIG")
	if configPath == "" {
		configPath = "../../encproxy.toml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Attestation.VerdictTTL < time.Hour {
		cfg.Attestation.VerdictTTL = time.Hour
	}
	applyLiveProviderFilter(cfg)

	db := newProxyTestDB(t)
	defer db.Close()

	providerKeys := liveProviderKeys()
	creds := providers.ProviderCredentials{
		Tinfoil:     providerKeys["tinfoil"],
		PPQ:         providerKeys["ppq"],
		Redpill:     providerKeys["redpill"],
		Nanogpt:     providerKeys["nanogpt"],
		Near:        providerKeys["near"],
		Chutes:      providerKeys["chutes"],
		PrivateMode: providerKeys["privatemode"],
	}

	for _, p := range cfg.Providers {
		attConfig, _ := json.Marshal(p.AttestationConfig)
		pricing, _ := json.Marshal(p.Pricing)
		if err := db.UpsertProvider(ctx, &models.Provider{
			ID:                p.ID,
			Name:              p.Name,
			BaseURL:           p.BaseURL,
			TrustTier:         models.TrustTier(p.TrustTier),
			AttestationConfig: string(attConfig),
			Pricing:           string(pricing),
		}); err != nil {
			t.Fatalf("upsert provider %s: %v", p.ID, err)
		}
	}

	if err := providers.NewModelFetcher(db).FetchAllModels(ctx, creds); err != nil {
		t.Fatalf("fetch live models: %v", err)
	}

	attestationSvc := attestation.NewService(db, cfg.Attestation, providerKeys)
	attestationSvc.SweepOnce(ctx)

	expectedModels := verifiedConfidentialModels(t, ctx, db)
	if len(expectedModels) == 0 {
		t.Fatal("no live verified confidential/encrypted models found")
	}

	createProxyAPIKey(t, ctx, db, "sk-live-e2e", nil)
	server := NewServer(
		db,
		routing.NewRouter(db),
		authz.NewAuthorizer(db),
		attestationSvc,
		usage.NewService(db),
		1024*1024,
		providerKeys,
		true,
	)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	listedModels := liveListModels(t, mux)
	assertModelSetsEqual(t, expectedModels, listedModels)

	chatTimeout := liveChatTimeout()
	client := &http.Client{Timeout: chatTimeout}
	var failures []string
	chatModels := filterLiveChatModels(t, listedModels)
	server.httpClient.Timeout = chatTimeout + 30*time.Second
	for _, modelID := range chatModels {
		route, err := routing.NewRouter(db).SelectProvider(ctx, routing.SelectionCriteria{
			RequestedModel: modelID,
			RequestedMode:  models.ModeChat,
			RequiredTier:   models.TrustTierConfidential,
		})
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s route selection failed: %v", modelID, err))
			continue
		}
		if route.TrustTier != models.TrustTierConfidential && route.TrustTier != models.TrustTierEncrypted {
			failures = append(failures, fmt.Sprintf("%s selected non-confidential provider %s (%s)", modelID, route.Provider.ID, route.TrustTier))
			continue
		}

		status, body := liveChatCompletion(t, client, mux, modelID)
		if status < 200 || status >= 300 {
			failures = append(failures, fmt.Sprintf("%s via %s/%s returned HTTP %d: %.300s", modelID, route.Provider.ID, route.Model, status, body))
		}
	}

	t.Logf("verified %d live confidential/encrypted normalized models; tested %d chat models", len(listedModels), len(chatModels))
	if len(failures) > 0 {
		sort.Strings(failures)
		t.Fatalf("live provider routing failures:\n%s", strings.Join(failures, "\n"))
	}
}

func applyLiveProviderFilter(cfg *config.Config) {
	allowed := splitCSVSet(os.Getenv("ENCPROXY_LIVE_PROVIDERS"))
	if len(allowed) == 0 {
		return
	}

	filtered := cfg.Providers[:0]
	for _, provider := range cfg.Providers {
		if allowed[provider.ID] {
			filtered = append(filtered, provider)
		}
	}
	cfg.Providers = filtered
}

func filterLiveChatModels(t *testing.T, listedModels []string) []string {
	t.Helper()

	requested := splitCSVSet(os.Getenv("ENCPROXY_LIVE_MODELS"))
	excluded := splitCSVSet(os.Getenv("ENCPROXY_LIVE_EXCLUDE_MODELS"))
	if len(requested) == 0 {
		selected := make([]string, 0, len(listedModels))
		for _, modelID := range listedModels {
			if !excluded[modelID] {
				selected = append(selected, modelID)
			}
		}
		return selected
	}

	listed := make(map[string]bool, len(listedModels))
	for _, modelID := range listedModels {
		listed[modelID] = true
	}

	selected := make([]string, 0, len(requested))
	for modelID := range requested {
		canonical := models.CanonicalModelName(modelID)
		if !listed[canonical] {
			t.Fatalf("requested live model %q (%q canonical) was not listed", modelID, canonical)
		}
		if excluded[canonical] {
			continue
		}
		selected = append(selected, canonical)
	}
	sort.Strings(selected)
	return selected
}

func splitCSVSet(raw string) map[string]bool {
	result := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = true
		}
	}
	return result
}

func liveProviderKeys() map[string]string {
	return map[string]string{
		"tinfoil":     os.Getenv("TINFOIL_API_KEY"),
		"ppq":         os.Getenv("PPQ_API_KEY"),
		"ppq-private": os.Getenv("PPQ_API_KEY"),
		"redpill":     os.Getenv("REDPILL_API_KEY"),
		"nanogpt":     os.Getenv("NANOGPT_API_KEY"),
		"near":        os.Getenv("NEAR_API_KEY"),
		"chutes":      os.Getenv("CHUTES_API_KEY"),
		"privatemode": os.Getenv("PRIVATEMODE_API_KEY"),
	}
}

func liveChatTimeout() time.Duration {
	raw := strings.TrimSpace(os.Getenv("ENCPROXY_LIVE_CHAT_TIMEOUT"))
	if raw == "" {
		return 2 * time.Minute
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return 2 * time.Minute
	}
	return timeout
}

func verifiedConfidentialModels(t *testing.T, ctx context.Context, db *database.DB) []string {
	t.Helper()

	providerList, err := db.ListProviders(ctx)
	if err != nil {
		t.Fatalf("list providers: %v", err)
	}

	expected := map[string]bool{}
	for _, provider := range providerList {
		if !modelpolicy.IsConfidentialTier(provider.TrustTier) {
			continue
		}

		providerModels, err := db.GetProviderModels(ctx, provider.ID)
		if err != nil {
			t.Fatalf("list models for %s: %v", provider.ID, err)
		}

		for _, providerModel := range providerModels {
			if !modelpolicy.SupportsChatCompletions(providerModel.Model) || !modelpolicy.IsProviderModelTEEEligible(provider.ID, providerModel.Model) {
				continue
			}
			attestations, err := db.GetVerifiedProvidersForModel(ctx, providerModel.Model, providerModel.Mode)
			if err != nil {
				t.Fatalf("get attestations for %s/%s: %v", provider.ID, providerModel.Model, err)
			}
			for _, attestation := range attestations {
				if attestation.ProviderID == provider.ID && attestation.Verified {
					expected[models.CanonicalModelName(providerModel.Model)] = true
				}
			}
		}
	}

	return sortedKeys(expected)
}

func liveListModels(t *testing.T, handler http.Handler) []string {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, "/v1/models", nil)
	if err != nil {
		t.Fatalf("create /v1/models request: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	resp := recorder.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("/v1/models returned HTTP %d: %s", resp.StatusCode, body)
	}

	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}

	modelIDs := make([]string, 0, len(response.Data))
	for _, model := range response.Data {
		modelIDs = append(modelIDs, model.ID)
	}
	sort.Strings(modelIDs)
	return modelIDs
}

func liveChatCompletion(t *testing.T, client *http.Client, handler http.Handler, modelID string) (int, string) {
	t.Helper()

	payload := map[string]interface{}{
		"model": modelID,
		"messages": []map[string]string{
			{"role": "user", "content": "Reply with the word ok."},
		},
		"max_tokens": 256,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create chat request for %s: %v", modelID, err)
	}
	req.Header.Set("Authorization", "Bearer sk-live-e2e")
	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.ServeHTTP(recorder, req)
	}()

	select {
	case <-done:
	case <-time.After(client.Timeout):
		return http.StatusGatewayTimeout, "request timed out"
	}

	resp := recorder.Result()
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(responseBody)
}

func assertModelSetsEqual(t *testing.T, expected []string, got []string) {
	t.Helper()

	expectedSet := map[string]bool{}
	gotSet := map[string]bool{}
	for _, model := range expected {
		expectedSet[model] = true
	}
	for _, model := range got {
		gotSet[model] = true
	}

	var missing []string
	for _, model := range expected {
		if !gotSet[model] {
			missing = append(missing, model)
		}
	}

	var extra []string
	for _, model := range got {
		if !expectedSet[model] {
			extra = append(extra, model)
		}
	}

	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("/v1/models mismatch\nmissing verified confidential models: %v\nextra models: %v", missing, extra)
	}
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
