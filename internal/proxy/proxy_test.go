package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enclava/encproxy/internal/attestation"
	"github.com/enclava/encproxy/internal/authz"
	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/models"
	"github.com/enclava/encproxy/internal/routing"
	"github.com/enclava/encproxy/internal/usage"
)

func TestBuildUpstreamRequestBodyAdaptsRedpillOpenAIReasoningTokenLimit(t *testing.T) {
	body, err := buildUpstreamRequestBody(
		[]byte(`{"model":"gpt-5","messages":[],"max_tokens":1}`),
		"redpill",
		"openai/gpt-5",
		false,
	)
	if err != nil {
		t.Fatalf("build request body: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode request body: %v", err)
	}

	if payload["model"] != "openai/gpt-5" {
		t.Fatalf("model = %v, want provider model", payload["model"])
	}
	if _, ok := payload["max_tokens"]; ok {
		t.Fatal("max_tokens was not removed")
	}
	if payload["max_completion_tokens"] != float64(1) {
		t.Fatalf("max_completion_tokens = %v, want 1", payload["max_completion_tokens"])
	}
}

func TestBuildUpstreamRequestBodyLeavesOtherProviderTokenLimitUnchanged(t *testing.T) {
	body, err := buildUpstreamRequestBody(
		[]byte(`{"model":"gpt-5","messages":[],"max_tokens":1}`),
		"tinfoil",
		"gpt-oss-120b",
		false,
	)
	if err != nil {
		t.Fatalf("build request body: %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode request body: %v", err)
	}

	if payload["max_tokens"] != float64(1) {
		t.Fatalf("max_tokens = %v, want 1", payload["max_tokens"])
	}
	if _, ok := payload["max_completion_tokens"]; ok {
		t.Fatal("max_completion_tokens was unexpectedly added")
	}
}

func TestChatCompletionsFailoverKeepsConfidentialRoutingEndToEnd(t *testing.T) {
	ctx := context.Background()
	db := newProxyTestDB(t)
	defer db.Close()

	var secondCalls atomic.Int32
	var secondModel atomic.Value
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		var payload map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		secondModel.Store(payload["model"])

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-test",
			"object":  "chat.completion",
			"created": int64(1),
			"model":   payload["model"],
			"choices": []interface{}{},
			"usage": map[string]int64{
				"prompt_tokens":     1,
				"completion_tokens": 1,
				"total_tokens":      2,
			},
		})
	}))
	defer second.Close()

	var firstCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		addProxyVerifiedRoute(t, context.Background(), db, "near", models.TrustTierConfidential, second.URL, "near/secure-model")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"retry me"}`))
	}))
	defer first.Close()

	var plainCalls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, first.URL, "tinfoil/secure-model")
	addProxyVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, plain.URL, "openai/secure-model")
	createProxyAPIKey(t, ctx, db, "sk-test", []string{"tinfoil", "near"})

	server := newProxyHTTPServer(t, db, map[string]string{"near": "second-key"})
	defer server.Close()

	resp := postChatCompletion(t, server.URL, "sk-test", `{"model":"secure-model","messages":[{"role":"user","content":"hello"}]}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if firstCalls.Load() != 1 {
		t.Fatalf("first provider calls = %d, want 1", firstCalls.Load())
	}
	if secondCalls.Load() != 1 {
		t.Fatalf("second provider calls = %d, want 1", secondCalls.Load())
	}
	if plainCalls.Load() != 0 {
		t.Fatalf("plaintext provider calls = %d, want 0", plainCalls.Load())
	}
	if got := secondModel.Load(); got != "near/secure-model" {
		t.Fatalf("upstream model = %v, want near/secure-model", got)
	}
}

func TestChatCompletionsDoesNotFailoverToPlaintextEndToEnd(t *testing.T) {
	ctx := context.Background()
	db := newProxyTestDB(t)
	defer db.Close()

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"retry me"}`))
	}))
	defer first.Close()

	var plainCalls atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer plain.Close()

	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, first.URL, "tinfoil/secure-model")
	addProxyVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, plain.URL, "openai/secure-model")
	createProxyAPIKey(t, ctx, db, "sk-test", nil)

	server := newProxyHTTPServer(t, db, nil)
	defer server.Close()

	resp := postChatCompletion(t, server.URL, "sk-test", `{"model":"secure-model","messages":[{"role":"user","content":"hello"}]}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 503; body=%s", resp.StatusCode, body)
	}
	if plainCalls.Load() != 0 {
		t.Fatalf("plaintext provider calls = %d, want 0", plainCalls.Load())
	}
}

func TestStreamingFailoverKeepsConfidentialRouting(t *testing.T) {
	ctx := context.Background()
	db := newProxyTestDB(t)
	defer db.Close()

	var firstCalls atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer first.Close()

	var secondCalls atomic.Int32
	var secondModel atomic.Value
	var includeUsage atomic.Bool
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondCalls.Add(1)
		var payload map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode upstream request: %v", err)
		}
		secondModel.Store(payload["model"])
		if options, ok := payload["stream_options"].(map[string]interface{}); ok {
			if value, ok := options["include_usage"].(bool); ok {
				includeUsage.Store(value)
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data: {\"ok\":true}\n\n"))
	}))
	defer second.Close()

	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, first.URL, "tinfoil/secure-model")
	addProxyVerifiedRoute(t, ctx, db, "near", models.TrustTierConfidential, second.URL, "near/secure-model")

	server := newProxyServer(t, db, nil)
	body := []byte(`{"model":"secure-model","stream":true,"messages":[{"role":"user","content":"hello"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	server.handleStreamingRequest(
		ctx,
		recorder,
		request,
		&models.ChatCompletionRequest{Model: "secure-model", Stream: true},
		&routing.Route{
			Provider:  &models.Provider{ID: "tinfoil", BaseURL: first.URL, TrustTier: models.TrustTierConfidential},
			Model:     "tinfoil/secure-model",
			Mode:      models.ModeChat,
			TrustTier: models.TrustTierConfidential,
		},
		routing.SelectionCriteria{
			RequestedModel: "secure-model",
			RequestedMode:  models.ModeChat,
			RequiredTier:   models.TrustTierConfidential,
		},
		&models.APIKey{},
		"request-id",
		"key-prefix",
		body,
		time.Now(),
	)

	resp := recorder.Result()
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, respBody)
	}
	if firstCalls.Load() != 1 {
		t.Fatalf("first provider calls = %d, want 1", firstCalls.Load())
	}
	if secondCalls.Load() != 1 {
		t.Fatalf("second provider calls = %d, want 1", secondCalls.Load())
	}
	if got := secondModel.Load(); got != "near/secure-model" {
		t.Fatalf("upstream model = %v, want near/secure-model", got)
	}
	if !includeUsage.Load() {
		t.Fatal("stream_options.include_usage was not forwarded as true")
	}
	if !bytes.Contains(respBody, []byte(`data: {"ok":true}`)) {
		t.Fatalf("stream body = %q, want upstream SSE data", respBody)
	}
}

func TestListModelsOnlyShowsVerifiedConfidentialModels(t *testing.T) {
	ctx := context.Background()
	db := newProxyTestDB(t)
	defer db.Close()

	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "http://conf.example", "tinfoil/secure-model")
	addProxyVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, "http://plain.example", "openai/public-only")
	addProxyVerifiedRoute(t, ctx, db, "redpill", models.TrustTierConfidential, "http://redpill.example", "anthropic/claude-opus-4")
	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "http://tinfoil.example", "doc-upload")

	server := newProxyHTTPServer(t, db, nil)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/models")
	if err != nil {
		t.Fatalf("GET /v1/models: %v", err)
	}
	defer resp.Body.Close()

	var response struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}

	seen := map[string]bool{}
	for _, model := range response.Data {
		seen[model.ID] = true
	}
	if !seen["secure-model"] {
		t.Fatalf("/v1/models did not include secure-model: %#v", seen)
	}
	if seen["public-only"] {
		t.Fatalf("/v1/models included plaintext-only model: %#v", seen)
	}
	if seen["claude-opus-4"] {
		t.Fatalf("/v1/models included remote-hosted Anthropic model: %#v", seen)
	}
	if seen["doc-upload"] {
		t.Fatalf("/v1/models included non-chat model: %#v", seen)
	}
}

func TestConfidentialityStatusOnlyShowsServableConfidentialModels(t *testing.T) {
	ctx := context.Background()
	db := newProxyTestDB(t)
	defer db.Close()

	addProxyVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "http://conf.example", "tinfoil/secure-model")
	addProxyVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, "http://plain.example", "openai/public-only")
	addProxyVerifiedRoute(t, ctx, db, "redpill", models.TrustTierConfidential, "http://redpill.example", "anthropic/claude-opus-4")
	addProxyVerifiedRoute(t, ctx, db, "near", models.TrustTierConfidential, "http://near.example", "near/Qwen/Qwen3-Embedding-0.6B")

	server := newProxyHTTPServer(t, db, nil)
	defer server.Close()

	resp, err := http.Get(server.URL + "/v1/confidentiality")
	if err != nil {
		t.Fatalf("GET /v1/confidentiality: %v", err)
	}
	defer resp.Body.Close()

	var response struct {
		Providers []struct {
			ID     string `json:"id"`
			Models []struct {
				Model string `json:"model"`
			} `json:"models"`
		} `json:"providers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode /v1/confidentiality: %v", err)
	}

	seen := map[string]bool{}
	for _, provider := range response.Providers {
		if provider.ID == "plain" {
			t.Fatalf("/v1/confidentiality included plaintext provider: %#v", response.Providers)
		}
		for _, model := range provider.Models {
			seen[model.Model] = true
		}
	}
	if !seen["tinfoil/secure-model"] {
		t.Fatalf("/v1/confidentiality did not include secure model: %#v", seen)
	}
	if seen["openai/public-only"] || seen["anthropic/claude-opus-4"] || seen["near/Qwen/Qwen3-Embedding-0.6B"] {
		t.Fatalf("/v1/confidentiality included non-confidential or non-chat models: %#v", seen)
	}
}

func newProxyTestDB(t *testing.T) *database.DB {
	t.Helper()

	db, err := database.Open(config.Database{
		Path:            filepath.Join(t.TempDir(), "encproxy-test.db"),
		MaxOpenConns:    1,
		MaxIdleConns:    1,
		ConnMaxLifetime: time.Minute,
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	return db
}

func newProxyHTTPServer(t *testing.T, db *database.DB, providerKeys map[string]string) *httptest.Server {
	t.Helper()
	server := newProxyServer(t, db, providerKeys)

	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	return httptest.NewServer(mux)
}

func newProxyServer(t *testing.T, db *database.DB, providerKeys map[string]string) *Server {
	t.Helper()
	if providerKeys == nil {
		providerKeys = map[string]string{}
	}

	attestationSvc := attestation.NewService(db, config.Attestation{
		RefreshInterval: time.Minute,
		VerdictTTL:      time.Hour,
		PolicyDigest:    "sha256:test",
	}, providerKeys)

	return NewServer(
		db,
		routing.NewRouter(db),
		authz.NewAuthorizer(db),
		attestationSvc,
		usage.NewService(db),
		1024*1024,
		providerKeys,
		true,
	)
}

func createProxyAPIKey(t *testing.T, ctx context.Context, db *database.DB, keyValue string, allowedProviders []string) {
	t.Helper()

	keyHash := database.HashAPIKey(keyValue)
	if err := db.CreateAPIKey(ctx, &models.APIKey{
		ID:               keyValue,
		KeyHash:          keyHash,
		KeyPrefix:        database.APIKeyPrefix(keyHash),
		Name:             "test",
		AllowedProviders: allowedProviders,
	}); err != nil {
		t.Fatalf("create API key: %v", err)
	}
}

func addProxyVerifiedRoute(t *testing.T, ctx context.Context, db *database.DB, providerID string, tier models.TrustTier, baseURL string, model string) {
	t.Helper()

	if err := db.UpsertProvider(ctx, &models.Provider{
		ID:                providerID,
		Name:              providerID,
		BaseURL:           baseURL,
		TrustTier:         tier,
		AttestationConfig: "{}",
		Pricing:           "{}",
	}); err != nil {
		t.Fatalf("upsert provider %s: %v", providerID, err)
	}

	if err := db.UpsertProviderModel(ctx, &models.ProviderModel{
		ProviderID: providerID,
		Model:      model,
		Mode:       models.ModeChat,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("upsert provider model %s/%s: %v", providerID, model, err)
	}

	if err := db.UpsertAttestation(ctx, &models.ProviderAttestation{
		ProviderID:     providerID,
		Model:          model,
		Mode:           models.ModeChat,
		Verified:       true,
		EvidenceDigest: "sha256:test",
		PolicyDigest:   "sha256:test",
		VerifiedClaims: "{}",
		ExpiresAt:      time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert attestation %s/%s: %v", providerID, model, err)
	}
}

func postChatCompletion(t *testing.T, baseURL string, apiKey string, body string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/chat/completions: %v", err)
	}
	return resp
}
