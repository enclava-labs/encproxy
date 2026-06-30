package routing

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/models"
)

func TestCalculateCost(t *testing.T) {
	tests := []struct {
		promptTokens     int64
		completionTokens int64
		pricePer1M       float64
		want             int64
	}{
		// 1000 tokens @ 1500 micro-USD per 1M = 1.5 micro-USD ~ 2
		{500, 500, 1500, 2},
		// 1M tokens @ 1500 micro-USD per 1M = 1500 micro-USD
		{500000, 500000, 1500, 1500},
		// 0 tokens
		{0, 0, 1500, 0},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := CalculateCost(tt.promptTokens, tt.completionTokens, tt.pricePer1M)
			if got != tt.want {
				t.Errorf("CalculateCost(%d, %d, %f) = %d, want %d",
					tt.promptTokens, tt.completionTokens, tt.pricePer1M, got, tt.want)
			}
		})
	}
}

func TestEstimateTokens(t *testing.T) {
	tests := []struct {
		charCount int
		want      int64
	}{
		// ~4 chars per token
		{0, 0},
		{4, 1},
		{100, 25},
		{400, 100},
		{401, 101}, // Rounds up
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := EstimateTokens(tt.charCount)
			if got != tt.want {
				t.Errorf("EstimateTokens(%d) = %d, want %d", tt.charCount, got, tt.want)
			}
		})
	}
}

func TestRetryableHTTPStatus(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{200, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{408, true}, // Request Timeout
		{429, true}, // Too Many Requests
		{500, false},
		{502, true}, // Bad Gateway
		{503, true}, // Service Unavailable
		{504, true}, // Gateway Timeout
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := RetryableHTTPStatus(tt.status)
			if got != tt.want {
				t.Errorf("RetryableHTTPStatus(%d) = %v, want %v", tt.status, got, tt.want)
			}
		})
	}
}

func TestFailoverState(t *testing.T) {
	fs := &FailoverState{}

	// Initially should allow retry
	if !fs.ShouldRetry(3) {
		t.Error("ShouldRetry should be true initially")
	}

	// Mark first attempt
	fs.MarkAttempted("provider1")
	if !fs.ShouldRetry(3) {
		t.Error("ShouldRetry should be true after 1 attempt")
	}

	// Mark second attempt
	fs.MarkAttempted("provider2")
	if !fs.ShouldRetry(3) {
		t.Error("ShouldRetry should be true after 2 attempts")
	}

	// Mark third attempt
	fs.MarkAttempted("provider3")
	if fs.ShouldRetry(3) {
		t.Error("ShouldRetry should be false after max retries")
	}
}

func TestRoutingError(t *testing.T) {
	tests := []struct {
		code    string
		message string
		want    bool
	}{
		{"no_verified_provider", "msg", false},
		{"provider_not_allowed", "msg", false},
		{"no_suitable_provider", "msg", false},
		{"network_error", "msg", true},
		{"timeout", "msg", true},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := &RoutingError{Code: tt.code, Message: tt.message}
			got := err.IsRetryable()
			if got != tt.want {
				t.Errorf("IsRetryable() for %s = %v, want %v", tt.code, got, tt.want)
			}
		})
	}
}

func TestRedactError(t *testing.T) {
	original := &RoutingError{Code: "upstream_error", Message: "connection refused"}

	tests := []struct {
		tier models.TrustTier
		want string
	}{
		{models.TrustTierConfidential, "provider_error"},
		{models.TrustTierEncrypted, "provider_error"},
		{models.TrustTierPlaintext, "upstream_error"},
	}

	for _, tt := range tests {
		t.Run(string(tt.tier), func(t *testing.T) {
			got := RedactError(original, tt.tier)
			routingErr, ok := got.(*RoutingError)
			if !ok {
				t.Error("Expected RoutingError")
				return
			}
			if routingErr.Code != tt.want {
				t.Errorf("Code = %s, want %s", routingErr.Code, tt.want)
			}
		})
	}
}

func TestSelectProviderRequiresConfidentialCapableTier(t *testing.T) {
	ctx := context.Background()
	db := newRoutingTestDB(t)
	defer db.Close()

	addVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, "openai/secure-model")
	addVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "tinfoil/secure-model")

	router := NewRouter(db)
	route, err := router.SelectProvider(ctx, SelectionCriteria{
		RequestedModel: "secure-model",
		RequestedMode:  models.ModeChat,
		RequiredTier:   models.TrustTierConfidential,
	})
	if err != nil {
		t.Fatalf("SelectProvider returned error: %v", err)
	}
	if route.Provider.TrustTier == models.TrustTierPlaintext {
		t.Fatalf("selected plaintext provider %q for confidential route", route.Provider.ID)
	}
}

func TestSelectProviderRejectsRemoteHostedModelFamilies(t *testing.T) {
	ctx := context.Background()
	db := newRoutingTestDB(t)
	defer db.Close()

	addVerifiedRoute(t, ctx, db, "redpill", models.TrustTierConfidential, "anthropic/claude-opus-4")

	router := NewRouter(db)
	_, err := router.SelectProvider(ctx, SelectionCriteria{
		RequestedModel: "claude-opus-4",
		RequestedMode:  models.ModeChat,
		RequiredTier:   models.TrustTierConfidential,
	})
	if err == nil {
		t.Fatal("SelectProvider succeeded for remote-hosted Anthropic model")
	}
	routingErr, ok := err.(*RoutingError)
	if !ok || routingErr.Code != "no_suitable_provider" {
		t.Fatalf("SelectProvider error = %v, want no_suitable_provider", err)
	}
}

func TestNextProviderPreservesConfidentialTierAndAllowedProviders(t *testing.T) {
	ctx := context.Background()
	db := newRoutingTestDB(t)
	defer db.Close()

	addVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "tinfoil/secure-model")
	addVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, "openai/secure-model")
	addVerifiedRoute(t, ctx, db, "near", models.TrustTierEncrypted, "near/secure-model")
	addVerifiedRoute(t, ctx, db, "nanogpt", models.TrustTierConfidential, "TEE/secure-model")

	router := NewRouter(db)
	route, err := router.NextProvider(ctx, SelectionCriteria{
		RequestedModel:   "secure-model",
		RequestedMode:    models.ModeChat,
		AllowedProviders: []string{"tinfoil", "near"},
		RequiredTier:     models.TrustTierConfidential,
	}, &FailoverState{AttemptedProviders: []string{"tinfoil"}})
	if err != nil {
		t.Fatalf("NextProvider returned error: %v", err)
	}
	if route.Provider.ID != "near" {
		t.Fatalf("NextProvider selected %q, want near", route.Provider.ID)
	}
	if route.Provider.TrustTier == models.TrustTierPlaintext {
		t.Fatalf("selected plaintext provider %q for confidential failover", route.Provider.ID)
	}
}

func TestNextProviderDoesNotFailOverToPlaintext(t *testing.T) {
	ctx := context.Background()
	db := newRoutingTestDB(t)
	defer db.Close()

	addVerifiedRoute(t, ctx, db, "tinfoil", models.TrustTierConfidential, "tinfoil/secure-model")
	addVerifiedRoute(t, ctx, db, "plain", models.TrustTierPlaintext, "openai/secure-model")

	router := NewRouter(db)
	_, err := router.NextProvider(ctx, SelectionCriteria{
		RequestedModel: "secure-model",
		RequestedMode:  models.ModeChat,
		RequiredTier:   models.TrustTierConfidential,
	}, &FailoverState{AttemptedProviders: []string{"tinfoil"}})
	if err == nil {
		t.Fatal("NextProvider succeeded with only plaintext failover available")
	}
	routingErr, ok := err.(*RoutingError)
	if !ok || routingErr.Code != "no_failover_available" {
		t.Fatalf("NextProvider error = %v, want no_failover_available", err)
	}
}

func BenchmarkCalculateCost(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CalculateCost(500000, 500000, 1500)
	}
}

func newRoutingTestDB(t *testing.T) *database.DB {
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

func addVerifiedRoute(t *testing.T, ctx context.Context, db *database.DB, providerID string, tier models.TrustTier, model string) {
	t.Helper()

	if err := db.UpsertProvider(ctx, &models.Provider{
		ID:                providerID,
		Name:              providerID,
		BaseURL:           "http://example.test",
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
