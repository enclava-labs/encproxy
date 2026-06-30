package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/modelpolicy"
	"github.com/enclava/encproxy/internal/models"
)

// Router handles provider selection and request routing.
type Router struct {
	db *database.DB
}

// NewRouter creates a new router.
func NewRouter(db *database.DB) *Router {
	return &Router{db: db}
}

// Route represents a selected provider route.
type Route struct {
	Provider      *models.Provider
	Model         string
	Mode          models.Mode
	Region        string
	TrustTier     models.TrustTier
	NeedsEHBP     bool // Whether to use EHBP body encryption
	EHBPKeyConfig []byte
	SecureClient  interface{} // *tinfoilClient.SecureClient for Tinfoil
}

// SelectionCriteria contains criteria for provider selection.
type SelectionCriteria struct {
	RequestedModel   string
	RequestedMode    models.Mode
	AllowedProviders []string
	PreferredRegions []string
	AllowedRegions   []string
	RequiredTier     models.TrustTier
}

// SelectProvider selects the best provider for a request.
func (r *Router) SelectProvider(ctx context.Context, criteria SelectionCriteria) (*Route, error) {
	// Get verified providers for this model
	verifiedModels, err := r.db.GetProviderModelsWithVerification(ctx, criteria.RequestedModel, criteria.RequestedMode)
	if err != nil {
		return nil, fmt.Errorf("get verified providers: %w", err)
	}

	if len(verifiedModels) == 0 {
		return nil, &RoutingError{Code: "no_verified_provider", Message: "no verified provider available for this model"}
	}

	// Filter by allowed providers
	var candidates []*models.ProviderModel
	for _, vm := range verifiedModels {
		if len(criteria.AllowedProviders) > 0 {
			found := false
			for _, ap := range criteria.AllowedProviders {
				if ap == vm.ProviderID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		candidates = append(candidates, vm)
	}

	if len(candidates) == 0 {
		return nil, &RoutingError{Code: "provider_not_allowed", Message: "no allowed providers available for this model"}
	}

	// Get full provider details for candidates
	var routes []*Route
	for _, c := range candidates {
		provider, err := r.db.GetProvider(ctx, c.ProviderID)
		if err != nil {
			continue
		}

		if !meetsRequiredTier(provider.TrustTier, criteria.RequiredTier) {
			continue
		}
		if !modelEligibleForRoute(provider, c.Model, criteria.RequestedMode) {
			continue
		}

		// Check region constraints
		if len(criteria.AllowedRegions) > 0 {
			// Hard constraint: provider must be in allowed regions
			// For now, we don't have per-provider region data in DB
			// This would be extended with provider region metadata
		}

		route := &Route{
			Provider:  provider,
			Model:     c.Model,
			Mode:      c.Mode,
			TrustTier: provider.TrustTier,
			NeedsEHBP: needsEHBP(provider),
		}
		routes = append(routes, route)
	}

	if len(routes) == 0 {
		return nil, &RoutingError{Code: "no_suitable_provider", Message: "no suitable provider available for the given constraints"}
	}

	// Score and rank routes
	scored := r.scoreRoutes(routes, criteria)

	// Return the best route
	return scored[0].route, nil
}

// scoredRoute wraps a route with its score.
type scoredRoute struct {
	route *Route
	score float64
}

// scoreRoutes scores routes based on various criteria.
func (r *Router) scoreRoutes(routes []*Route, criteria SelectionCriteria) []scoredRoute {
	var scored []scoredRoute

	for _, route := range routes {
		score := 0.0

		// Trust tier scoring (higher is better)
		switch route.Provider.TrustTier {
		case models.TrustTierConfidential:
			score += 100
		case models.TrustTierEncrypted:
			score += 50
		case models.TrustTierPlaintext:
			score += 10
		}

		// Region preference scoring
		if len(criteria.PreferredRegions) > 0 {
			// For now, simulate region matching - would need provider region metadata
			for _, pr := range criteria.PreferredRegions {
				if pr != "" {
					score += 10 // Preferred region match
					break
				}
			}
		}

		// Add small random factor for load balancing
		score += rand.Float64() * 5

		scored = append(scored, scoredRoute{route: route, score: score})
	}

	// Sort by score descending
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[j].score > scored[i].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	return scored
}

// needsEHBP checks if a provider needs EHBP encryption.
func needsEHBP(p *models.Provider) bool {
	// PPQ-private uses EHBP
	var attConfig map[string]interface{}
	if err := json.Unmarshal([]byte(p.AttestationConfig), &attConfig); err == nil {
		if useProxy, ok := attConfig["use_proxy"].(bool); ok && useProxy {
			return false
		}
		if useProxy, ok := attConfig["UseProxy"].(bool); ok && useProxy {
			return false
		}
		if attType, ok := attConfig["type"].(string); ok && attType == "ppq-private" {
			return true
		}
		if attType, ok := attConfig["Type"].(string); ok && attType == "ppq-private" {
			return true
		}
	}
	return false
}

func meetsRequiredTier(providerTier, requiredTier models.TrustTier) bool {
	switch requiredTier {
	case "":
		return true
	case models.TrustTierPlaintext:
		return true
	case models.TrustTierConfidential, models.TrustTierEncrypted:
		return providerTier == models.TrustTierConfidential || providerTier == models.TrustTierEncrypted
	default:
		return providerTier == requiredTier
	}
}

func modelEligibleForRoute(provider *models.Provider, model string, mode models.Mode) bool {
	if mode == models.ModeChat && !modelpolicy.SupportsChatCompletions(model) {
		return false
	}
	return modelpolicy.IsProviderModelTEEEligible(provider.ID, model)
}

// RoutingError represents a routing error.
type RoutingError struct {
	Code    string
	Message string
}

func (e *RoutingError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// IsRetryable checks if the error is retryable.
func (e *RoutingError) IsRetryable() bool {
	switch e.Code {
	case "no_verified_provider", "provider_not_allowed", "no_suitable_provider":
		return false
	default:
		return true
	}
}

// FailoverState tracks failover attempts.
type FailoverState struct {
	AttemptedProviders []string
	LastError          error
}

// ShouldRetry checks if we should retry with another provider.
func (fs *FailoverState) ShouldRetry(maxRetries int) bool {
	return len(fs.AttemptedProviders) < maxRetries
}

// MarkAttempted marks a provider as attempted.
func (fs *FailoverState) MarkAttempted(providerID string) {
	fs.AttemptedProviders = append(fs.AttemptedProviders, providerID)
}

// NextProvider selects the next provider avoiding attempted ones.
func (r *Router) NextProvider(ctx context.Context, criteria SelectionCriteria, state *FailoverState) (*Route, error) {
	// Get all candidates
	verifiedModels, err := r.db.GetProviderModelsWithVerification(ctx, criteria.RequestedModel, criteria.RequestedMode)
	if err != nil {
		return nil, err
	}

	var routes []*Route
	for _, vm := range verifiedModels {
		// Skip already attempted
		attempted := false
		for _, ap := range state.AttemptedProviders {
			if ap == vm.ProviderID {
				attempted = true
				break
			}
		}
		if attempted {
			continue
		}

		// Apply filters
		if len(criteria.AllowedProviders) > 0 {
			found := false
			for _, ap := range criteria.AllowedProviders {
				if ap == vm.ProviderID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		provider, err := r.db.GetProvider(ctx, vm.ProviderID)
		if err != nil {
			continue
		}

		if !meetsRequiredTier(provider.TrustTier, criteria.RequiredTier) {
			continue
		}
		if !modelEligibleForRoute(provider, vm.Model, criteria.RequestedMode) {
			continue
		}

		routes = append(routes, &Route{
			Provider:  provider,
			Model:     vm.Model,
			Mode:      vm.Mode,
			TrustTier: provider.TrustTier,
			NeedsEHBP: needsEHBP(provider),
		})
	}

	if len(routes) == 0 {
		return nil, &RoutingError{Code: "no_failover_available", Message: "no additional providers available for failover"}
	}

	scored := r.scoreRoutes(routes, criteria)
	return scored[0].route, nil
}

// CalculateCost estimates the cost of a request.
func CalculateCost(promptTokens, completionTokens int64, pricePer1M float64) int64 {
	totalTokens := promptTokens + completionTokens
	// Price is in micro-USD per 1M tokens
	// Cost = tokens * price / 1M
	cost := float64(totalTokens) * pricePer1M / 1e6
	return int64(math.Round(cost))
}

// EstimateTokens estimates token count from character count.
// Rough approximation: ~4 characters per token.
func EstimateTokens(charCount int) int64 {
	return int64(math.Ceil(float64(charCount) / 4.0))
}

// RetryableHTTPStatus checks if an HTTP status warrants retry.
func RetryableHTTPStatus(status int) bool {
	switch status {
	case 502, 503, 504, 429: // Bad Gateway, Service Unavailable, Gateway Timeout, Too Many Requests
		return true
	case 408, 423: // Request Timeout, Locked
		return true
	default:
		return false
	}
}

// RedactError redacts error messages for confidential providers.
func RedactError(err error, tier models.TrustTier) error {
	if tier == models.TrustTierConfidential || tier == models.TrustTierEncrypted {
		// For confidential providers, return generic error
		return &RoutingError{
			Code:    "provider_error",
			Message: "an error occurred with the confidential provider",
		}
	}
	return err
}

// init seeds the random number generator.
func init() {
	rand.Seed(time.Now().UnixNano())
}
