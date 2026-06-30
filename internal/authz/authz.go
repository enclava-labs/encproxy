package authz

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/models"
)

// Authorizer handles API key authorization.
type Authorizer struct {
	db *database.DB
}

// NewAuthorizer creates a new authorizer.
func NewAuthorizer(db *database.DB) *Authorizer {
	return &Authorizer{db: db}
}

// AuthorizationResult contains the result of an authorization check.
type AuthorizationResult struct {
	APIKey        *models.APIKey
	Allowed       bool
	Reason        string
	TargetModels  []string
	TargetRegions []string
}

// AuthorizeRequest authorizes a request based on the API key and requested model.
func (a *Authorizer) AuthorizeRequest(ctx context.Context, keyHash, requestedModel string, requestedRegions []string) (*AuthorizationResult, error) {
	key, err := a.db.GetAPIKeyByHash(ctx, keyHash)
	if err != nil {
		return &AuthorizationResult{Allowed: false, Reason: "invalid_api_key"}, nil
	}

	// Check if model is allowed
	if len(key.AllowedModels) > 0 {
		found := false
		for _, m := range key.AllowedModels {
			if matchesModel(m, requestedModel) {
				found = true
				break
			}
		}
		if !found {
			return &AuthorizationResult{
				APIKey: key,
				Allowed: false,
				Reason:  "model_not_allowed",
			}, nil
		}
	}

	// Check region restrictions
	if len(key.AllowedRegions) > 0 && len(requestedRegions) > 0 {
		for _, reqRegion := range requestedRegions {
			found := false
			for _, allowedRegion := range key.AllowedRegions {
				if normalizeRegion(reqRegion) == normalizeRegion(allowedRegion) {
					found = true
					break
				}
			}
			if !found {
				return &AuthorizationResult{
					APIKey: key,
					Allowed: false,
					Reason:  "region_not_allowed",
				}, nil
			}
		}
	}

	// Determine target models
	targetModels := []string{requestedModel}
	if len(key.AllowedModels) > 0 {
		targetModels = filterModels(key.AllowedModels, requestedModel)
	}

	// Determine target regions
	targetRegions := requestedRegions
	if len(key.PreferredRegions) > 0 {
		targetRegions = prioritizeRegions(key.PreferredRegions, requestedRegions)
	}
	if len(key.AllowedRegions) > 0 && len(targetRegions) == 0 {
		targetRegions = key.AllowedRegions
	}

	return &AuthorizationResult{
		APIKey:        key,
		Allowed:       true,
		TargetModels:  targetModels,
		TargetRegions: targetRegions,
	}, nil
}

// CheckProviderAllowed checks if a provider is allowed for a key.
func (a *Authorizer) CheckProviderAllowed(key *models.APIKey, providerID string) bool {
	if len(key.AllowedProviders) == 0 {
		return true
	}
	// If providerID is empty, allow (may be an internal/internal call)
	if providerID == "" {
		return true
	}
	for _, p := range key.AllowedProviders {
		if p == providerID {
			return true
		}
	}
	return false
}

// matchesModel checks if a pattern matches a model.
func matchesModel(pattern, model string) bool {
	pattern = strings.ToLower(pattern)
	model = strings.ToLower(model)

	// Exact match
	if pattern == model {
		return true
	}

	// Wildcard prefix match (e.g., "meta-llama/*")
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if strings.HasPrefix(model, prefix+"/") {
			return true
		}
	}

	// Wildcard suffix match (e.g., "*/llama-3")
	if strings.HasPrefix(pattern, "*/") {
		suffix := strings.TrimPrefix(pattern, "*/")
		if strings.HasSuffix(model, "/"+suffix) || strings.HasSuffix(model, "-"+suffix) {
			return true
		}
	}

	return false
}

// filterModels filters allowed models based on request.
func filterModels(allowed []string, requested string) []string {
	var result []string
	for _, m := range allowed {
		if matchesModel(m, requested) {
			result = append(result, requested)
		}
	}
	return result
}

// normalizeRegion normalizes a region string.
func normalizeRegion(region string) string {
	return strings.ToLower(strings.TrimSpace(region))
}

// prioritizeRegions reorders regions based on preferences.
func prioritizeRegions(preferred, requested []string) []string {
	if len(requested) == 0 {
		return preferred
	}

	// Build set of requested regions
	requestedSet := make(map[string]bool)
	for _, r := range requested {
		requestedSet[normalizeRegion(r)] = true
	}

	// First add preferred regions that are in requested
	var result []string
	for _, p := range preferred {
		normP := normalizeRegion(p)
		if requestedSet[normP] {
			result = append(result, p)
		}
	}

	// Then add remaining requested regions
	for _, r := range requested {
		normR := normalizeRegion(r)
		found := false
		for _, p := range preferred {
			if normalizeRegion(p) == normR {
				found = true
				break
			}
		}
		if !found {
			result = append(result, r)
		}
	}

	return result
}

// ParseAPIKey extracts the key from an Authorization header.
func ParseAPIKey(header string) string {
	header = strings.TrimSpace(header)
	// Handle "Bearer sk-..." format
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	// Handle direct key
	return strings.TrimSpace(header)
}

// APIKeyMiddleware extracts and validates API keys from requests.
type APIKeyMiddleware struct {
	authorizer *Authorizer
}

// NewAPIKeyMiddleware creates a new API key middleware.
func NewAPIKeyMiddleware(authorizer *Authorizer) *APIKeyMiddleware {
	return &APIKeyMiddleware{authorizer: authorizer}
}

// ContextKey is used to store values in context.
type ContextKey string

const (
	// ContextKeyAPIKey stores the API key in context.
	ContextKeyAPIKey = ContextKey("api_key")
	// ContextKeyAuthResult stores the auth result in context.
	ContextKeyAuthResult = ContextKey("auth_result")
)

// AuthError represents an authorization error.
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// MarshalJSON returns a JSON error response.
func (e *AuthError) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"error": map[string]string{
			"type":    e.Code,
			"message": e.Message,
		},
	})
}
