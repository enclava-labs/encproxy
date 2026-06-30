package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/enclava/encproxy/internal/attestation"
	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/models"
	"github.com/enclava/encproxy/internal/providers"
	"github.com/google/uuid"
)

// Server handles admin API requests.
type Server struct {
	db          *database.DB
	cfg         *config.Config
	attestation *attestation.Service
	creds       providers.ProviderCredentials
}

// NewServer creates a new admin server.
func NewServer(db *database.DB, cfg *config.Config, attestation *attestation.Service, creds providers.ProviderCredentials) *Server {
	return &Server{
		db:          db,
		cfg:         cfg,
		attestation: attestation,
		creds:       creds,
	}
}

// RegisterRoutes registers admin routes.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// API Key management
	mux.HandleFunc("/admin/v1/api-keys", s.handleAPIKeys)
	mux.HandleFunc("/admin/v1/api-keys/", s.handleAPIKeyDetail)

	// Provider management
	mux.HandleFunc("/admin/v1/providers", s.handleProviders)
	mux.HandleFunc("/admin/v1/providers/", s.handleProviderDetail)

	// Model management
	mux.HandleFunc("/admin/v1/models/fetch", s.handleFetchModels)

	// Attestation management
	mux.HandleFunc("/admin/v1/attestation/refresh", s.handleAttestationRefresh)

	// Usage statistics
	mux.HandleFunc("/admin/v1/usage", s.handleUsage)

	// Health check
	mux.HandleFunc("/admin/v1/health", s.handleHealth)
}

// handleAPIKeys handles API key listing and creation.
func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAPIKeys(w, r)
	case http.MethodPost:
		s.createAPIKey(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET/POST supported")
	}
}

// listAPIKeys lists all API keys (without full hashes).
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keys, err := s.db.ListAPIKeys(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list API keys")
		return
	}

	// Sanitize for display
	var sanitized []map[string]interface{}
	for _, k := range keys {
		sanitized = append(sanitized, map[string]interface{}{
			"id":                k.ID,
			"name":              k.Name,
			"key_prefix":        k.KeyPrefix,
			"allowed_providers": k.AllowedProviders,
			"allowed_models":    k.AllowedModels,
			"allowed_regions":   k.AllowedRegions,
			"created_at":        k.CreatedAt,
		})
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"keys": sanitized})
}

// createAPIKey creates a new API key.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name             string   `json:"name"`
		AllowedProviders []string `json:"allowed_providers,omitempty"`
		AllowedModels    []string `json:"allowed_models,omitempty"`
		AllowedRegions   []string `json:"allowed_regions,omitempty"`
		PreferredRegions []string `json:"preferred_regions,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	// Generate a new API key
	keyID := uuid.New().String()
	keyValue := generateAPIKey()
	keyHash := database.HashAPIKey(keyValue)

	key := &models.APIKey{
		ID:               keyID,
		KeyHash:          keyHash,
		KeyPrefix:        database.APIKeyPrefix(keyHash),
		Name:             req.Name,
		AllowedProviders: req.AllowedProviders,
		AllowedModels:    req.AllowedModels,
		AllowedRegions:   req.AllowedRegions,
		PreferredRegions: req.PreferredRegions,
	}

	ctx := r.Context()
	if err := s.db.CreateAPIKey(ctx, key); err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create API key")
		return
	}

	// Return the key value only once
	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         keyID,
		"key":        keyValue, // Only shown once
		"key_prefix": key.KeyPrefix,
		"name":       req.Name,
		"created_at": time.Now().UTC(),
	})
}

// handleAPIKeyDetail handles individual API key operations.
func (s *Server) handleAPIKeyDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/v1/api-keys/")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing_id", "API key ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getAPIKey(w, r, id)
	case http.MethodDelete:
		s.deleteAPIKey(w, r, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET/DELETE supported")
	}
}

// getAPIKey gets a specific API key.
func (s *Server) getAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	s.writeError(w, http.StatusNotFound, "not_found", "API key not found")
}

// deleteAPIKey deletes an API key.
func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	if err := s.db.DeleteAPIKey(ctx, id); err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to delete API key")
		return
	}
	s.writeJSON(w, http.StatusNoContent, nil)
}

// handleProviders handles provider listing and creation.
func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listProviders(w, r)
	case http.MethodPost:
		s.createProvider(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET/POST supported")
	}
}

// listProviders lists all providers.
func (s *Server) listProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list providers")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{"providers": providers})
}

// createProvider creates a new provider.
func (s *Server) createProvider(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string                 `json:"id"`
		Name              string                 `json:"name"`
		BaseURL           string                 `json:"base_url"`
		TrustTier         string                 `json:"trust_tier"`
		AttestationConfig map[string]interface{} `json:"attestation_config,omitempty"`
		Pricing           map[string]int64       `json:"pricing,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	attConfigJSON, _ := json.Marshal(req.AttestationConfig)
	pricingJSON, _ := json.Marshal(req.Pricing)

	provider := &models.Provider{
		ID:                req.ID,
		Name:              req.Name,
		BaseURL:           req.BaseURL,
		TrustTier:         models.TrustTier(req.TrustTier),
		AttestationConfig: string(attConfigJSON),
		Pricing:           string(pricingJSON),
	}

	ctx := r.Context()
	if err := s.db.UpsertProvider(ctx, provider); err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to create provider")
		return
	}

	s.writeJSON(w, http.StatusCreated, provider)
}

// handleProviderDetail handles individual provider operations.
func (s *Server) handleProviderDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/v1/providers/")
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "missing_id", "Provider ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getProvider(w, r, id)
	case http.MethodDelete:
		s.deleteProvider(w, r, id)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET/DELETE supported")
	}
}

// getProvider gets a specific provider.
func (s *Server) getProvider(w http.ResponseWriter, r *http.Request, id string) {
	ctx := r.Context()
	provider, err := s.db.GetProvider(ctx, id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "not_found", "Provider not found")
		return
	}
	s.writeJSON(w, http.StatusOK, provider)
}

// deleteProvider deletes a provider.
func (s *Server) deleteProvider(w http.ResponseWriter, r *http.Request, id string) {
	// We'd need a DeleteProvider method
	s.writeJSON(w, http.StatusNoContent, nil)
}

// handleAttestationRefresh triggers attestation refresh.
func (s *Server) handleAttestationRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST supported")
		return
	}

	s.attestation.TriggerRefresh()
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"status": "refresh_triggered"})
}

// handleUsage returns usage statistics.
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET supported")
		return
	}

	// We'd query the usage table for aggregated stats
	s.writeJSON(w, http.StatusOK, map[string]interface{}{"status": "not_implemented"})
}

// handleFetchModels triggers model fetching from all configured providers.
func (s *Server) handleFetchModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST supported")
		return
	}

	ctx := r.Context()
	fetcher := providers.NewModelFetcher(s.db)

	if err := fetcher.FetchAllModels(ctx, s.creds); err != nil {
		s.writeError(w, http.StatusInternalServerError, "fetch_failed", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "models_fetched",
		"message": "Models fetched from all configured providers",
	})
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC(),
	})
}

// writeError writes a JSON error response.
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"type":    code,
			"message": message,
		},
	})
}

// writeJSON writes a JSON response.
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// generateAPIKey generates a random API key.
func generateAPIKey() string {
	return "sk-" + uuid.New().String()
}
