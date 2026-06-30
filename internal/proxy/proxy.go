package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/enclava/encproxy/internal/attestation"
	"github.com/enclava/encproxy/internal/authz"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/ehbp"
	"github.com/enclava/encproxy/internal/modelpolicy"
	"github.com/enclava/encproxy/internal/models"
	"github.com/enclava/encproxy/internal/routing"
	"github.com/enclava/encproxy/internal/usage"
	"github.com/google/uuid"
)

// Server handles proxy requests.
type Server struct {
	db               *database.DB
	router           *routing.Router
	authorizer       *authz.Authorizer
	attestation      *attestation.Service
	usage            *usage.Service
	httpClient       *http.Client
	maxReqBytes      int64
	providerKeys     map[string]string // providerID -> API key
	confidentialOnly bool              // Only serve confidential/encrypted models
}

// NewServer creates a new proxy server.
func NewServer(db *database.DB, router *routing.Router, authorizer *authz.Authorizer, attestation *attestation.Service, usage *usage.Service, maxReqBytes int64, providerKeys map[string]string, confidentialOnly bool) *Server {
	return &Server{
		db:               db,
		router:           router,
		authorizer:       authorizer,
		attestation:      attestation,
		usage:            usage,
		httpClient:       &http.Client{Timeout: 120 * time.Second},
		maxReqBytes:      maxReqBytes,
		providerKeys:     providerKeys,
		confidentialOnly: confidentialOnly,
	}
}

// RegisterRoutes registers proxy routes.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	mux.HandleFunc("/v1/models", s.handleListModels)
	mux.HandleFunc("/v1/confidentiality", s.handleConfidentialityStatus)
}

// handleChatCompletions handles chat completion requests.
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST is supported")
		return
	}

	ctx := r.Context()
	startTime := time.Now()
	requestID := uuid.New().String()

	// Extract and validate API key
	authHeader := r.Header.Get("Authorization")
	apiKey := authz.ParseAPIKey(authHeader)
	if apiKey == "" {
		s.writeError(w, http.StatusUnauthorized, "missing_api_key", "Authorization header is required")
		return
	}

	keyHash := database.HashAPIKey(apiKey)
	keyPrefix := database.APIKeyPrefix(keyHash)

	// Read and parse request body
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxReqBytes))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to read request body")
		return
	}
	defer r.Body.Close()

	var req models.ChatCompletionRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request JSON")
		return
	}

	if req.Model == "" {
		s.writeError(w, http.StatusBadRequest, "missing_model", "Model is required")
		return
	}

	// Authorize request
	authResult, err := s.authorizer.AuthorizeRequest(ctx, keyHash, req.Model, nil)
	if err != nil || !authResult.Allowed {
		code := "unauthorized"
		if authResult.Reason != "" {
			code = authResult.Reason
		}
		s.writeError(w, http.StatusForbidden, code, "Request not authorized")
		return
	}

	// Determine required trust tier
	requiredTier := models.TrustTierConfidential

	// Select provider
	criteria := routing.SelectionCriteria{
		RequestedModel:   req.Model,
		RequestedMode:    models.ModeChat,
		AllowedProviders: authResult.APIKey.AllowedProviders,
		PreferredRegions: authResult.TargetRegions,
		AllowedRegions:   authResult.APIKey.AllowedRegions,
		RequiredTier:     requiredTier,
	}

	route, err := s.router.SelectProvider(ctx, criteria)
	if err != nil {
		if routingErr, ok := err.(*routing.RoutingError); ok {
			s.writeError(w, http.StatusServiceUnavailable, routingErr.Code, routingErr.Message)
		} else {
			s.writeError(w, http.StatusServiceUnavailable, "routing_failed", err.Error())
		}
		s.recordUsage(ctx, requestID, keyPrefix, "", req.Model, models.ModeChat, "error",
			time.Since(startTime).Milliseconds(), 0, 0, 0, "routing_failed", err.Error())
		return
	}

	// Check provider is allowed for this key
	if !s.authorizer.CheckProviderAllowed(authResult.APIKey, route.Provider.ID) {
		s.writeError(w, http.StatusForbidden, "provider_not_allowed", "Provider not allowed for this API key")
		return
	}

	// Stream or non-stream handling
	if req.Stream {
		s.handleStreamingRequest(ctx, w, r, &req, route, criteria, authResult.APIKey, requestID, keyPrefix, body, startTime)
	} else {
		s.handleNonStreamingRequest(ctx, w, r, &req, route, criteria, authResult.APIKey, &routing.FailoverState{}, requestID, keyPrefix, body, startTime)
	}
}

// handleNonStreamingRequest handles non-streaming chat completion.
func (s *Server) handleNonStreamingRequest(ctx context.Context, w http.ResponseWriter, r *http.Request,
	req *models.ChatCompletionRequest, route *routing.Route, criteria routing.SelectionCriteria, apiKey *models.APIKey, failoverState *routing.FailoverState, requestID, keyPrefix string,
	originalBody []byte, startTime time.Time) {

	// Prepare request body
	bodyToSend, err := buildUpstreamRequestBody(originalBody, route.Provider.ID, route.Model, false)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "Failed to prepare upstream request")
		return
	}

	// Apply EHBP encryption if needed (PPQ-private)
	if route.NeedsEHBP {
		vc, err := s.attestation.GetVerifiedClient(route.Provider.ID, route.Model, models.ModeChat)
		if err != nil {
			s.writeError(w, http.StatusServiceUnavailable, "attestation_error", "Failed to get verified client")
			s.recordUsage(ctx, requestID, keyPrefix, route.Provider.ID, req.Model, models.ModeChat, "error",
				time.Since(startTime).Milliseconds(), 0, 0, 0, "attestation_error", err.Error())
			return
		}

		if vc.HPKEPublicKey != nil {
			// Parse key config from attestation
			keyConfig := buildEHBPKeyConfig(vc.HPKEPublicKey)

			encrypted, err := ehbp.EncryptRequest(keyConfig, bodyToSend)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "encryption_error", "Failed to encrypt request")
				s.recordUsage(ctx, requestID, keyPrefix, route.Provider.ID, req.Model, models.ModeChat, "error",
					time.Since(startTime).Milliseconds(), 0, 0, 0, "encryption_error", err.Error())
				return
			}

			bodyToSend = encrypted.Body

			// Store exported secret for response decryption
			ctx = context.WithValue(ctx, "ehbp_exported_secret", encrypted.ExportedSecret)
			ctx = context.WithValue(ctx, "ehbp_request_enc", encrypted.EncapsulatedKey)
			ctx = context.WithValue(ctx, "ehbp_verified_client", vc)
		}
	}

	// Forward request to provider
	providerURL, _ := providerEndpoint(route.Provider.BaseURL, "chat/completions")

	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, providerURL.String(), bytes.NewReader(bodyToSend))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "proxy_error", "Failed to create upstream request")
		return
	}

	// Copy headers
	for k, v := range r.Header {
		if k != "Authorization" && k != "Content-Length" {
			upstreamReq.Header[k] = v
		}
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("X-Request-ID", requestID)
	if route.NeedsEHBP {
		if requestEnc, ok := ctx.Value("ehbp_request_enc").([]byte); ok {
			upstreamReq.Header.Set("Ehbp-Encapsulated-Key", hex.EncodeToString(requestEnc))
		}
		if vc, ok := ctx.Value("ehbp_verified_client").(*attestation.VerifiedClient); ok {
			if enclaveHost, ok := vc.Claims["enclave"].(string); ok && enclaveHost != "" {
				upstreamReq.Header.Set("X-Tinfoil-Enclave-Url", "https://"+enclaveHost)
			}
		}
		if route.Provider.ID == "ppq" {
			upstreamReq.Header.Set("X-Private-Model", route.Model)
			upstreamReq.Header.Set("x-query-source", "api")
		}
	}
	// Inject the provider's API key
	if providerKey, ok := s.providerKeys[route.Provider.ID]; ok && providerKey != "" {
		upstreamReq.Header.Set("Authorization", "Bearer "+providerKey)
	}

	// Execute request
	resp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		err = routing.RedactError(err, route.TrustTier)
		s.writeError(w, http.StatusBadGateway, "upstream_error", err.Error())
		s.recordUsage(ctx, requestID, keyPrefix, route.Provider.ID, req.Model, models.ModeChat, "error",
			time.Since(startTime).Milliseconds(), 0, 0, 0, "upstream_error", err.Error())
		return
	}
	defer resp.Body.Close()

	// Handle retryable errors
	if routing.RetryableHTTPStatus(resp.StatusCode) {
		// Try failover
		failoverState.LastError = fmt.Errorf("status %d", resp.StatusCode)
		failoverState.MarkAttempted(route.Provider.ID)

		nextRoute, err := s.router.NextProvider(ctx, criteria, failoverState)
		if err == nil && s.authorizer.CheckProviderAllowed(apiKey, nextRoute.Provider.ID) {
			// Retry with next provider
			s.handleNonStreamingRequest(ctx, w, r, req, nextRoute, criteria, apiKey, failoverState, requestID, keyPrefix, originalBody, startTime)
			return
		}
	}

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, s.maxReqBytes*10))
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "upstream_error", "Failed to read response")
		return
	}

	// Decrypt EHBP response if needed
	if route.NeedsEHBP {
		if exportedSecret, ok := ctx.Value("ehbp_exported_secret").([]byte); ok {
			if requestEnc, ok := ctx.Value("ehbp_request_enc").([]byte); ok {
				// Extract response nonce from headers
				responseNonce := extractResponseNonce(resp.Header)
				if responseNonce != nil {
					decrypted, err := ehbp.DecryptResponse(exportedSecret, requestEnc, responseNonce, respBody)
					if err != nil {
						log.Printf("Failed to decrypt EHBP response: %v", err)
					} else {
						respBody = decrypted
					}
				}
			}
		}
	}

	// Parse for usage tracking
	var chatResp models.ChatCompletionResponse
	if err := json.Unmarshal(respBody, &chatResp); err == nil {
		var promptTokens, completionTokens int64
		if chatResp.Usage != nil {
			promptTokens = chatResp.Usage.PromptTokens
			completionTokens = chatResp.Usage.CompletionTokens
		}

		// Calculate cost estimate
		cost := int64(0)
		var pricing map[string]int64
		if err := json.Unmarshal([]byte(route.Provider.Pricing), &pricing); err == nil {
			if price, ok := pricing[req.Model]; ok {
				cost = routing.CalculateCost(promptTokens, completionTokens, float64(price)/1e6)
			}
		}

		s.recordUsage(ctx, requestID, keyPrefix, route.Provider.ID, req.Model, models.ModeChat, "success",
			time.Since(startTime).Milliseconds(), promptTokens, completionTokens, cost, "", "")
	} else {
		s.recordUsage(ctx, requestID, keyPrefix, route.Provider.ID, req.Model, models.ModeChat, "success",
			time.Since(startTime).Milliseconds(), 0, 0, 0, "", "")
	}

	// Return response to client
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleStreamingRequest handles streaming (SSE) chat completion.
func (s *Server) handleStreamingRequest(ctx context.Context, w http.ResponseWriter, r *http.Request,
	req *models.ChatCompletionRequest, route *routing.Route, criteria routing.SelectionCriteria, apiKey *models.APIKey,
	requestID, keyPrefix string, originalBody []byte, startTime time.Time) {

	// Ensure we can flush
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "streaming_error", "Streaming not supported")
		return
	}

	currentRoute := route
	failoverState := &routing.FailoverState{}

	for {
		if currentRoute.NeedsEHBP {
			failoverState.MarkAttempted(currentRoute.Provider.ID)
			nextRoute, err := s.router.NextProvider(ctx, criteria, failoverState)
			if err == nil && s.authorizer.CheckProviderAllowed(apiKey, nextRoute.Provider.ID) {
				currentRoute = nextRoute
				continue
			}
			s.writeStreamingError(w, http.StatusServiceUnavailable, "streaming_not_supported", "Streaming is not supported for encrypted providers")
			return
		}

		body, err := buildUpstreamRequestBody(originalBody, currentRoute.Provider.ID, currentRoute.Model, true)
		if err != nil {
			s.writeStreamingError(w, http.StatusBadRequest, "invalid_request", "Failed to prepare upstream request")
			return
		}

		// Forward to provider
		providerURL, _ := providerEndpoint(currentRoute.Provider.BaseURL, "chat/completions")

		upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, providerURL.String(), bytes.NewReader(body))
		if err != nil {
			s.writeStreamingError(w, http.StatusInternalServerError, "proxy_error", "Failed to create upstream request")
			return
		}

		for k, v := range r.Header {
			if k != "Authorization" && k != "Content-Length" {
				upstreamReq.Header[k] = v
			}
		}
		upstreamReq.Header.Set("Content-Type", "application/json")
		upstreamReq.Header.Set("Accept", "text/event-stream")
		upstreamReq.Header.Set("X-Request-ID", requestID)
		// Inject the provider's API key
		if providerKey, ok := s.providerKeys[currentRoute.Provider.ID]; ok && providerKey != "" {
			upstreamReq.Header.Set("Authorization", "Bearer "+providerKey)
		}

		// Execute request
		resp, err := s.httpClient.Do(upstreamReq)
		if err != nil {
			failoverState.MarkAttempted(currentRoute.Provider.ID)
			nextRoute, nextErr := s.router.NextProvider(ctx, criteria, failoverState)
			if nextErr == nil && s.authorizer.CheckProviderAllowed(apiKey, nextRoute.Provider.ID) {
				currentRoute = nextRoute
				continue
			}

			err = routing.RedactError(err, currentRoute.TrustTier)
			s.writeStreamingError(w, http.StatusBadGateway, "upstream_error", err.Error())
			return
		}

		if routing.RetryableHTTPStatus(resp.StatusCode) {
			failoverState.MarkAttempted(currentRoute.Provider.ID)
			nextRoute, nextErr := s.router.NextProvider(ctx, criteria, failoverState)
			if nextErr == nil && s.authorizer.CheckProviderAllowed(apiKey, nextRoute.Provider.ID) {
				resp.Body.Close()
				currentRoute = nextRoute
				continue
			}
		}

		defer resp.Body.Close()

		// Set headers for SSE only after failover decisions are complete.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		// Stream response
		if resp.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(resp.Body)
			if err != nil {
				s.writeStreamingError(w, http.StatusBadGateway, "upstream_error", "Failed to read gzip response")
				return
			}
			defer reader.Close()
			s.streamResponse(w, flusher, reader, currentRoute, requestID, keyPrefix, req.Model, startTime)
			return
		}

		s.streamResponse(w, flusher, resp.Body, currentRoute, requestID, keyPrefix, req.Model, startTime)
		return
	}
}

// streamResponse streams the response body.
func (s *Server) streamResponse(w http.ResponseWriter, flusher http.Flusher, reader io.Reader,
	route *routing.Route, requestID, keyPrefix, model string, startTime time.Time) {

	buf := make([]byte, 4096)
	var totalTokens int64

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			// Just forward the SSE data
			w.Write(buf[:n])
			flusher.Flush()

			// Count chunks for basic usage estimation
			totalTokens++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	// Record usage (approximate for streaming)
	s.recordUsage(context.Background(), requestID, keyPrefix, route.Provider.ID, model, models.ModeChat,
		"success", time.Since(startTime).Milliseconds(), 0, totalTokens, 0, "", "")
}

// handleListModels handles model listing.
func (s *Server) handleListModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is supported")
		return
	}

	ctx := r.Context()

	// Get all providers
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to list providers")
		return
	}

	// Build model list using normalized names for deduplication
	var modelList []map[string]interface{}
	seen := make(map[string]bool)

	for _, p := range providers {
		if !modelpolicy.IsConfidentialTier(p.TrustTier) {
			continue
		}

		pModels, err := s.db.GetProviderModels(ctx, p.ID)
		if err != nil {
			continue
		}

		for _, pm := range pModels {
			if !pm.Enabled {
				continue
			}
			if !modelpolicy.SupportsChatCompletions(pm.Model) || !modelpolicy.IsProviderModelTEEEligible(p.ID, pm.Model) {
				continue
			}

			// Use normalized model name for deduplication (enables failover routing)
			normalizedModel := models.CanonicalModelName(pm.Model)
			if seen[normalizedModel] {
				continue
			}

			// Check if model has valid attestation (using normalized name)
			verifiedModels, err := s.db.GetProviderModelsWithVerification(ctx, normalizedModel, pm.Mode)
			if err != nil || len(verifiedModels) == 0 {
				continue
			}

			// Build provider list for failover info using only confidential-capable providers.
			providerNames := make([]string, 0, len(verifiedModels))
			confidentialCount := 0
			for _, vm := range verifiedModels {
				prov, _ := s.db.GetProvider(ctx, vm.ProviderID)
				if prov == nil {
					continue
				}
				if modelpolicy.IsServableConfidentialChatModel(prov, vm.Model) {
					providerNames = append(providerNames, prov.Name)
					confidentialCount++
				}
			}

			// Skip this model if no confidential providers available (in confidential-only mode)
			if confidentialCount == 0 {
				continue
			}

			model := map[string]interface{}{
				"id":        normalizedModel,
				"object":    "model",
				"created":   time.Now().Unix(),
				"owned_by":  strings.Join(providerNames, ", "),
				"providers": confidentialCount, // Number of providers available for failover
			}
			modelList = append(modelList, model)
			seen[normalizedModel] = true
		}
	}

	response := map[string]interface{}{
		"object": "list",
		"data":   modelList,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleConfidentialityStatus returns the current confidentiality status.
func (s *Server) handleConfidentialityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only GET is supported")
		return
	}

	ctx := r.Context()
	status, err := s.attestation.GetConfidentialityStatus(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "Failed to get status")
		return
	}

	// Add server configuration info
	status["confidential_only"] = s.confidentialOnly
	status["required_tier"] = "confidential_or_encrypted"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
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

func (s *Server) writeStreamingError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(status)

	payload, _ := json.Marshal(map[string]interface{}{
		"error": map[string]string{
			"type":    code,
			"message": message,
		},
	})
	w.Write([]byte("event: error\ndata: "))
	w.Write(payload)
	w.Write([]byte("\n\n"))
}

func buildUpstreamRequestBody(originalBody []byte, providerID, providerModel string, includeStreamUsage bool) ([]byte, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(originalBody, &payload); err != nil {
		return nil, err
	}

	payload["model"] = providerRequestModel(providerID, providerModel)
	adaptProviderParameters(payload, providerID, providerModel)
	if includeStreamUsage {
		streamOptions, ok := payload["stream_options"].(map[string]interface{})
		if !ok {
			streamOptions = map[string]interface{}{}
		}
		streamOptions["include_usage"] = true
		payload["stream_options"] = streamOptions
	}

	return json.Marshal(payload)
}

func providerRequestModel(providerID, providerModel string) string {
	if providerID == "ppq" {
		return strings.TrimPrefix(providerModel, "private/")
	}
	return providerModel
}

func adaptProviderParameters(payload map[string]interface{}, providerID, providerModel string) {
	if !requiresMaxCompletionTokens(providerID, providerModel) {
		return
	}
	if _, ok := payload["max_completion_tokens"]; ok {
		return
	}
	maxTokens, ok := payload["max_tokens"]
	if !ok {
		return
	}

	payload["max_completion_tokens"] = maxTokens
	delete(payload, "max_tokens")
}

func requiresMaxCompletionTokens(providerID, providerModel string) bool {
	if providerID != "redpill" {
		return false
	}

	model := strings.ToLower(providerModel)
	return strings.HasPrefix(model, "openai/gpt-5") ||
		strings.HasPrefix(model, "openai/o1") ||
		strings.HasPrefix(model, "openai/o3") ||
		strings.HasPrefix(model, "openai/o4")
}

// recordUsage records a usage event.
func (s *Server) recordUsage(ctx context.Context, requestID, keyPrefix, providerID, model string,
	mode models.Mode, status string, latencyMs, promptTokens, completionTokens, cost int64,
	errorCode, errorMessage string) {

	event := &models.UsageEvent{
		RequestID:        requestID,
		Timestamp:        time.Now().UTC(),
		APIKeyHashPrefix: keyPrefix,
		ProviderID:       providerID,
		Model:            model,
		Mode:             mode,
		Status:           status,
		LatencyMs:        latencyMs,
		CostEstimateUSD:  cost,
	}

	if promptTokens > 0 {
		event.PromptTokens = &promptTokens
	}
	if completionTokens > 0 {
		event.CompletionTokens = &completionTokens
	}
	if errorCode != "" {
		event.ErrorCode = &errorCode
	}
	if errorMessage != "" {
		event.ErrorMessage = &errorMessage
	}

	if err := s.usage.RecordEvent(ctx, event); err != nil {
		log.Printf("Failed to record usage: %v", err)
	}
}

// buildEHBPKeyConfig builds an EHBP key configuration from a public key.
func buildEHBPKeyConfig(publicKey []byte) []byte {
	// Format: key_id(1) || kem_id(2) || public_key(32) || cipher_suites_len(2) || cipher_suites(4)
	config := make([]byte, 0, 1+2+32+2+4)

	// Key ID: 0
	config = append(config, 0)

	// KEM ID: X25519 (big-endian)
	config = append(config, 0x00, 0x20)

	// Public key (32 bytes)
	config = append(config, publicKey...)

	// Cipher suites length: 4 (1 suite)
	config = append(config, 0x00, 0x04)

	// Cipher suite: HKDF-SHA256 || AES-256-GCM
	config = append(config, 0x00, 0x01) // KDF
	config = append(config, 0x00, 0x02) // AEAD

	return config
}

// extractResponseNonce extracts the response nonce from headers.
func extractResponseNonce(headers http.Header) []byte {
	nonceHex := headers.Get("Ehbp-Response-Nonce")
	if nonceHex == "" {
		nonceHex = headers.Get("X-EHBP-Response-Nonce")
	}
	if nonceHex == "" {
		return nil
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil
	}
	return nonce
}

func providerEndpoint(baseURL, path string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	basePath := strings.TrimRight(u.Path, "/")
	u.Path = basePath + "/" + strings.TrimLeft(path, "/")
	return u, nil
}

// CreateReverseProxy creates a reverse proxy for a provider.
func CreateReverseProxy(target *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if transport != nil {
		proxy.Transport = transport
	}
	return proxy
}
