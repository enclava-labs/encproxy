package models

import (
	"time"
)

// TrustTier represents the confidentiality level of a provider.
type TrustTier string

const (
	TrustTierConfidential TrustTier = "confidential"
	TrustTierEncrypted    TrustTier = "encrypted"
	TrustTierPlaintext    TrustTier = "plaintext"
)

// Mode represents the API endpoint mode.
type Mode string

const (
	ModeChat       Mode = "chat"
	ModeCompletion Mode = "completion"
	ModeEmbedding  Mode = "embedding"
)

// APIKey represents a customer API key.
type APIKey struct {
	ID           string    `json:"id" db:"id"`
	KeyHash      string    `json:"-" db:"key_hash"`
	KeyPrefix    string    `json:"key_prefix" db:"key_prefix"`
	Name         string    `json:"name" db:"name"`
	AllowedProviders []string `json:"allowed_providers,omitempty" db:"allowed_providers"`
	AllowedModels    []string `json:"allowed_models,omitempty" db:"allowed_models"`
	AllowedRegions   []string `json:"allowed_regions,omitempty" db:"allowed_regions"`
	PreferredRegions []string `json:"preferred_regions,omitempty" db:"preferred_regions"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Provider represents an upstream LLM provider.
type Provider struct {
	ID                string    `json:"id" db:"id"`
	Name              string    `json:"name" db:"name"`
	BaseURL           string    `json:"base_url" db:"base_url"`
	TrustTier         TrustTier `json:"trust_tier" db:"trust_tier"`
	AttestationConfig string    `json:"attestation_config,omitempty" db:"attestation_config"`
	Pricing           string    `json:"pricing,omitempty" db:"pricing"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}

// ProviderModel represents a model available on a provider.
type ProviderModel struct {
	ProviderID      string `json:"provider_id" db:"provider_id"`
	Model           string `json:"model" db:"model"`
	NormalizedModel string `json:"normalized_model" db:"normalized_model"`
	Mode            Mode   `json:"mode" db:"mode"`
	Enabled         bool   `json:"enabled" db:"enabled"`
}

// ProviderAttestation represents a cached attestation verdict.
type ProviderAttestation struct {
	ProviderID      string    `json:"provider_id" db:"provider_id"`
	Model           string    `json:"model" db:"model"`
	Mode            Mode      `json:"mode" db:"mode"`
	Verified        bool      `json:"verified" db:"verified"`
	EvidenceDigest  string    `json:"evidence_digest" db:"evidence_digest"`
	PolicyDigest    string    `json:"policy_digest" db:"policy_digest"`
	VerifiedClaims  string    `json:"verified_claims,omitempty" db:"verified_claims"`
	ExpiresAt       time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time `json:"updated_at" db:"updated_at"`
}

// UsageEvent represents a privacy-safe usage tap record.
type UsageEvent struct {
	RequestID        string    `json:"request_id" db:"request_id"`
	Timestamp        time.Time `json:"timestamp" db:"timestamp"`
	APIKeyHashPrefix string    `json:"api_key_hash_prefix" db:"api_key_hash_prefix"`
	ProviderID       string    `json:"provider_id" db:"provider_id"`
	Model            string    `json:"model" db:"model"`
	Mode             Mode      `json:"mode" db:"mode"`
	Status           string    `json:"status" db:"status"`
	LatencyMs        int64     `json:"latency_ms" db:"latency_ms"`
	PromptTokens     *int64    `json:"prompt_tokens,omitempty" db:"prompt_tokens"`
	CompletionTokens *int64    `json:"completion_tokens,omitempty" db:"completion_tokens"`
	CostEstimateUSD  int64     `json:"cost_estimate_usd" db:"cost_estimate_usd"`
	ErrorCode        *string   `json:"error_code,omitempty" db:"error_code"`
	ErrorMessage     *string   `json:"error_message,omitempty" db:"error_message"`
}

// PricingHistory represents historical pricing data.
type PricingHistory struct {
	ProviderID         string    `json:"provider_id" db:"provider_id"`
	Model              string    `json:"model" db:"model"`
	PricePer1MTokensUSD int64    `json:"price_per_1m_tokens_usd" db:"price_per_1m_tokens_usd"`
	EffectiveFrom      time.Time `json:"effective_from" db:"effective_from"`
}

// ChatCompletionRequest represents an OpenAI-compatible chat completion request.
type ChatCompletionRequest struct {
	Model          string         `json:"model"`
	Messages       []Message      `json:"messages"`
	Stream         bool           `json:"stream,omitempty"`
	StreamOptions  *StreamOptions `json:"stream_options,omitempty"`
	Temperature    *float64       `json:"temperature,omitempty"`
	MaxTokens      *int64         `json:"max_tokens,omitempty"`
	TopP           *float64       `json:"top_p,omitempty"`
	PresencePenalty  *float64     `json:"presence_penalty,omitempty"`
	FrequencyPenalty *float64     `json:"frequency_penalty,omitempty"`
}

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// StreamOptions represents stream-specific options.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// ChatCompletionResponse represents an OpenAI-compatible chat completion response.
type ChatCompletionResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}

// Choice represents a completion choice.
type Choice struct {
	Index        int      `json:"index"`
	Message      *Message `json:"message,omitempty"`
	Delta        *Message `json:"delta,omitempty"`
	FinishReason *string  `json:"finish_reason,omitempty"`
}

// Usage represents token usage.
type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// StreamChunk represents a server-sent event chunk.
type StreamChunk struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   *Usage   `json:"usage,omitempty"`
}
