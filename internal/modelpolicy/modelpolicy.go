package modelpolicy

import (
	"strings"

	"github.com/enclava/encproxy/internal/models"
)

// IsConfidentialTier returns whether a provider tier is acceptable for
// confidentiality-preserving routing.
func IsConfidentialTier(tier models.TrustTier) bool {
	return tier == models.TrustTierConfidential || tier == models.TrustTierEncrypted
}

// SupportsChatCompletions returns whether a provider model ID should be exposed
// through the chat completions endpoint.
func SupportsChatCompletions(modelID string) bool {
	model := strings.ToLower(modelID)
	nonChatMarkers := []string{
		"doc-upload",
		"embedding",
		"embed-",
		"reranker",
		"whisper",
		"tts",
		"websearch",
		"realtime",
		"privacy-filter",
		"flux",
	}
	for _, marker := range nonChatMarkers {
		if strings.Contains(model, marker) {
			return false
		}
	}
	return strings.TrimSpace(modelID) != ""
}

// IsProviderModelTEEEligible returns whether a provider/model pair can be
// treated as a TEE-backed model. This is an explicit allow policy because some
// providers return attestations for proxy infrastructure while still serving
// non-confidential upstream models.
func IsProviderModelTEEEligible(providerID, modelID string) bool {
	provider := strings.ToLower(strings.TrimSpace(providerID))
	model := strings.ToLower(strings.TrimSpace(modelID))
	if model == "" {
		return false
	}

	switch provider {
	case "nanogpt":
		return IsNanoGPTTEEModel(modelID)
	case "ppq", "ppq-private":
		return strings.HasPrefix(model, "private/")
	case "chutes":
		return hasTEEMarker(model)
	case "tinfoil", "near", "privatemode":
		return !IsKnownRemoteHostedModel(modelID)
	case "redpill":
		return strings.HasPrefix(model, "phala/") && !IsKnownRemoteHostedModel(modelID)
	}

	return false
}

// IsServableConfidentialChatModel applies the full policy used by /v1/models
// and confidential chat routing.
func IsServableConfidentialChatModel(provider *models.Provider, modelID string) bool {
	if provider == nil || !IsConfidentialTier(provider.TrustTier) {
		return false
	}
	return SupportsChatCompletions(modelID) && IsProviderModelTEEEligible(provider.ID, modelID)
}

// IsNanoGPTTEEModel returns true only for NanoGPT's explicit TEE namespace.
func IsNanoGPTTEEModel(model string) bool {
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "tee/") || strings.Contains(model, "/tee/")
}

// IsKnownRemoteHostedModel identifies proprietary model families that are
// normally served by a non-TEE upstream, not by local confidential inference.
func IsKnownRemoteHostedModel(modelID string) bool {
	original := strings.ToLower(strings.TrimSpace(modelID))
	canonical := models.CanonicalModelName(modelID)

	if strings.HasPrefix(original, "anthropic/") || hasFamily(canonical, "claude") {
		return true
	}
	if strings.HasPrefix(original, "google/gemini") || hasFamily(canonical, "gemini") {
		return true
	}
	if strings.HasPrefix(original, "xai/grok") || strings.HasPrefix(original, "x-ai/grok") || strings.HasPrefix(original, "x-ai/") || hasFamily(canonical, "grok") {
		return true
	}
	if strings.HasPrefix(original, "cohere/command") || hasFamily(canonical, "command") {
		return true
	}

	return isOpenAIHostedModel(original, canonical)
}

func isOpenAIHostedModel(original, canonical string) bool {
	if strings.HasPrefix(original, "openai/gpt-oss") || strings.HasPrefix(canonical, "gpt-oss") {
		return false
	}
	if hasFamily(canonical, "gpt-3") || canonical == "gpt-3-5-turbo" {
		return true
	}
	if canonical == "gpt-4" || strings.HasPrefix(canonical, "gpt-4-") || canonical == "gpt-4o" || strings.HasPrefix(canonical, "gpt-4o-") {
		return true
	}
	if canonical == "gpt-5" || strings.HasPrefix(canonical, "gpt-5-") {
		return true
	}
	if hasFamily(canonical, "chatgpt") {
		return true
	}
	return hasFamily(canonical, "o1") || hasFamily(canonical, "o3") || hasFamily(canonical, "o4")
}

func hasFamily(model, family string) bool {
	return model == family || strings.HasPrefix(model, family+"-")
}

func hasTEEMarker(model string) bool {
	return strings.Contains(model, "/tee/") ||
		strings.HasPrefix(model, "tee/") ||
		strings.HasSuffix(model, "-tee") ||
		strings.Contains(model, "-tee-")
}
