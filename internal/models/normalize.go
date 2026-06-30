package models

import (
	"regexp"
	"strings"
)

// NormalizeModelName converts a provider-specific model ID to a canonical form.
// This enables failover routing between providers offering the same model.
//
// Examples:
//   - "tinfoil/gpt-oss-120b" -> "gpt-oss-120b"
//   - "near/openai/gpt-oss-120b" -> "gpt-oss-120b"
//   - "nanogpt/openai/gpt-oss-120b" -> "gpt-oss-120b"
//   - "meta-llama/Meta-Llama-3.1-8B-Instruct" -> "meta-llama-3.1-8b-instruct"
//   - "openai/gpt-4" -> "gpt-4"
//   - "anthropic/claude-3-opus" -> "claude-3-opus"
func NormalizeModelName(model string) string {
	// First, strip common provider prefixes
	normalized := stripProviderPrefix(model)

	// Normalize case (lowercase)
	normalized = strings.ToLower(normalized)

	// Normalize separators (hyphens and underscores)
	normalized = normalizeSeparators(normalized)

	// Remove common suffixes that don't affect model identity
	normalized = stripModelSuffixes(normalized)

	return normalized
}

// stripProviderPrefix removes provider-specific prefixes from model names.
func stripProviderPrefix(model string) string {
	// Common provider prefixes to strip
	prefixes := []string{
		"tinfoil/",
		"near/",
		"nanogpt/",
		"redpill/",
		"chutes/",
		"ppq/",
		"ppq-private/",
		"private/",
		"openrouter/",
		"openai/",
		"anthropic/",
		"google/",
		"meta-llama/",
		"meta/",
		"mistralai/",
		"qwen/",
		"deepseek-ai/",
		"TEE/",
		"nvidia/",
		"moonshotai/",
		"z-ai/",
		"zai-org/",
		"black-forest-labs/",
		"stepfun/",
		"perceptron/",
		"soob3123/",
		"liquid/",
		"exa/",
		"linkup/",
	}

	result := model
	for _, prefix := range prefixes {
		if strings.HasPrefix(strings.ToLower(model), strings.ToLower(prefix)) {
			result = model[len(prefix):]
			// Some providers have nested prefixes (e.g., near/openai/gpt-4)
			// Strip recursively
			return stripProviderPrefix(result)
		}
	}

	return result
}

// normalizeSeparators normalizes hyphens, underscores, dots, and colons in model names.
func normalizeSeparators(model string) string {
	// Replace underscores, dots, and colons with hyphens for consistency
	result := strings.ReplaceAll(model, "_", "-")
	result = strings.ReplaceAll(result, ".", "-")
	result = strings.ReplaceAll(result, ":", "-")

	// Remove duplicate hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}

	// Trim leading/trailing hyphens
	result = strings.Trim(result, "-")

	return result
}

// stripModelSuffixes removes version/date suffixes that don't affect model identity.
func stripModelSuffixes(model string) string {
	// Date suffixes like -20250929, -20241022, etc. - can be at end OR followed by more text
	// e.g., "claude-sonnet-4-5-20250929" or "claude-sonnet-4-5-20250929-thinking"
	dateSuffix := regexp.MustCompile(`-\d{8}(-|$)`)
	model = dateSuffix.ReplaceAllString(model, "${1}") // Keep the ending if present

	// Version suffixes that are redundant (keep main version numbers)
	// e.g., "v2", "v3" at the end
	versionSuffix := regexp.MustCompile(`-v\d+$`)
	model = versionSuffix.ReplaceAllString(model, "")

	return model
}

// ModelAlias represents known aliases for the same model.
type ModelAlias struct {
	Canonical string
	Aliases   []string
}

// KnownModelAliases maps common model name variations to canonical forms.
var KnownModelAliases = []ModelAlias{
	{
		Canonical: "gpt-4",
		Aliases:   []string{"gpt4", "gpt-4-turbo", "gpt-4-turbo-preview"},
	},
	{
		Canonical: "gpt-4o",
		Aliases:   []string{"gpt4o", "gpt-4o-latest"},
	},
	{
		Canonical: "gpt-4o-mini",
		Aliases:   []string{"gpt4o-mini", "gpt-4o-mini-latest"},
	},
	{
		Canonical: "claude-3-opus",
		Aliases:   []string{"claude-opus", "claude-3-opus-latest"},
	},
	{
		Canonical: "claude-3-sonnet",
		Aliases:   []string{"claude-sonnet", "claude-3-sonnet-latest"},
	},
	{
		Canonical: "claude-3-haiku",
		Aliases:   []string{"claude-haiku", "claude-3-haiku-latest"},
	},
	{
		Canonical: "llama-3-1-8b",
		Aliases:   []string{"llama-3.1-8b", "llama3-1-8b", "meta-llama-3-1-8b"},
	},
	{
		Canonical: "llama-3-1-70b",
		Aliases:   []string{"llama-3.1-70b", "llama3-1-70b", "meta-llama-3-1-70b"},
	},
	{
		Canonical: "llama-3-3-70b",
		Aliases:   []string{"llama-3.3-70b", "llama3-3-70b"},
	},
}

// CanonicalModelName returns the canonical name for a model, checking known aliases.
func CanonicalModelName(model string) string {
	normalized := NormalizeModelName(model)

	for _, alias := range KnownModelAliases {
		if normalized == alias.Canonical {
			return alias.Canonical
		}
		for _, a := range alias.Aliases {
			if normalized == a {
				return alias.Canonical
			}
		}
	}

	return normalized
}

// ModelsMatch checks if two model names refer to the same model.
func ModelsMatch(model1, model2 string) bool {
	return CanonicalModelName(model1) == CanonicalModelName(model2)
}
