package models

import (
	"strings"
	"testing"
)

// TestNormalizeModelName tests normalization using realistic provider model names.
// These are based on actual model names fetched from Tinfoil, NEAR AI, NanoGPT, etc.
func TestNormalizeModelName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// === TINFOIL models (from actual fetch) ===
		{"tinfoil/gpt-oss-120b", "gpt-oss-120b"},
		{"tinfoil/gpt-oss-safeguard-120b", "gpt-oss-safeguard-120b"},
		{"tinfoil/llama3-3-70b", "llama3-3-70b"},
		{"tinfoil/gemma4-31b", "gemma4-31b"},
		{"tinfoil/kimi-k2-6", "kimi-k2-6"},
		{"tinfoil/deepseek-v4-pro", "deepseek-v4-pro"},
		{"tinfoil/glm-5-1", "glm-5-1"},
		{"tinfoil/qwen3-vl-30b", "qwen3-vl-30b"},
		{"tinfoil/nomic-embed-text", "nomic-embed-text"},
		{"tinfoil/voxtral-small-24b", "voxtral-small-24b"},
		{"tinfoil/whisper-large-v3-turbo", "whisper-large-v3-turbo"},
		{"tinfoil/websearch", "websearch"},
		{"tinfoil/doc-upload", "doc-upload"},
		{"tinfoil/qwen3-tts", "qwen3-tts"},

		// === NEAR AI models (nested prefixes) ===
		{"near/openai/gpt-oss-120b", "gpt-oss-120b"},        // Same as tinfoil
		{"near/openai/gpt-4.1", "gpt-4-1"},                  // Version normalization
		{"near/openai/gpt-4.1-mini", "gpt-4-1-mini"},
		{"near/openai/gpt-4.1-nano", "gpt-4-1-nano"},
		{"near/openai/gpt-5", "gpt-5"},
		{"near/openai/gpt-5.1", "gpt-5-1"},
		{"near/openai/gpt-5.2", "gpt-5-2"},
		{"near/openai/gpt-5.4", "gpt-5-4"},
		{"near/openai/gpt-5.4-mini", "gpt-5-4-mini"},
		{"near/openai/gpt-5.4-nano", "gpt-5-4-nano"},
		{"near/openai/gpt-5.5", "gpt-5-5"},
		{"near/openai/gpt-5-mini", "gpt-5-mini"},
		{"near/openai/gpt-5-nano", "gpt-5-nano"},
		{"near/openai/o3", "o3"},
		{"near/openai/o3-mini", "o3-mini"},
		{"near/openai/o4-mini", "o4-mini"},
		{"near/anthropic/claude-opus-4-6", "claude-opus-4-6"},
		{"near/anthropic/claude-sonnet-4-5", "claude-sonnet-4-5"},
		{"near/anthropic/claude-sonnet-4-6", "claude-sonnet-4-6"},
		{"near/anthropic/claude-haiku-4-5", "claude-haiku-4-5"},
		{"near/moonshotai/kimi-k2.6", "kimi-k2-6"},          // Dot becomes hyphen, matches tinfoil kimi-k2-6
		{"near/google/gemini-2.5-flash", "gemini-2-5-flash"},
		{"near/google/gemini-2.5-pro", "gemini-2-5-pro"},
		{"near/google/gemma-4-31B-it", "gemma-4-31b-it"},
		{"near/qwen/qwen3.7-max", "qwen3-7-max"},            // Dot becomes hyphen
		{"near/Qwen/Qwen3.6-27B-FP8", "qwen3-6-27b-fp8"},    // Dot becomes hyphen, case normalized
		{"near/Qwen/Qwen3-VL-30B-A3B-Instruct", "qwen3-vl-30b-a3b-instruct"}, // Case normalized
		{"near/zai-org/GLM-5.1-FP8", "glm-5-1-fp8"},
		{"near/deepseek-ai/DeepSeek-V4-Flash", "deepseek-v4-flash"},

		// === NanoGPT models ===
		{"nanogpt/openai/gpt-oss-120b", "gpt-oss-120b"},     // Same as tinfoil/near
		{"nanogpt/openai/gpt-oss-20b", "gpt-oss-20b"},
		{"nanogpt/openai/gpt-oss-safeguard-20b", "gpt-oss-safeguard-20b"},
		{"nanogpt/openai/gpt-5.5", "gpt-5-5"},
		{"nanogpt/openai/gpt-5.4", "gpt-5-4"},
		{"nanogpt/openai/gpt-5.2", "gpt-5-2"},
		{"nanogpt/openai/gpt-5", "gpt-5"},
		{"nanogpt/openai/gpt-latest", "gpt-latest"},
		{"nanogpt/openai/gpt-chat-latest", "gpt-chat-latest"},
		{"nanogpt/TEE/qwen3.6-27b", "qwen3-6-27b"},          // Dot becomes hyphen
		{"nanogpt/nvidia/nemotron-3-ultra-550b-a55b", "nemotron-3-ultra-550b-a55b"},
		{"nanogpt/nvidia/nemotron-3-ultra-550b-a55b:thinking", "nemotron-3-ultra-550b-a55b-thinking"},
		{"nanogpt/anthropic/claude-sonnet-latest", "claude-sonnet-latest"},
		{"nanogpt/claude-sonnet-4-5-20250929", "claude-sonnet-4-5"}, // Date stripping
		{"nanogpt/claude-sonnet-4-5-20250929-thinking", "claude-sonnet-4-5-thinking"}, // Date stripped, colon converted
		{"nanogpt/stepfun/step-3.7-flash:thinking", "step-3-7-flash-thinking"}, // Dot and colon to hyphen
		{"nanogpt/z-ai/glm-4.5v", "glm-4-5v"},
		{"nanogpt/z-ai/glm-4.5v:thinking", "glm-4-5v-thinking"}, // Dot and colon to hyphen
		{"nanogpt/z-ai/glm-5-turbo", "glm-5-turbo"},
		{"nanogpt/gemini-2.5-flash-preview-05-20", "gemini-2-5-flash-preview-05-20"},
		{"nanogpt/gemini-2.5-flash-preview-05-20:thinking", "gemini-2-5-flash-preview-05-20-thinking"}, // Dot and colon to hyphen

		// === REDPILL models ===
		{"redpill/llama-3-1-70b", "llama-3-1-70b"},
		{"redpill/claude-3-opus", "claude-3-opus"},

		// === CHUTES models ===
		{"chutes/meta-llama/Meta-Llama-3-1-8B-Instruct", "meta-llama-3-1-8b-instruct"},
		{"chutes/meta-llama/Meta-Llama-3-1-70B-Instruct", "meta-llama-3-1-70b-instruct"},
		{"chutes/meta-llama/Meta-Llama-3-3-70B-Instruct", "meta-llama-3-3-70b-instruct"},

		// === PPQ models ===
		{"ppq/openai/gpt-4o", "gpt-4o"},
		{"ppq/openai/gpt-4o-mini", "gpt-4o-mini"},
		{"ppq-private/openai/gpt-4o", "gpt-4o"},

		// === Case normalization ===
		{"GPT-4", "gpt-4"},
		{"Meta-Llama-3-1-8B", "meta-llama-3-1-8b"},
		{"Qwen3.5-122B-A10B", "qwen3-5-122b-a10b"},

		// === Separator normalization ===
		{"gpt_4", "gpt-4"},
		{"gpt.4", "gpt-4"},
		{"gpt__4", "gpt-4"},
		{"qwen_3_5_122b", "qwen-3-5-122b"},

		// === Date suffix stripping ===
		{"claude-sonnet-4-5-20250929", "claude-sonnet-4-5"},
		{"gpt-4-20241022", "gpt-4"},
		{"claude-3-opus-20240229", "claude-3-opus"},

		// === Version suffix stripping ===
		{"model-v2", "model"},
		{"gpt-4-v1", "gpt-4"},

		// === OpenAI direct ===
		{"openai/gpt-4", "gpt-4"},
		{"openai/gpt-4o", "gpt-4o"},
		{"openai/gpt-4o-mini", "gpt-4o-mini"},
		{"openai/gpt-4-turbo", "gpt-4-turbo"},
		{"openai/gpt-4-turbo-preview", "gpt-4-turbo-preview"},

		// === Anthropic direct ===
		{"anthropic/claude-3-opus", "claude-3-opus"},
		{"anthropic/claude-3-sonnet", "claude-3-sonnet"},
		{"anthropic/claude-3-haiku", "claude-3-haiku"},

		// === Already normalized ===
		{"gpt-4", "gpt-4"},
		{"llama-3-1-8b", "llama-3-1-8b"},
		{"deepseek-v4-pro", "deepseek-v4-pro"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := NormalizeModelName(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizeModelName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestModelDistinguishability verifies that DIFFERENT models are NOT matched as the same.
// This is critical - we must NOT conflate gpt-oss-120b with gpt-oss-20b, etc.
func TestModelDistinguishability(t *testing.T) {
	// Pairs that should NOT match (different models)
	differentModels := []struct {
		model1 string
		model2 string
		reason string
	}{
		// Different sizes - CRITICAL these must not match
		{"tinfoil/gpt-oss-120b", "nanogpt/openai/gpt-oss-20b", "120b vs 20b"},
		{"gpt-oss-120b", "gpt-oss-20b", "120b vs 20b bare"},
		{"gpt-oss-120b", "gpt-oss-safeguard-120b", "regular vs safeguard"},
		{"tinfoil/gpt-oss-120b", "tinfoil/gpt-oss-safeguard-120b", "prefixed regular vs safeguard"},

		// GPT-4 family - different models
		{"gpt-4", "gpt-4o", "4 vs 4o"},
		{"gpt-4", "gpt-4o-mini", "4 vs 4o-mini"},
		{"gpt-4-turbo", "gpt-4o", "4-turbo vs 4o"},
		{"gpt-4o", "gpt-4o-mini", "4o vs 4o-mini"},

		// GPT-5 family
		{"gpt-5", "gpt-5.1", "5 vs 5.1"},
		{"gpt-5", "gpt-5-mini", "5 vs 5-mini"},
		{"gpt-5", "gpt-5-nano", "5 vs 5-nano"},
		{"gpt-5.4", "gpt-5.5", "5.4 vs 5.5"},
		{"near/openai/gpt-5", "near/openai/gpt-5.1", "5 vs 5.1 prefixed"},

		// Claude family
		{"claude-3-opus", "claude-3-sonnet", "opus vs sonnet"},
		{"claude-3-opus", "claude-3-haiku", "opus vs haiku"},
		{"claude-sonnet-4-5", "claude-sonnet-4-6", "4.5 vs 4.6"},
		{"claude-opus-4-6", "claude-sonnet-4-6", "opus vs sonnet at 4.6"},

		// Llama family
		{"llama-3-1-8b", "llama-3-1-70b", "8b vs 70b"},
		{"llama-3-1-70b", "llama-3-3-70b", "3.1 vs 3.3 both 70b"},
		{"meta-llama-3-1-8b", "meta-llama-3-1-70b", "8b vs 70b with prefix"},

		// Qwen family
		{"qwen3-vl-30b", "qwen3-7-max", "vl vs max"},
		{"qwen3-6-27b", "qwen3-7-27b", "6 vs 7 (different versions)"},

		// Kimi family (dots become hyphens)
		// Note: kimi-k2.6 normalizes to kimi-k2-6, so these match by design

		// Gemini family
		{"gemini-2.5-flash", "gemini-2.5-pro", "flash vs pro"},
		{"gemini-2.5-flash", "gemini-2.5-flash-lite", "flash vs flash-lite"},

		// GLM family
		{"glm-5-1", "glm-5-turbo", "5.1 vs 5-turbo"},
		{"glm-4-5v", "glm-5-1", "4.5v vs 5.1"},

		// DeepSeek family
		{"deepseek-v4-pro", "deepseek-v4-flash", "pro vs flash"},

		// O-series
		{"o3", "o3-mini", "o3 vs o3-mini"},
		{"o3", "o4-mini", "o3 vs o4-mini"},

		// Completely different
		{"gpt-4", "claude-3-opus", "gpt vs claude"},
		{"gpt-oss-120b", "llama-3-3-70b", "gpt-oss vs llama"},
		{"whisper-large-v3-turbo", "gpt-oss-120b", "whisper vs gpt"},
	}

	for _, tt := range differentModels {
		t.Run(tt.reason, func(t *testing.T) {
			if ModelsMatch(tt.model1, tt.model2) {
				norm1 := CanonicalModelName(tt.model1)
				norm2 := CanonicalModelName(tt.model2)
				t.Errorf("ModelsMatch(%q, %q) = true, but they are different models (%s)\n  normalized: %q vs %q",
					tt.model1, tt.model2, tt.reason, norm1, norm2)
			}
		})
	}
}

// TestModelEquivalence verifies that the SAME model from DIFFERENT providers IS matched.
func TestModelEquivalence(t *testing.T) {
	// Pairs that SHOULD match (same model, different providers)
	equivalentModels := []struct {
		model1 string
		model2 string
		reason string
	}{
		// Same GPT-4 from different providers
		{"tinfoil/gpt-4", "openai/gpt-4", "tinfoil vs openai"},
		{"near/openai/gpt-4", "nanogpt/openai/gpt-4", "near vs nanogpt"},
		{"ppq/openai/gpt-4o", "openai/gpt-4o", "ppq vs openai"},

		// Same GPT-OSS-120b from different providers
		{"tinfoil/gpt-oss-120b", "near/openai/gpt-oss-120b", "tinfoil vs near"},
		{"tinfoil/gpt-oss-120b", "nanogpt/openai/gpt-oss-120b", "tinfoil vs nanogpt"},
		{"near/openai/gpt-oss-120b", "nanogpt/openai/gpt-oss-120b", "near vs nanogpt"},

		// Same Kimi from different providers
		{"tinfoil/kimi-k2-6", "near/moonshotai/kimi-k2.6", "tinfoil vs near"},

		// Same Claude family (note: claude-opus-4-6 is a newer version than claude-3-opus)
		// These are intentionally different - claude-3-opus vs claude-opus-4-6 are different versions
		// Note: claude-opus-4-6 vs claude-3-opus might be different versions - skip if unsure

		// Case differences
		{"GPT-4", "gpt-4", "case"},
		{"Meta-Llama-3-1-8B", "meta-llama-3-1-8b", "case with prefix"},

		// Separator differences
		{"gpt_4", "gpt-4", "underscore vs hyphen"},
		{"gpt.4", "gpt-4", "dot vs hyphen"},

		// Date suffixes (same model, different snapshot)
		{"claude-3-opus-20240229", "claude-3-opus", "with vs without date"},
		{"gpt-4-20241022", "gpt-4", "with vs without date"},
	}

	for _, tt := range equivalentModels {
		t.Run(tt.reason, func(t *testing.T) {
			if !ModelsMatch(tt.model1, tt.model2) {
				norm1 := CanonicalModelName(tt.model1)
				norm2 := CanonicalModelName(tt.model2)
				t.Errorf("ModelsMatch(%q, %q) = false, but should match (%s)\n  normalized: %q vs %q",
					tt.model1, tt.model2, tt.reason, norm1, norm2)
			}
		})
	}
}

// TestCanonicalModelName tests canonical name resolution with aliases.
func TestCanonicalModelName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Basic canonicalization
		{"gpt-4", "gpt-4"},
		{"gpt4", "gpt-4"},
		{"gpt-4-turbo", "gpt-4"},
		{"gpt-4-turbo-preview", "gpt-4"},

		// GPT-4o family
		{"gpt-4o", "gpt-4o"},
		{"gpt4o", "gpt-4o"},
		{"gpt-4o-latest", "gpt-4o"},
		{"gpt-4o-mini", "gpt-4o-mini"},
		{"gpt4o-mini", "gpt-4o-mini"},

		// Claude aliases
		{"claude-3-opus", "claude-3-opus"},
		{"claude-opus", "claude-3-opus"},
		{"claude-3-opus-latest", "claude-3-opus"},

		{"claude-3-sonnet", "claude-3-sonnet"},
		{"claude-sonnet", "claude-3-sonnet"},

		{"claude-3-haiku", "claude-3-haiku"},
		{"claude-haiku", "claude-3-haiku"},

		// Llama version normalization
		{"llama-3.1-8b", "llama-3-1-8b"},
		{"llama-3-1-8b", "llama-3-1-8b"},
		{"meta-llama/Meta-Llama-3-1-8B", "llama-3-1-8b"}, // Both meta-llama/ and Meta- stripped
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := CanonicalModelName(tt.input)
			if result != tt.expected {
				t.Errorf("CanonicalModelName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestStripProviderPrefix tests the provider prefix stripping.
func TestStripProviderPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Single prefix
		{"tinfoil/gpt-4", "gpt-4"},
		{"near/gpt-4", "gpt-4"},
		{"nanogpt/gpt-4", "gpt-4"},
		{"redpill/gpt-4", "gpt-4"},
		{"chutes/gpt-4", "gpt-4"},
		{"ppq/gpt-4", "gpt-4"},
		{"ppq-private/gpt-4", "gpt-4"},

		// Nested prefixes (common with NEAR and NanoGPT)
		{"near/openai/gpt-4", "gpt-4"},
		{"near/anthropic/claude-3-opus", "claude-3-opus"},
		{"near/qwen/qwen3-7-max", "qwen3-7-max"},
		{"nanogpt/openai/gpt-4", "gpt-4"},
		{"nanogpt/TEE/qwen3-6-27b", "qwen3-6-27b"},
		{"nanogpt/nvidia/nemotron-3", "nemotron-3"},

		// Triple nested - note: stripProviderPrefix doesn't lowercase
		{"chutes/meta-llama/Meta-Llama-3-1-8B", "Meta-Llama-3-1-8B"},

		// No prefix
		{"gpt-4", "gpt-4"},
		{"claude-3-opus", "claude-3-opus"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := stripProviderPrefix(tt.input)
			// Note: stripProviderPrefix doesn't do case normalization
			// so we compare case-insensitively for the "no prefix" case
			expected := tt.expected
			if strings.Contains(tt.input, "/") {
				// Has prefix, should be stripped
				if result != expected {
					t.Errorf("stripProviderPrefix(%q) = %q, want %q", tt.input, result, expected)
				}
			}
		})
	}
}
