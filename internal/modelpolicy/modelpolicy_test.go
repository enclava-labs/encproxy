package modelpolicy

import "testing"

func TestIsProviderModelTEEEligible(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		want     bool
	}{
		{"tinfoil open model", "tinfoil", "gpt-oss-120b", true},
		{"redpill gpt oss", "redpill", "openai/gpt-oss-120b", false},
		{"redpill phala", "redpill", "phala/deepseek-v4-flash", true},
		{"redpill anthropic", "redpill", "anthropic/claude-opus-4", false},
		{"redpill claude no prefix", "redpill", "claude-sonnet-4", false},
		{"redpill openai hosted", "redpill", "openai/gpt-5", false},
		{"redpill google gemini", "redpill", "google/gemini-2.5-pro", false},
		{"redpill google gemma", "redpill", "google/gemma-4-31B-it", false},
		{"redpill xai grok", "redpill", "x-ai/grok-4", false},
		{"nanogpt tee namespace", "nanogpt", "TEE/qwen3.6-27b", true},
		{"nanogpt public namespace", "nanogpt", "openai/gpt-oss-120b", false},
		{"ppq private", "ppq", "private/gpt-oss-120b", true},
		{"ppq public", "ppq", "openai/gpt-oss-120b", false},
		{"chutes tee suffix", "chutes", "Qwen/Qwen3-32B-TEE", true},
		{"chutes no tee marker", "chutes", "Qwen/Qwen3-32B", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsProviderModelTEEEligible(tt.provider, tt.model); got != tt.want {
				t.Fatalf("IsProviderModelTEEEligible(%q, %q) = %v, want %v", tt.provider, tt.model, got, tt.want)
			}
		})
	}
}

func TestSupportsChatCompletions(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"tinfoil/gpt-oss-120b", true},
		{"near/Qwen/Qwen3-VL-30B-A3B-Instruct", true},
		{"tinfoil/nomic-embed-text", false},
		{"tinfoil/doc-upload", false},
		{"near/openai/privacy-filter", false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := SupportsChatCompletions(tt.model); got != tt.want {
				t.Fatalf("SupportsChatCompletions(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}
