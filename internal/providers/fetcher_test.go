package providers

import "testing"

func TestSupportsChatCompletions(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"tinfoil/gpt-oss-120b", true},
		{"near/Qwen/Qwen3-VL-30B-A3B-Instruct", true},
		{"chutes/Qwen/Qwen3-32B-TEE", true},
		{"tinfoil/nomic-embed-text", false},
		{"near/Qwen/Qwen3-Embedding-0.6B", false},
		{"near/Qwen/Qwen3-Reranker-0.6B", false},
		{"tinfoil/doc-upload", false},
		{"tinfoil/websearch", false},
		{"tinfoil/whisper-large-v3-turbo", false},
		{"tinfoil/qwen3-tts", false},
		{"tinfoil/voxtral-mini-4b-realtime", false},
		{"near/black-forest-labs/FLUX.2-klein-4B", false},
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
