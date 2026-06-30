package attestation

import "testing"

func TestIsNanoGPTTEEModel(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{"TEE/qwen3.6-27b", true},
		{"nanogpt/TEE/qwen3.6-27b", true},
		{"Qwen/Qwen3-235B-A22B-Instruct-2507-TEE", false},
		{"Steelskull/L3.3-Cu-Mai-R1-70b", false},
		{"openai/gpt-oss-120b", false},
	}

	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := isNanoGPTTEEModel(tt.model); got != tt.want {
				t.Fatalf("isNanoGPTTEEModel(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}
