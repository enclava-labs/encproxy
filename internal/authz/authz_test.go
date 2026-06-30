package authz

import (
	"testing"

	"github.com/enclava/encproxy/internal/models"
)

func TestParseAPIKey(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "Bearer token",
			header: "Bearer sk-abc123",
			want:   "sk-abc123",
		},
		{
			name:   "Bearer lowercase",
			header: "bearer sk-abc123",
			want:   "sk-abc123",
		},
		{
			name:   "Direct key",
			header: "sk-abc123",
			want:   "sk-abc123",
		},
		{
			name:   "With extra spaces",
			header: "  Bearer sk-abc123  ",
			want:   "sk-abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseAPIKey(tt.header)
			if got != tt.want {
				t.Errorf("ParseAPIKey(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestMatchesModel(t *testing.T) {
	tests := []struct {
		pattern string
		model   string
		want    bool
	}{
		{"meta-llama/Meta-Llama-3.1-8B-Instruct", "meta-llama/Meta-Llama-3.1-8B-Instruct", true},
		{"meta-llama/*", "meta-llama/Meta-Llama-3.1-8B-Instruct", true},
		{"meta-llama/*", "meta-llama/Meta-Llama-3.1-70B-Instruct", true},
		{"meta-llama/*", "openai/gpt-4", false},
		{"*/llama-3", "some-vendor/llama-3", true},
		{"*/llama-3", "some-vendor/meta-llama-3", true},
		{"*/llama-3", "some-vendor/gpt-4", false},
		{"anthropic/claude-3-opus", "anthropic/claude-3-opus", true},
		{"anthropic/claude-3-opus", "anthropic/claude-3-sonnet", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.model, func(t *testing.T) {
			got := matchesModel(tt.pattern, tt.model)
			if got != tt.want {
				t.Errorf("matchesModel(%q, %q) = %v, want %v", tt.pattern, tt.model, got, tt.want)
			}
		})
	}
}

func TestCheckProviderAllowed(t *testing.T) {
	authorizer := &Authorizer{}

	key := &models.APIKey{
		AllowedProviders: []string{"tinfoil", "ppq"},
	}

	tests := []struct {
		providerID string
		want       bool
	}{
		{"tinfoil", true},
		{"ppq", true},
		{"openai", false},
		{"", true}, // Empty list allows all
	}

	// Test with restricted key
	for _, tt := range tests {
		t.Run("restricted_"+tt.providerID, func(t *testing.T) {
			got := authorizer.CheckProviderAllowed(key, tt.providerID)
			if got != tt.want {
				t.Errorf("CheckProviderAllowed(%q) = %v, want %v", tt.providerID, got, tt.want)
			}
		})
	}

	// Test with unrestricted key
	unrestrictedKey := &models.APIKey{AllowedProviders: []string{}}
	tests = []struct {
		providerID string
		want       bool
	}{
		{"any-provider", true},
	}

	for _, tt := range tests {
		t.Run("unrestricted_"+tt.providerID, func(t *testing.T) {
			got := authorizer.CheckProviderAllowed(unrestrictedKey, tt.providerID)
			if got != tt.want {
				t.Errorf("CheckProviderAllowed(%q) = %v, want %v", tt.providerID, got, tt.want)
			}
		})
	}
}

func TestPrioritizeRegions(t *testing.T) {
	tests := []struct {
		name      string
		preferred []string
		requested []string
		want      []string
	}{
		{
			name:      "No preferred",
			preferred: []string{},
			requested: []string{"us-east-1", "eu-west-1"},
			want:      []string{"us-east-1", "eu-west-1"},
		},
		{
			name:      "Preferred first",
			preferred: []string{"eu-west-1"},
			requested: []string{"us-east-1", "eu-west-1"},
			want:      []string{"eu-west-1", "us-east-1"},
		},
		{
			name:      "Multiple preferred",
			preferred: []string{"eu-west-1", "us-east-1"},
			requested: []string{"us-west-2", "us-east-1", "eu-west-1"},
			want:      []string{"eu-west-1", "us-east-1", "us-west-2"},
		},
		{
			name:      "No requested",
			preferred: []string{"eu-west-1"},
			requested: []string{},
			want:      []string{"eu-west-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prioritizeRegions(tt.preferred, tt.requested)
			if len(got) != len(tt.want) {
				t.Errorf("prioritizeRegions(%v, %v) = %v, want %v", tt.preferred, tt.requested, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("prioritizeRegions(%v, %v)[%d] = %v, want %v", tt.preferred, tt.requested, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizeRegion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"us-east-1", "us-east-1"},
		{"US-East-1", "us-east-1"},
		{"  eu-west-1  ", "eu-west-1"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRegion(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRegion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func BenchmarkParseAPIKey(b *testing.B) {
	header := "Bearer sk-abc123def456ghi789"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseAPIKey(header)
	}
}
