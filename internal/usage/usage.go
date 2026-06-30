package usage

import (
	"context"
	"log"

	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/models"
)

// Service handles usage event recording.
type Service struct {
	db *database.DB
}

// NewService creates a new usage service.
func NewService(db *database.DB) *Service {
	return &Service{db: db}
}

// RecordEvent records a usage event.
func (s *Service) RecordEvent(ctx context.Context, event *models.UsageEvent) error {
	// Ensure we never record user content
	// The event structure enforces metadata-only by design
	if err := s.db.RecordUsageEvent(ctx, event); err != nil {
		// Log but don't fail the request
		log.Printf("usage recording failed: %v", err)
		return err
	}
	return nil
}

// GetUsageStats returns aggregated usage statistics.
func (s *Service) GetUsageStats(ctx context.Context, apiKeyPrefix string) (*UsageStats, error) {
	// This would query the DB for aggregated stats
	// For now, return empty stats
	return &UsageStats{}, nil
}

// UsageStats represents usage statistics.
type UsageStats struct {
	TotalRequests     int64   `json:"total_requests"`
	TotalTokens       int64   `json:"total_tokens"`
	TotalCostMicroUSD int64   `json:"total_cost_micro_usd"`
	AverageLatencyMs  float64 `json:"average_latency_ms"`
}
