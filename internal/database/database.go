package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/models"
	_ "modernc.org/sqlite"
)

// DB wraps a database connection with our schema operations.
type DB struct {
	db *sql.DB
}

// Open opens a SQLite database and runs migrations.
func Open(cfg config.Database) (*DB, error) {
	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", cfg.Path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	d := &DB{db: db}

	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return d, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// migrate runs database migrations.
func (d *DB) migrate() error {
	migrations := []string{
		// Initial schema
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			key_hash TEXT NOT NULL UNIQUE,
			key_prefix TEXT NOT NULL,
			name TEXT,
			allowed_providers TEXT,
			allowed_models TEXT,
			allowed_regions TEXT,
			preferred_regions TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);`,

		`CREATE TABLE IF NOT EXISTS providers (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			base_url TEXT NOT NULL,
			trust_tier TEXT NOT NULL,
			attestation_config TEXT,
			pricing TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		`CREATE TABLE IF NOT EXISTS provider_models (
			provider_id TEXT NOT NULL,
			model TEXT NOT NULL,
			normalized_model TEXT NOT NULL,
			mode TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			PRIMARY KEY (provider_id, model, mode),
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_provider_models_normalized ON provider_models(normalized_model, mode, enabled);`,

		`CREATE TABLE IF NOT EXISTS provider_attestations (
			provider_id TEXT NOT NULL,
			model TEXT NOT NULL,
			mode TEXT NOT NULL,
			verified BOOLEAN NOT NULL,
			evidence_digest TEXT NOT NULL,
			policy_digest TEXT NOT NULL,
			verified_claims TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (provider_id, model, mode),
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE
		);`,

		`CREATE TABLE IF NOT EXISTS usage_events (
			request_id TEXT PRIMARY KEY,
			timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			api_key_hash_prefix TEXT NOT NULL,
			provider_id TEXT,  -- Nullable for routing failures
			model TEXT NOT NULL,
			mode TEXT NOT NULL,
			status TEXT NOT NULL,
			latency_ms INTEGER NOT NULL,
			prompt_tokens INTEGER,
			completion_tokens INTEGER,
			cost_estimate_usd INTEGER NOT NULL,
			error_code TEXT,
			error_message TEXT,
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE SET NULL
		);`,

		`CREATE INDEX IF NOT EXISTS idx_usage_events_timestamp ON usage_events(timestamp);`,
		`CREATE INDEX IF NOT EXISTS idx_usage_events_key ON usage_events(api_key_hash_prefix);`,

		`CREATE TABLE IF NOT EXISTS pricing_history (
			provider_id TEXT NOT NULL,
			model TEXT NOT NULL,
			price_per_1m_tokens_usd INTEGER NOT NULL,
			effective_from TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (provider_id, model, effective_from),
			FOREIGN KEY (provider_id) REFERENCES providers(id) ON DELETE CASCADE
		);`,
	}

	for _, migration := range migrations {
		if _, err := d.db.Exec(migration); err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}

	return nil
}

// HashAPIKey computes the SHA-256 hash of an API key.
func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// APIKeyPrefix returns the first 8 characters of a key hash.
func APIKeyPrefix(hash string) string {
	if len(hash) >= 8 {
		return hash[:8]
	}
	return hash
}

// CreateAPIKey creates a new API key.
func (d *DB) CreateAPIKey(ctx context.Context, key *models.APIKey) error {
	allowedProviders, _ := json.Marshal(key.AllowedProviders)
	allowedModels, _ := json.Marshal(key.AllowedModels)
	allowedRegions, _ := json.Marshal(key.AllowedRegions)
	preferredRegions, _ := json.Marshal(key.PreferredRegions)

	sql := `INSERT INTO api_keys (id, key_hash, key_prefix, name, allowed_providers, allowed_models, allowed_regions, preferred_regions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	now := time.Now().UTC()
	_, err := d.db.ExecContext(ctx, sql,
		key.ID,
		key.KeyHash,
		key.KeyPrefix,
		key.Name,
		string(allowedProviders),
		string(allowedModels),
		string(allowedRegions),
		string(preferredRegions),
		now,
		now,
	)
	return err
}

// GetAPIKeyByHash retrieves an API key by its hash.
func (d *DB) GetAPIKeyByHash(ctx context.Context, hash string) (*models.APIKey, error) {
	sql := `SELECT id, key_hash, key_prefix, name, allowed_providers, allowed_models, allowed_regions, preferred_regions, created_at, updated_at
		FROM api_keys WHERE key_hash = ?`

	row := d.db.QueryRowContext(ctx, sql, hash)

	key := &models.APIKey{}
	var allowedProviders, allowedModels, allowedRegions, preferredRegions string

	err := row.Scan(&key.ID, &key.KeyHash, &key.KeyPrefix, &key.Name,
		&allowedProviders, &allowedModels, &allowedRegions, &preferredRegions,
		&key.CreatedAt, &key.UpdatedAt)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, fmt.Errorf("api key not found")
		}
		return nil, err
	}

	json.Unmarshal([]byte(allowedProviders), &key.AllowedProviders)
	json.Unmarshal([]byte(allowedModels), &key.AllowedModels)
	json.Unmarshal([]byte(allowedRegions), &key.AllowedRegions)
	json.Unmarshal([]byte(preferredRegions), &key.PreferredRegions)

	return key, nil
}

// ListAPIKeys lists all API keys.
func (d *DB) ListAPIKeys(ctx context.Context) ([]*models.APIKey, error) {
	sql := `SELECT id, key_hash, key_prefix, name, allowed_providers, allowed_models, allowed_regions, preferred_regions, created_at, updated_at FROM api_keys`

	rows, err := d.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		var allowedProviders, allowedModels, allowedRegions, preferredRegions string

		err := rows.Scan(&key.ID, &key.KeyHash, &key.KeyPrefix, &key.Name,
			&allowedProviders, &allowedModels, &allowedRegions, &preferredRegions,
			&key.CreatedAt, &key.UpdatedAt)
		if err != nil {
			continue
		}

		json.Unmarshal([]byte(allowedProviders), &key.AllowedProviders)
		json.Unmarshal([]byte(allowedModels), &key.AllowedModels)
		json.Unmarshal([]byte(allowedRegions), &key.AllowedRegions)
		json.Unmarshal([]byte(preferredRegions), &key.PreferredRegions)

		keys = append(keys, key)
	}

	return keys, rows.Err()
}

// DeleteAPIKey deletes an API key.
func (d *DB) DeleteAPIKey(ctx context.Context, id string) error {
	_, err := d.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = ?", id)
	return err
}

// UpsertProvider creates or updates a provider.
func (d *DB) UpsertProvider(ctx context.Context, p *models.Provider) error {
	// AttestationConfig and Pricing are already JSON strings; store them directly.
	sql := `INSERT INTO providers (id, name, base_url, trust_tier, attestation_config, pricing, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			base_url = excluded.base_url,
			trust_tier = excluded.trust_tier,
			attestation_config = excluded.attestation_config,
			pricing = excluded.pricing,
			updated_at = excluded.updated_at`

	now := time.Now().UTC()
	_, err := d.db.ExecContext(ctx, sql,
		p.ID, p.Name, p.BaseURL, p.TrustTier,
		p.AttestationConfig, p.Pricing,
		now, now,
	)
	return err
}

// GetProvider retrieves a provider by ID.
func (d *DB) GetProvider(ctx context.Context, id string) (*models.Provider, error) {
	sql := `SELECT id, name, base_url, trust_tier, attestation_config, pricing, created_at, updated_at FROM providers WHERE id = ?`

	row := d.db.QueryRowContext(ctx, sql, id)

	p := &models.Provider{}
	var attConfig, pricing string

	err := row.Scan(&p.ID, &p.Name, &p.BaseURL, &p.TrustTier, &attConfig, &pricing, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, fmt.Errorf("provider not found")
		}
		return nil, err
	}

	p.AttestationConfig = attConfig
	p.Pricing = pricing

	return p, nil
}

// ListProviders lists all providers.
func (d *DB) ListProviders(ctx context.Context) ([]*models.Provider, error) {
	sql := `SELECT id, name, base_url, trust_tier, attestation_config, pricing, created_at, updated_at FROM providers`

	rows, err := d.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*models.Provider
	for rows.Next() {
		p := &models.Provider{}
		var attConfig, pricing string

		err := rows.Scan(&p.ID, &p.Name, &p.BaseURL, &p.TrustTier, &attConfig, &pricing, &p.CreatedAt, &p.UpdatedAt)
		if err != nil {
			continue
		}

		p.AttestationConfig = attConfig
		p.Pricing = pricing

		providers = append(providers, p)
	}

	return providers, rows.Err()
}

// UpsertProviderModel creates or updates a provider-model mapping.
func (d *DB) UpsertProviderModel(ctx context.Context, pm *models.ProviderModel) error {
	// Compute normalized model name if not provided
	if pm.NormalizedModel == "" {
		pm.NormalizedModel = models.CanonicalModelName(pm.Model)
	}

	sql := `INSERT INTO provider_models (provider_id, model, normalized_model, mode, enabled)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(provider_id, model, mode) DO UPDATE SET
			normalized_model = excluded.normalized_model,
			enabled = excluded.enabled`
	_, err := d.db.ExecContext(ctx, sql, pm.ProviderID, pm.Model, pm.NormalizedModel, pm.Mode, pm.Enabled)
	return err
}

// GetProviderModels retrieves models for a provider.
func (d *DB) GetProviderModels(ctx context.Context, providerID string) ([]*models.ProviderModel, error) {
	sql := `SELECT provider_id, model, normalized_model, mode, enabled FROM provider_models WHERE provider_id = ?`

	rows, err := d.db.QueryContext(ctx, sql, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models_ []*models.ProviderModel
	for rows.Next() {
		pm := &models.ProviderModel{}
		var mode string
		err := rows.Scan(&pm.ProviderID, &pm.Model, &pm.NormalizedModel, &mode, &pm.Enabled)
		if err != nil {
			continue
		}
		pm.Mode = models.Mode(mode)
		models_ = append(models_, pm)
	}

	return models_, rows.Err()
}

// GetVerifiedProvidersForModel returns providers with valid attestation for a model.
func (d *DB) GetVerifiedProvidersForModel(ctx context.Context, model string, mode models.Mode) ([]*models.ProviderAttestation, error) {
	now := time.Now().UTC()
	sql := `SELECT provider_id, model, mode, verified, evidence_digest, policy_digest, verified_claims, expires_at, created_at, updated_at
		FROM provider_attestations
		WHERE model = ? AND mode = ? AND verified = TRUE AND expires_at > ?`

	rows, err := d.db.QueryContext(ctx, sql, model, mode, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attestations []*models.ProviderAttestation
	for rows.Next() {
		a := &models.ProviderAttestation{}
		var modeStr string
		err := rows.Scan(&a.ProviderID, &a.Model, &modeStr, &a.Verified, &a.EvidenceDigest, &a.PolicyDigest,
			&a.VerifiedClaims, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt)
		if err != nil {
			continue
		}
		a.Mode = models.Mode(modeStr)
		attestations = append(attestations, a)
	}

	return attestations, rows.Err()
}

// UpsertAttestation creates or updates an attestation verdict.
func (d *DB) UpsertAttestation(ctx context.Context, a *models.ProviderAttestation) error {
	sql := `INSERT INTO provider_attestations (provider_id, model, mode, verified, evidence_digest, policy_digest, verified_claims, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_id, model, mode) DO UPDATE SET
			verified = excluded.verified,
			evidence_digest = excluded.evidence_digest,
			policy_digest = excluded.policy_digest,
			verified_claims = excluded.verified_claims,
			expires_at = excluded.expires_at,
			updated_at = excluded.updated_at`

	now := time.Now().UTC()
	_, err := d.db.ExecContext(ctx, sql,
		a.ProviderID, a.Model, a.Mode, a.Verified, a.EvidenceDigest, a.PolicyDigest,
		a.VerifiedClaims, a.ExpiresAt, now, now,
	)
	return err
}

// RecordUsageEvent records a usage event.
func (d *DB) RecordUsageEvent(ctx context.Context, e *models.UsageEvent) error {
	sql := `INSERT INTO usage_events (request_id, timestamp, api_key_hash_prefix, provider_id, model, mode, status, latency_ms, prompt_tokens, completion_tokens, cost_estimate_usd, error_code, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var promptTokens, completionTokens interface{}
	if e.PromptTokens != nil {
		promptTokens = *e.PromptTokens
	}
	if e.CompletionTokens != nil {
		completionTokens = *e.CompletionTokens
	}

	// Convert empty provider_id to NULL for FK constraint
	var providerID interface{}
	if e.ProviderID != "" {
		providerID = e.ProviderID
	}

	_, err := d.db.ExecContext(ctx, sql,
		e.RequestID, e.Timestamp, e.APIKeyHashPrefix, providerID,
		e.Model, e.Mode, e.Status, e.LatencyMs, promptTokens, completionTokens,
		e.CostEstimateUSD, e.ErrorCode, e.ErrorMessage,
	)
	return err
}

// GetProviderModelsWithVerification returns all models for providers with valid attestations.
func (d *DB) GetProviderModelsWithVerification(ctx context.Context, model string, mode models.Mode) ([]*models.ProviderModel, error) {
	now := time.Now().UTC()
	normalizedModel := models.CanonicalModelName(model)

	sql := `SELECT pm.provider_id, pm.model, pm.normalized_model, pm.mode, pm.enabled
		FROM provider_models pm
		JOIN provider_attestations pa ON pm.provider_id = pa.provider_id AND pm.model = pa.model AND pm.mode = pa.mode
		WHERE pm.normalized_model = ? AND pm.mode = ? AND pm.enabled = TRUE AND pa.verified = TRUE AND pa.expires_at > ?`

	rows, err := d.db.QueryContext(ctx, sql, normalizedModel, mode, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models_ []*models.ProviderModel
	for rows.Next() {
		pm := &models.ProviderModel{}
		var modeStr string
		err := rows.Scan(&pm.ProviderID, &pm.Model, &pm.NormalizedModel, &modeStr, &pm.Enabled)
		if err != nil {
			continue
		}
		pm.Mode = models.Mode(modeStr)
		models_ = append(models_, pm)
	}

	return models_, rows.Err()
}

// GetModelsByNormalizedName returns all provider models matching a canonical model name.
func (d *DB) GetModelsByNormalizedName(ctx context.Context, normalizedModel string, mode models.Mode) ([]*models.ProviderModel, error) {
	sql := `SELECT provider_id, model, normalized_model, mode, enabled FROM provider_models 
		WHERE normalized_model = ? AND mode = ? AND enabled = TRUE`

	rows, err := d.db.QueryContext(ctx, sql, normalizedModel, mode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var models_ []*models.ProviderModel
	for rows.Next() {
		pm := &models.ProviderModel{}
		var modeStr string
		err := rows.Scan(&pm.ProviderID, &pm.Model, &pm.NormalizedModel, &modeStr, &pm.Enabled)
		if err != nil {
			continue
		}
		pm.Mode = models.Mode(modeStr)
		models_ = append(models_, pm)
	}

	return models_, rows.Err()
}

// BuildClaimsDigest computes a digest over verified claims.
func BuildClaimsDigest(providerID, model string, mode models.Mode, claims map[string]interface{}) string {
	canonical := fmt.Sprintf("%s:%s:%s:%v", providerID, model, mode, claims)
	h := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h[:])
}
