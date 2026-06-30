package main

import (
	"database/sql"
	"fmt"
	"os"
	"sort"

	_ "modernc.org/sqlite"
)

type ProviderModel struct {
	ProviderID      string
	Model           string
	NormalizedModel string
	Mode            string
	Enabled         bool
}

func main() {
	dbPath := "./encproxy.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}

	dsn := fmt.Sprintf("%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT provider_id, model, normalized_model, mode, enabled
		FROM provider_models
		ORDER BY normalized_model, provider_id
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to query: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	var models []ProviderModel
	for rows.Next() {
		var m ProviderModel
		err := rows.Scan(&m.ProviderID, &m.Model, &m.NormalizedModel, &m.Mode, &m.Enabled)
		if err != nil {
			continue
		}
		models = append(models, m)
	}

	// Print all models
	fmt.Println("=== Provider Models and Normalized Mappings ===")
	fmt.Printf("%-20s %-35s %-25s %-12s %s\n", "Provider", "Model", "Normalized", "Mode", "Enabled")
	fmt.Println("--------------------------------------------------------------------------------------------------------------")

	for _, m := range models {
		enabledStr := "yes"
		if !m.Enabled {
			enabledStr = "no"
		}
		fmt.Printf("%-20s %-35s %-25s %-12s %s\n", m.ProviderID, m.Model, m.NormalizedModel, m.Mode, enabledStr)
	}

	// Statistics
	fmt.Println()
	fmt.Println("=== Statistics ===")
	fmt.Printf("Total models: %d\n", len(models))

	// Count unique normalized models
	normalizedMap := make(map[string]int)
	for _, m := range models {
		normalizedMap[m.NormalizedModel]++
	}
	fmt.Printf("Unique normalized models: %d\n", len(normalizedMap))

	// Count providers
	providerMap := make(map[string]int)
	for _, m := range models {
		providerMap[m.ProviderID]++
	}
	fmt.Printf("Number of providers: %d\n", len(providerMap))

	// Show models with multiple providers (failover candidates)
	fmt.Println()
	fmt.Println("=== Models with Multiple Providers (Failover) ===")
	var multiProviderModels []string
	for norm, count := range normalizedMap {
		if count > 1 {
			multiProviderModels = append(multiProviderModels, norm)
		}
	}
	sort.Strings(multiProviderModels)

	for _, norm := range multiProviderModels {
		fmt.Printf("\nNormalized: %s\n", norm)
		for _, m := range models {
			if m.NormalizedModel == norm {
				fmt.Printf("  - %s: %s (%s, enabled=%v)\n", m.ProviderID, m.Model, m.Mode, m.Enabled)
			}
		}
	}

	// Show unique models (only available from one provider)
	fmt.Println()
	fmt.Println("=== Models Unique to a Single Provider ===")
	var uniqueModels []string
	for norm, count := range normalizedMap {
		if count == 1 {
			uniqueModels = append(uniqueModels, norm)
		}
	}
	sort.Strings(uniqueModels)

	for _, norm := range uniqueModels {
		for _, m := range models {
			if m.NormalizedModel == norm {
				fmt.Printf("  %s: %s from %s (%s, enabled=%v)\n", norm, m.Model, m.ProviderID, m.Mode, m.Enabled)
				break
			}
		}
	}
}
