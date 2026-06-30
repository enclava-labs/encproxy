package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/enclava/encproxy/internal/admin"
	"github.com/enclava/encproxy/internal/attestation"
	"github.com/enclava/encproxy/internal/authz"
	"github.com/enclava/encproxy/internal/config"
	"github.com/enclava/encproxy/internal/database"
	"github.com/enclava/encproxy/internal/managedproxies"
	"github.com/enclava/encproxy/internal/models"
	"github.com/enclava/encproxy/internal/providers"
	"github.com/enclava/encproxy/internal/proxy"
	"github.com/enclava/encproxy/internal/routing"
	"github.com/enclava/encproxy/internal/usage"
)

func loadCredentials() providers.ProviderCredentials {
	return providers.ProviderCredentials{
		Tinfoil:     os.Getenv("TINFOIL_API_KEY"),
		PPQ:         os.Getenv("PPQ_API_KEY"),
		Redpill:     os.Getenv("REDPILL_API_KEY"),
		Nanogpt:     os.Getenv("NANOGPT_API_KEY"),
		Near:        os.Getenv("NEAR_API_KEY"),
		Chutes:      os.Getenv("CHUTES_API_KEY"),
		PrivateMode: os.Getenv("PRIVATEMODE_API_KEY"),
	}
}

func main() {
	var (
		configPath  = flag.String("config", "encproxy.toml", "Path to configuration file")
		initDB      = flag.Bool("init", false, "Initialize database and exit")
		fetchModels = flag.Bool("fetch-models", false, "Fetch models from providers and exit")
	)
	flag.Parse()

	// Load provider credentials from environment
	creds := loadCredentials()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if !*initDB {
		managedCreds := managedproxies.Credentials{}
		if configIncludesProvider(cfg, "ppq") {
			managedCreds.PPQ = creds.PPQ
		}
		if configIncludesProvider(cfg, "privatemode") {
			managedCreds.PrivateMode = creds.PrivateMode
		}

		proxyManager := managedproxies.New()
		if err := proxyManager.Start(ctx, managedCreds); err != nil {
			log.Fatalf("Failed to start managed provider proxies: %v", err)
		}
		defer proxyManager.Stop()

		// Managed proxies may set runtime proxy URLs after the first config load.
		cfg.ApplyRuntimeProviderOverrides()
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// Open database
	db, err := database.Open(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	log.Printf("Database opened: %s", cfg.Database.Path)

	if *initDB {
		log.Println("Database initialized successfully")
		return
	}

	// Initialize services
	authorizer := authz.NewAuthorizer(db)
	router := routing.NewRouter(db)
	usageSvc := usage.NewService(db)

	// Build provider API key map (needed for both attestation and proxy)
	providerKeys := map[string]string{
		"tinfoil":     creds.Tinfoil,
		"ppq":         creds.PPQ,
		"redpill":     creds.Redpill,
		"nanogpt":     creds.Nanogpt,
		"near":        creds.Near,
		"chutes":      creds.Chutes,
		"privatemode": creds.PrivateMode,
	}

	// Initialize attestation service with provider keys
	attestationSvc := attestation.NewService(db, cfg.Attestation, providerKeys)

	// Initialize providers from config
	for _, p := range cfg.Providers {
		log.Printf("Configuring provider: %s (%s)", p.ID, p.Name)

		attConfig, _ := json.Marshal(p.AttestationConfig)
		pricing, _ := json.Marshal(p.Pricing)

		provider := &models.Provider{
			ID:                p.ID,
			Name:              p.Name,
			BaseURL:           p.BaseURL,
			TrustTier:         models.TrustTier(p.TrustTier),
			AttestationConfig: string(attConfig),
			Pricing:           string(pricing),
		}

		if err := db.UpsertProvider(ctx, provider); err != nil {
			log.Printf("Failed to configure provider %s: %v", p.ID, err)
		}
	}

	// Handle fetch-models flag
	if *fetchModels {
		log.Println("Fetching models from configured providers...")
		fetcher := providers.NewModelFetcher(db)
		if err := fetcher.FetchAllModels(ctx, creds); err != nil {
			log.Fatalf("Failed to fetch models: %v", err)
		}
		log.Println("Models fetched successfully")
		return
	}

	// Start attestation service
	go attestationSvc.Start(ctx)
	defer attestationSvc.Stop()

	// Create servers
	proxyServer := proxy.NewServer(db, router, authorizer, attestationSvc, usageSvc, cfg.Server.MaxRequestBytes, providerKeys, cfg.Server.ConfidentialOnly)
	adminServer := admin.NewServer(db, cfg, attestationSvc, creds)

	// Setup HTTP muxes
	proxyMux := http.NewServeMux()
	proxyServer.RegisterRoutes(proxyMux)

	adminMux := http.NewServeMux()
	adminServer.RegisterRoutes(adminMux)

	// Create HTTP servers
	proxyHTTPServer := &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      proxyMux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	adminHTTPServer := &http.Server{
		Addr:         cfg.Server.AdminListenAddr,
		Handler:      adminMux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start servers
	go func() {
		log.Printf("Proxy server listening on %s", cfg.Server.ListenAddr)
		if err := proxyHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	go func() {
		log.Printf("Admin server listening on %s", cfg.Server.AdminListenAddr)
		if err := adminHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := proxyHTTPServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Proxy server shutdown error: %v", err)
	}
	if err := adminHTTPServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Admin server shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}

func configIncludesProvider(cfg *config.Config, providerID string) bool {
	for _, provider := range cfg.Providers {
		if provider.ID == providerID {
			return true
		}
	}
	return false
}
