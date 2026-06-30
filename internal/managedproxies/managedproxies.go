package managedproxies

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPPQPort         = "18787"
	defaultPrivateModePort = "18080"
)

// Credentials contains API keys needed to start local provider encryption
// proxies. The keys are passed only to the corresponding helper process.
type Credentials struct {
	PPQ         string
	PrivateMode string
}

// Manager owns local provider encryption proxy processes for providers whose
// private/confidential API requires an official local proxy.
type Manager struct {
	mu        sync.Mutex
	processes []*managedProcess
	stopped   bool
}

type managedProcess struct {
	name   string
	cancel context.CancelFunc
	done   chan error
	stop   func(context.Context) error
}

// New creates an empty provider proxy manager.
func New() *Manager {
	return &Manager{}
}

// Start starts required local provider proxies and exports their local base URLs
// into the process environment before encproxy configuration is loaded.
func (m *Manager) Start(ctx context.Context, creds Credentials) error {
	if !managedProxiesEnabled() {
		log.Printf("Managed provider proxies disabled")
		return nil
	}

	if creds.PrivateMode != "" && os.Getenv("PRIVATEMODE_PROXY_URL") == "" {
		if err := m.ensurePrivateMode(ctx, creds.PrivateMode); err != nil {
			m.Stop()
			return err
		}
	}

	return nil
}

// Stop terminates proxy processes started by this manager.
func (m *Manager) Stop() {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.stopped = true
	processes := append([]*managedProcess(nil), m.processes...)
	m.mu.Unlock()

	for i := len(processes) - 1; i >= 0; i-- {
		proc := processes[i]
		stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if proc.stop != nil {
			if err := proc.stop(stopCtx); err != nil {
				log.Printf("Failed to stop managed %s proxy cleanly: %v", proc.name, err)
			}
		}
		cancel()
		proc.cancel()
		select {
		case <-proc.done:
		case <-time.After(15 * time.Second):
			log.Printf("Timed out waiting for managed %s proxy to exit", proc.name)
		}
	}
}

func (m *Manager) ensurePPQ(ctx context.Context, apiKey string) error {
	port := envDefault("PPQ_PROXY_PORT", defaultPPQPort)
	baseURL := "http://127.0.0.1:" + port + "/v1"
	if endpointReady(ctx, baseURL, apiKey) {
		os.Setenv("PPQ_PROXY_URL", baseURL)
		log.Printf("Using existing PPQ private proxy: %s", baseURL)
		return nil
	}

	cmd := exec.CommandContext(ctx, "npx", "-y", "ppq-private-mode")
	cmd.Env = append(os.Environ(), "PPQ_API_KEY="+apiKey, "PORT="+port)
	if err := m.startCommand(ctx, "PPQ", cmd, nil); err != nil {
		return fmt.Errorf("start PPQ private proxy: %w", err)
	}
	if err := waitReady(ctx, baseURL, apiKey, 90*time.Second); err != nil {
		return fmt.Errorf("PPQ private proxy did not become ready at %s: %w", baseURL, err)
	}

	os.Setenv("PPQ_PROXY_URL", baseURL)
	log.Printf("Managed PPQ private proxy ready: %s", baseURL)
	return nil
}

func (m *Manager) ensurePrivateMode(ctx context.Context, apiKey string) error {
	port := envDefault("PRIVATEMODE_PROXY_PORT", defaultPrivateModePort)
	baseURL := "http://127.0.0.1:" + port + "/v1"
	if endpointReady(ctx, baseURL, apiKey) {
		os.Setenv("PRIVATEMODE_PROXY_URL", baseURL)
		log.Printf("Using existing PrivateMode proxy: %s", baseURL)
		return nil
	}

	dockerCmd, dockerPrefix, err := dockerCommand(ctx)
	if err != nil {
		return err
	}

	containerName := fmt.Sprintf("encproxy-privatemode-proxy-%d", os.Getpid())
	args := append([]string{}, dockerPrefix...)
	args = append(args,
		"run",
		"--rm",
		"--name", containerName,
		"-p", "127.0.0.1:"+port+":8080",
		"ghcr.io/edgelesssys/privatemode/privatemode-proxy:latest",
		"--apiKey", apiKey,
	)
	cmd := exec.CommandContext(ctx, dockerCmd, args...)
	stop := func(stopCtx context.Context) error {
		stopArgs := append([]string{}, dockerPrefix...)
		stopArgs = append(stopArgs, "stop", containerName)
		return exec.CommandContext(stopCtx, dockerCmd, stopArgs...).Run()
	}

	if err := m.startCommand(ctx, "PrivateMode", cmd, stop); err != nil {
		return fmt.Errorf("start PrivateMode proxy: %w", err)
	}
	if err := waitReady(ctx, baseURL, apiKey, 120*time.Second); err != nil {
		return fmt.Errorf("PrivateMode proxy did not become ready at %s: %w", baseURL, err)
	}

	os.Setenv("PRIVATEMODE_PROXY_URL", baseURL)
	log.Printf("Managed PrivateMode proxy ready: %s", baseURL)
	return nil
}

func (m *Manager) startCommand(ctx context.Context, name string, cmd *exec.Cmd, stop func(context.Context) error) error {
	childCtx, cancel := context.WithCancel(ctx)
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	commandPath := cmd.Path
	commandArgs := append([]string{}, cmd.Args[1:]...)
	commandEnv := append([]string{}, cmd.Env...)

	cmd = exec.CommandContext(childCtx, commandPath, commandArgs...)
	cmd.Env = commandEnv
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
	cmd.WaitDelay = 5 * time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = logWriter{name: name}
	cmd.Stderr = logWriter{name: name}

	if err := cmd.Start(); err != nil {
		cancel()
		return err
	}

	proc := &managedProcess{
		name:   name,
		cancel: cancel,
		done:   make(chan error, 1),
		stop:   stop,
	}
	m.mu.Lock()
	m.processes = append(m.processes, proc)
	m.mu.Unlock()

	go func() {
		err := cmd.Wait()
		if childCtx.Err() == nil && err != nil {
			log.Printf("Managed %s proxy exited: %v", name, err)
		}
		proc.done <- err
	}()

	return nil
}

func waitReady(ctx context.Context, baseURL, apiKey string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if endpointReady(ctx, baseURL, apiKey) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = fmt.Errorf("endpoint not ready")
		time.Sleep(500 * time.Millisecond)
	}
	return lastErr
}

func endpointReady(ctx context.Context, baseURL, apiKey string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return false
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func dockerCommand(ctx context.Context) (string, []string, error) {
	if commandSucceeds(ctx, "docker", "info") {
		return "docker", nil, nil
	}
	if commandSucceeds(ctx, "sudo", "-n", "docker", "info") {
		return "sudo", []string{"-n", "docker"}, nil
	}
	return "", nil, fmt.Errorf("docker is required for managed PrivateMode proxy; install/configure docker or set PRIVATEMODE_PROXY_URL")
}

func commandSucceeds(ctx context.Context, name string, args ...string) bool {
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return exec.CommandContext(cmdCtx, name, args...).Run() == nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func managedProxiesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ENCPROXY_MANAGE_PROVIDER_PROXIES"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

type logWriter struct {
	name string
}

func (w logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			log.Printf("%s proxy: %s", w.name, line)
		}
	}
	return len(p), nil
}
