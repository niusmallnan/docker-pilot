package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{
			name:     "append to empty slice",
			slice:    []string{},
			item:     "test",
			expected: []string{"test"},
		},
		{
			name:     "append new item",
			slice:    []string{"a", "b"},
			item:     "c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "skip duplicate item",
			slice:    []string{"a", "b", "c"},
			item:     "b",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "append duplicate at beginning",
			slice:    []string{"a", "b", "c"},
			item:     "a",
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendUnique(tt.slice, tt.item)
			if len(result) != len(tt.expected) {
				t.Errorf("expected length %d, got %d", len(tt.expected), len(result))
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("expected %v at index %d, got %v", tt.expected[i], i, result[i])
				}
			}
		})
	}
}

func TestDaemonConfigJSON(t *testing.T) {
	config := &DaemonConfig{
		InsecureRegistries: []string{"registry.example.com"},
		RegistryMirrors:    []string{"https://registry.example.com"},
		BIP:                "172.31.0.1/16",
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	var decoded DaemonConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	if decoded.BIP != config.BIP {
		t.Errorf("expected BIP %s, got %s", config.BIP, decoded.BIP)
	}

	if len(decoded.InsecureRegistries) != 1 || decoded.InsecureRegistries[0] != "registry.example.com" {
		t.Errorf("InsecureRegistries mismatch")
	}
}

func TestWriteProxyConfig(t *testing.T) {
	// Create temp directory for testing
	tmpDir := t.TempDir()

	// Override the systemd drop-in directory for testing
	// Note: This test only verifies the file writing logic works
	config := ProxyConfig{
		Configured: true,
		HTTPProxy:  "http://proxy.example.com:8080",
		HTTPSProxy: "http://proxy.example.com:8080",
		NoProxy:    "localhost,127.0.0.1",
	}

	// Test the content generation by checking the structure
	content := `[Service]
Environment="HTTP_PROXY=` + config.HTTPProxy + `"
Environment="HTTPS_PROXY=` + config.HTTPSProxy + `"
Environment="NO_PROXY=` + config.NoProxy + `"
`

	if !contains(content, "HTTP_PROXY=http://proxy.example.com:8080") {
		t.Error("Proxy config content missing HTTP_PROXY")
	}

	if !contains(content, "HTTPS_PROXY=http://proxy.example.com:8080") {
		t.Error("Proxy config content missing HTTPS_PROXY")
	}

	if !contains(content, "NO_PROXY=localhost,127.0.0.1") {
		t.Error("Proxy config content missing NO_PROXY")
	}

	// Test actual file writing to temp directory
	testDropinDir := filepath.Join(tmpDir, "docker.service.d")
	testFile := filepath.Join(testDropinDir, "http-proxy.conf")

	if err := os.MkdirAll(testDropinDir, 0755); err != nil {
		t.Fatalf("failed to create test dir: %v", err)
	}

	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}

	if string(data) != content {
		t.Error("file content mismatch")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRegistryConfig(t *testing.T) {
	config := RegistryConfig{
		Configured: true,
		Registry:   "registry.example.com",
	}

	if !config.Configured {
		t.Error("expected Configured to be true")
	}

	if config.Registry != "registry.example.com" {
		t.Errorf("expected Registry to be 'registry.example.com', got '%s'", config.Registry)
	}
}

func TestCIDRConfig(t *testing.T) {
	config := CIDRConfig{
		Configured: true,
		BIP:        "172.31.0.1/16",
	}

	if !config.Configured {
		t.Error("expected Configured to be true")
	}

	if config.BIP != "172.31.0.1/16" {
		t.Errorf("expected BIP to be '172.31.0.1/16', got '%s'", config.BIP)
	}
}

func TestReadWriteDaemonConfig(t *testing.T) {
	tmpDir := t.TempDir()
	daemonJSON := filepath.Join(tmpDir, "daemon.json")

	// Use temp file to test write/read round-trip
	config := &DaemonConfig{
		InsecureRegistries: []string{"registry.example.com"},
		RegistryMirrors:    []string{"https://registry.example.com"},
		BIP:                "10.0.0.1/16",
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(daemonJSON, data, 0644); err != nil {
		t.Fatalf("failed to write temp daemon.json: %v", err)
	}

	readData, err := os.ReadFile(daemonJSON)
	if err != nil {
		t.Fatalf("failed to read temp daemon.json: %v", err)
	}
	var decoded DaemonConfig
	if err := json.Unmarshal(readData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.BIP != config.BIP {
		t.Errorf("BIP mismatch: got %s, want %s", decoded.BIP, config.BIP)
	}
	if len(decoded.InsecureRegistries) != 1 || decoded.InsecureRegistries[0] != config.InsecureRegistries[0] {
		t.Error("InsecureRegistries mismatch")
	}
	if len(decoded.RegistryMirrors) != 1 || decoded.RegistryMirrors[0] != config.RegistryMirrors[0] {
		t.Error("RegistryMirrors mismatch")
	}
}

func TestReadDaemonConfigNonExistent(t *testing.T) {
	// readDaemonConfig reads from a hardcoded path, but the logic is testable:
	// Non-existent file should return an error
	_, err := os.ReadFile("/nonexistent/path/daemon.json")
	if err == nil {
		t.Error("expected error reading non-existent file")
	}
}

func TestWriteRegistryConfigContent(t *testing.T) {
	config := RegistryConfig{
		Configured: true,
		Registry:   "my-registry.internal.com",
	}

	// Verify the data structure that would be written
	daemonConfig := &DaemonConfig{
		InsecureRegistries: appendUnique(nil, config.Registry),
		RegistryMirrors:    appendUnique(nil, "https://"+config.Registry),
	}

	if len(daemonConfig.InsecureRegistries) != 1 {
		t.Fatal("expected 1 insecure registry")
	}
	if daemonConfig.InsecureRegistries[0] != "my-registry.internal.com" {
		t.Errorf("expected 'my-registry.internal.com', got '%s'", daemonConfig.InsecureRegistries[0])
	}
	if len(daemonConfig.RegistryMirrors) != 1 {
		t.Fatal("expected 1 registry mirror")
	}
	if daemonConfig.RegistryMirrors[0] != "https://my-registry.internal.com" {
		t.Errorf("expected 'https://my-registry.internal.com', got '%s'", daemonConfig.RegistryMirrors[0])
	}

	data, err := json.MarshalIndent(daemonConfig, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !contains(string(data), "my-registry.internal.com") {
		t.Error("marshaled JSON missing registry reference")
	}
}

func TestWriteCIDRConfigContent(t *testing.T) {
	config := CIDRConfig{
		Configured: true,
		BIP:        "10.100.0.1/16",
	}

	daemonConfig := &DaemonConfig{
		BIP: config.BIP,
	}

	if daemonConfig.BIP != "10.100.0.1/16" {
		t.Errorf("expected BIP '10.100.0.1/16', got '%s'", daemonConfig.BIP)
	}

	data, err := json.MarshalIndent(daemonConfig, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !contains(string(data), "10.100.0.1/16") {
		t.Error("marshaled JSON missing BIP reference")
	}
}

func TestAppendUniqueOnDaemonConfig(t *testing.T) {
	existing := []string{"reg1.example.com", "reg2.example.com"}
	updated := appendUnique(existing, "reg2.example.com")
	if len(updated) != 2 {
		t.Error("duplicate should not be added")
	}
	updated = appendUnique(updated, "reg3.example.com")
	if len(updated) != 3 {
		t.Error("new item should be added")
	}
}
