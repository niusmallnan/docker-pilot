package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAnalyzeContainers(t *testing.T) {
	tests := []struct {
		name        string
		containers  []ContainerInfo
		expectCount int
	}{
		{
			name:        "empty container list",
			containers:  []ContainerInfo{},
			expectCount: 0,
		},
		{
			name: "healthy running container",
			containers: []ContainerInfo{
				{
					Name: "nginx",
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status:       "running",
						Running:      true,
						RestartCount: 0,
					},
					Config: struct{ Image string }{
						Image: "nginx:1.21",
					},
				},
			},
			expectCount: 1,
		},
		{
			name: "container with high restart count",
			containers: []ContainerInfo{
				{
					Name: "unstable-app",
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status:       "running",
						Running:      true,
						RestartCount: 10,
					},
					Config: struct{ Image string }{
						Image: "app:latest",
					},
				},
			},
			expectCount: 1,
		},
		{
			name: "stopped container with restart policy always",
			containers: []ContainerInfo{
				{
					Name: "crashed-app",
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status:       "exited",
						Running:      false,
						RestartCount: 5,
					},
					Config: struct{ Image string }{
						Image: "app:v1",
					},
					HostConfig: struct {
						RestartPolicy struct{ Name string }
					}{
						RestartPolicy: struct{ Name string }{
							Name: "always",
						},
					},
				},
			},
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reports := analyzeContainers(tt.containers)
			if len(reports) != tt.expectCount {
				t.Errorf("expected %d reports, got %d", tt.expectCount, len(reports))
			}
		})
	}
}

func TestContainerHealthStatus(t *testing.T) {
	container := ContainerInfo{
		Name: "test-container",
		State: struct {
			Status       string
			Running      bool
			RestartCount int    `json:"RestartCount"`
			StartedAt    string `json:"StartedAt"`
		}{
			Status:       "running",
			Running:      true,
			RestartCount: 0,
		},
		Config: struct{ Image string }{
			Image: "test:v1",
		},
	}

	reports := analyzeContainers([]ContainerInfo{container})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	if reports[0].Status != "healthy" {
		t.Errorf("expected status 'healthy', got '%s'", reports[0].Status)
	}

	if len(reports[0].Issues) != 0 {
		t.Errorf("expected 0 issues for healthy container, got %d", len(reports[0].Issues))
	}
}

func TestContainerWithLatestTag(t *testing.T) {
	container := ContainerInfo{
		Name: "test-container",
		State: struct {
			Status       string
			Running      bool
			RestartCount int    `json:"RestartCount"`
			StartedAt    string `json:"StartedAt"`
		}{
			Status:       "running",
			Running:      true,
			RestartCount: 0,
		},
		Config: struct{ Image string }{
			Image: "test:latest",
		},
	}

	reports := analyzeContainers([]ContainerInfo{container})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	if len(reports[0].Issues) != 1 {
		t.Errorf("expected 1 issue for latest tag, got %d", len(reports[0].Issues))
	}
}

func TestContainerNameTrimSlash(t *testing.T) {
	container := ContainerInfo{
		Name: "/my-container",
		State: struct {
			Status       string
			Running      bool
			RestartCount int    `json:"RestartCount"`
			StartedAt    string `json:"StartedAt"`
		}{
			Status:       "running",
			Running:      true,
			RestartCount: 0,
		},
		Config: struct{ Image string }{
			Image: "test:v1",
		},
	}

	reports := analyzeContainers([]ContainerInfo{container})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	if reports[0].Container.Name != "my-container" {
		t.Errorf("expected name 'my-container' (without slash), got '%s'", reports[0].Container.Name)
	}
}

func TestHighRestartCountWarning(t *testing.T) {
	container := ContainerInfo{
		Name: "unstable",
		State: struct {
			Status       string
			Running      bool
			RestartCount int    `json:"RestartCount"`
			StartedAt    string `json:"StartedAt"`
		}{
			Status:       "running",
			Running:      true,
			RestartCount: 6,
		},
		Config: struct{ Image string }{
			Image: "test:v1",
		},
	}

	reports := analyzeContainers([]ContainerInfo{container})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	// High restart count (6) should produce warning
	if reports[0].Status != "warning" {
		t.Errorf("expected status 'warning' for restart count > 5, got '%s'", reports[0].Status)
	}
}

func TestStoppedContainerWithRestartPolicy(t *testing.T) {
	container := ContainerInfo{
		Name: "crashed",
		State: struct {
			Status       string
			Running      bool
			RestartCount int    `json:"RestartCount"`
			StartedAt    string `json:"StartedAt"`
		}{
			Status:       "exited",
			Running:      false,
			RestartCount: 10,
		},
		Config: struct{ Image string }{
			Image: "test:v1",
		},
		HostConfig: struct {
			RestartPolicy struct{ Name string }
		}{
			RestartPolicy: struct{ Name string }{
				Name: "always",
			},
		},
	}

	reports := analyzeContainers([]ContainerInfo{container})
	if len(reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(reports))
	}

	if reports[0].Status != "critical" {
		t.Errorf("expected status 'critical' for stopped container with restart policy, got '%s'", reports[0].Status)
	}

	if len(reports[0].Suggestions) == 0 {
		t.Error("expected suggestions for critical container")
	}
}

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintHealthReport(t *testing.T) {
	t.Run("healthy container", func(t *testing.T) {
		reports := []ContainerHealth{
			{
				Container: ContainerInfo{
					Name: "nginx",
					Config: struct{ Image string }{
						Image: "nginx:1.21",
					},
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status: "running",
					},
				},
				Status: "healthy",
			},
		}
		output := captureStdout(func() { printHealthReport(reports) })
		if !strings.Contains(output, "Healthy: 1") {
			t.Error("expected 'Healthy: 1' in output, got:", output)
		}
	})

	t.Run("warning container", func(t *testing.T) {
		reports := []ContainerHealth{
			{
				Container: ContainerInfo{
					Name: "unstable-app",
					Config: struct{ Image string }{
						Image: "app:latest",
					},
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status: "running",
					},
				},
				Status: "warning",
				Issues: []string{"High restart count: 10"},
			},
		}
		output := captureStdout(func() { printHealthReport(reports) })
		if !strings.Contains(output, "Warning: 1") {
			t.Error("expected 'Warning: 1' in output, got:", output)
		}
		if !strings.Contains(output, "WARNING") {
			t.Error("expected 'WARNING' status in output")
		}
	})

	t.Run("critical container", func(t *testing.T) {
		reports := []ContainerHealth{
			{
				Container: ContainerInfo{
					Name: "crashed-app",
					Config: struct{ Image string }{
						Image: "app:v1",
					},
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{
						Status: "exited",
					},
				},
				Status: "critical",
				Issues: []string{"Container is not running"},
				Suggestions: []string{
					"Check logs: `docker logs crashed-app`",
				},
			},
		}
		output := captureStdout(func() { printHealthReport(reports) })
		if !strings.Contains(output, "Critical: 1") {
			t.Error("expected 'Critical: 1' in output, got:", output)
		}
		if !strings.Contains(output, "CRITICAL") {
			t.Error("expected 'CRITICAL' status in output")
		}
	})

	t.Run("mixed statuses", func(t *testing.T) {
		reports := []ContainerHealth{
			{
				Container: ContainerInfo{
					Name:   "nginx",
					Config: struct{ Image string }{Image: "nginx:1.21"},
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{Status: "running"},
				},
				Status: "healthy",
			},
			{
				Container: ContainerInfo{
					Name:   "api",
					Config: struct{ Image string }{Image: "api:latest"},
					State: struct {
						Status       string
						Running      bool
						RestartCount int    `json:"RestartCount"`
						StartedAt    string `json:"StartedAt"`
					}{Status: "running"},
				},
				Status:      "warning",
				Issues:      []string{"Using 'latest' tag"},
				Suggestions: []string{"Use specific version tags"},
			},
		}
		output := captureStdout(func() { printHealthReport(reports) })
		if !strings.Contains(output, "Healthy: 1") {
			t.Error("expected 'Healthy: 1' in output")
		}
		if !strings.Contains(output, "Warning: 1") {
			t.Error("expected 'Warning: 1' in output")
		}
		if !strings.Contains(output, "2 containers analyzed") {
			t.Error("expected '2 containers analyzed' in output")
		}
	})

	t.Run("empty reports", func(t *testing.T) {
		output := captureStdout(func() { printHealthReport(nil) })
		if !strings.Contains(output, "0 containers analyzed") {
			t.Error("expected '0 containers analyzed' in output")
		}
	})
}

func TestPrintScanReport(t *testing.T) {
	t.Run("report with vulnerabilities", func(t *testing.T) {
		report := types.Report{
			ArtifactName: "alpine:3.15",
			Results: types.Results{
				{
					Target: "alpine:3.15 (alpine 3.15.4)",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2022-28391",
							PkgName:          "busybox",
							InstalledVersion: "1.34.1-r3",
							FixedVersion:     "1.34.1-r4",
							Vulnerability:    dbTypes.Vulnerability{Severity: "CRITICAL"},
						},
						{
							VulnerabilityID:  "CVE-2022-37434",
							PkgName:          "zlib",
							InstalledVersion: "1.2.12-r0",
							FixedVersion:     "1.2.12-r1",
							Vulnerability:    dbTypes.Vulnerability{Severity: "HIGH"},
						},
						{
							VulnerabilityID:  "CVE-2021-42374",
							PkgName:          "busybox",
							InstalledVersion: "1.34.1-r3",
							FixedVersion:     "",
							Vulnerability:    dbTypes.Vulnerability{Severity: "MEDIUM"},
						},
					},
				},
			},
		}
		output := captureStdout(func() { printScanReport(report) })
		if !strings.Contains(output, "CVE-2022-28391") {
			t.Error("expected CVE-2022-28391 (CRITICAL) in output")
		}
		if !strings.Contains(output, "CVE-2022-37434") {
			t.Error("expected CVE-2022-37434 (HIGH) in output")
		}
		if strings.Contains(output, "CVE-2021-42374") {
			t.Error("MEDIUM severity CVE should be filtered out")
		}
		if !strings.Contains(output, "CRITICAL") {
			t.Error("expected CRITICAL severity label in output")
		}
		if !strings.Contains(output, "HIGH") {
			t.Error("expected HIGH severity label in output")
		}
	})

	t.Run("report with no vulnerabilities", func(t *testing.T) {
		report := types.Report{
			ArtifactName: "scratch:latest",
			Results:      types.Results{},
		}
		output := captureStdout(func() { printScanReport(report) })
		if strings.Contains(output, "CVE-") {
			t.Error("expected no CVE references in empty report")
		}
	})

	t.Run("result with empty vulnerability list", func(t *testing.T) {
		report := types.Report{
			ArtifactName: "alpine:latest",
			Results: types.Results{
				{
					Target:          "alpine:latest",
					Vulnerabilities: nil,
				},
			},
		}
		output := captureStdout(func() { printScanReport(report) })
		if strings.Contains(output, "Target:") {
			t.Error("expected no target output for result with no vulns")
		}
	})

	t.Run("multiple results", func(t *testing.T) {
		report := types.Report{
			ArtifactName: "ubuntu:22.04",
			Results: types.Results{
				{
					Target: "ubuntu:22.04",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2023-0001",
							Vulnerability:    dbTypes.Vulnerability{Severity: "HIGH"},
							PkgName:          "openssl",
							InstalledVersion: "3.0.2",
							FixedVersion:     "3.0.3",
						},
					},
				},
				{
					Target:          "node_modules",
					Vulnerabilities: nil,
				},
			},
		}
		output := captureStdout(func() { printScanReport(report) })
		if !strings.Contains(output, "CVE-2023-0001") {
			t.Error("expected CVE-2023-0001 in output")
		}
		if !strings.Contains(output, "HIGH") {
			t.Error("expected HIGH severity in output")
		}
	})
}

func TestDedupImages(t *testing.T) {
	t.Run("no duplicates", func(t *testing.T) {
		images := []ImageInfo{
			{ID: "abc", Name: "alpine:3.19"},
			{ID: "def", Name: "nginx:1.25"},
		}
		result := dedupImages(images)
		if len(result) != 2 {
			t.Fatalf("expected 2 unique images, got %d", len(result))
		}
	})

	t.Run("duplicate IDs merged", func(t *testing.T) {
		images := []ImageInfo{
			{ID: "abc", Name: "alpine:latest"},
			{ID: "abc", Name: "alpine:3.19"},
			{ID: "abc", Name: "my-alpine:prod"},
		}
		result := dedupImages(images)
		if len(result) != 1 {
			t.Fatalf("expected 1 unique image, got %d", len(result))
		}
		if len(result[0].Names) != 3 {
			t.Fatalf("expected 3 names, got %d: %v", len(result[0].Names), result[0].Names)
		}
		if result[0].Name != "alpine:latest" {
			t.Errorf("expected first name 'alpine:latest', got '%s'", result[0].Name)
		}
	})

	t.Run("mixed duplicated and unique", func(t *testing.T) {
		images := []ImageInfo{
			{ID: "aaa", Name: "img-a:v1"},
			{ID: "bbb", Name: "img-b:v1"},
			{ID: "aaa", Name: "img-a:v2"},
			{ID: "ccc", Name: "img-c:v1"},
		}
		result := dedupImages(images)
		if len(result) != 3 {
			t.Fatalf("expected 3 unique images, got %d", len(result))
		}
	})

	t.Run("empty list", func(t *testing.T) {
		result := dedupImages(nil)
		if len(result) != 0 {
			t.Fatalf("expected 0 images, got %d", len(result))
		}
	})

	t.Run("single image", func(t *testing.T) {
		images := []ImageInfo{
			{ID: "xyz", Name: "busybox:1.36"},
		}
		result := dedupImages(images)
		if len(result) != 1 {
			t.Fatalf("expected 1 image, got %d", len(result))
		}
		if len(result[0].Names) != 1 {
			t.Fatalf("expected 1 name, got %d", len(result[0].Names))
		}
	})
}

func TestImageArgFilter(t *testing.T) {
	images := []ImageInfo{
		{ID: "sha256:abc123", Name: "alpine:latest"},
		{ID: "sha256:def456", Name: "nginx:1.25"},
		{ID: "sha256:ghi789", Name: "busybox:1.36"},
		{ID: "sha256:abc123", Name: "alpine:3.19"},
	}

	t.Run("filter by exact name", func(t *testing.T) {
		filtered := filterImagesByArgs(images, []string{"nginx:1.25"})
		if len(filtered) != 1 {
			t.Fatalf("expected 1 match, got %d", len(filtered))
		}
		if filtered[0].Name != "nginx:1.25" {
			t.Errorf("expected 'nginx:1.25', got '%s'", filtered[0].Name)
		}
	})

	t.Run("filter by exact ID", func(t *testing.T) {
		filtered := filterImagesByArgs(images, []string{"sha256:ghi789"})
		if len(filtered) != 1 {
			t.Fatalf("expected 1 match, got %d", len(filtered))
		}
		if filtered[0].Name != "busybox:1.36" {
			t.Errorf("expected 'busybox:1.36', got '%s'", filtered[0].Name)
		}
	})

	t.Run("filter by ID prefix", func(t *testing.T) {
		filtered := filterImagesByArgs(images, []string{"sha256:abc"})
		if len(filtered) != 2 {
			t.Fatalf("expected 2 matches (both abc123), got %d", len(filtered))
		}
	})

	t.Run("no match", func(t *testing.T) {
		filtered := filterImagesByArgs(images, []string{"doesnotexist:latest"})
		if len(filtered) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(filtered))
		}
	})

	t.Run("multiple args", func(t *testing.T) {
		filtered := filterImagesByArgs(images, []string{"alpine:latest", "busybox:1.36"})
		if len(filtered) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(filtered))
		}
	})
}
