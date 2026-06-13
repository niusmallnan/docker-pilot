package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"docker-pilot/internal/config"
	"docker-pilot/internal/install"
	"docker-pilot/internal/system"
	"docker-pilot/internal/tui"
	"docker-pilot/internal/ui"

	"docker-pilot/internal/trivylite"
	"github.com/aquasecurity/trivy/pkg/types"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var version = "Dev"

func main() {
	Execute()
}

var rootCmd = &cobra.Command{
	Use:   "docker-pilot",
	Short: "Docker Pilot - setup & manage Docker on SLES 15+",
	Long:  `Docker Pilot - Interactive Docker installation and TUI management tool for SUSE Linux Enterprise Server.`,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure Docker (registry, proxy, network)",
	Long:  `Interactive configuration for Docker: registry, proxy, and container network CIDR. This is the default command.`,
	Run:   runConfig,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Docker images for CVE vulnerabilities",
	Long:  `Scan all Docker images on the host for known CVE vulnerabilities.`,
	Run:   runScan,
}

var scanForceDBRefresh bool

var aiInspectCmd = &cobra.Command{
	Use:   "ai-inspect",
	Short: "AI-powered container health inspection",
	Long:  `Use AI to analyze and inspect the health status of all running containers on the host.`,
	Run:   runAiInspect,
}

func init() {
	scanCmd.Flags().BoolVar(&scanForceDBRefresh, "ref-db", false, "force refresh vulnerability database from public.ecr.aws/aquasecurity/trivy-db:2")
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(aiInspectCmd)
}

func Execute() {
	// If no subcommand is provided, default to "config"
	if len(os.Args) == 1 {
		os.Args = append(os.Args, "config")
	}

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runConfig(cmd *cobra.Command, args []string) {
	// Create and run our new Bubble Tea UI
	inContainer := system.IsRunningInContainer()
	dockerExists := install.IsDockerInstalled()

	p := tea.NewProgram(tui.NewConfigModel(version, inContainer, dockerExists))
	m, err := p.Run()
	if err != nil {
		ui.PrintError("TUI failed: %v", err)
		os.Exit(1)
	}

	// Get the result
	configModel, ok := m.(tui.ConfigModel)
	if !ok || !configModel.Finished() {
		// User cancelled
		fmt.Println("\nConfiguration cancelled.")
		return
	}

	// Now run the actual config steps based on user choices
	ui.PrintBanner(version)

	isAdvancedMode := configModel.IsAdvancedMode()
	totalSteps := 2
	if isAdvancedMode {
		totalSteps = 5
	}

	// Step 1: System Check
	ui.PrintStep(1, totalSteps, "System Check")
	if err := system.CheckRequirements(); err != nil {
		ui.PrintError("System check failed: %v", err)
		os.Exit(1)
	}
	ui.PrintSuccess("System check passed")

	// Step 2: Install Docker Engine
	ui.PrintStep(2, totalSteps, "Install Docker Engine")
	skipDockerInstall := false
	if inContainer {
		ui.PrintWarning("Detected container environment - skipping Docker installation")
		skipDockerInstall = true
	} else if dockerExists {
		ui.PrintWarning("Docker is already installed - skipping installation")
		skipDockerInstall = true
	}

	if !skipDockerInstall {
		if err := install.InstallDocker(); err != nil {
			ui.PrintError("Docker installation failed: %v", err)
			os.Exit(1)
		}
		ui.PrintSuccess("Docker Engine installed")
	}

	if isAdvancedMode {
		// Step 3: Configure Registry
		ui.PrintStep(3, totalSteps, "Configure Registry")
		registryVal := configModel.GetChoice(0)
		if registryVal != "" && registryVal != "registry-1.docker.io" {
			registryConfig := config.RegistryConfig{
				Configured: true,
				Registry:   registryVal,
			}
			if err := config.WriteRegistryConfig(registryConfig); err != nil {
				ui.PrintError("Failed to write Registry configuration: %v", err)
				os.Exit(1)
			}
			ui.PrintSuccess("Registry configuration written")
		} else {
			ui.PrintWarning("Skipping Registry configuration")
		}

		// Step 4: Configure HTTP Proxy
		ui.PrintStep(4, totalSteps, "Configure HTTP Proxy")
		httpProxy := configModel.GetChoice(1)
		httpsProxy := configModel.GetChoice(2)
		if httpProxy != "" || httpsProxy != "" {
			// Default NO_PROXY
			noProxy := config.DefaultNoProxy
			if existingNoProxy := os.Getenv("NO_PROXY"); existingNoProxy != "" {
				noProxy = existingNoProxy
			}
			proxyConfig := config.ProxyConfig{
				Configured: true,
				HTTPProxy:  httpProxy,
				HTTPSProxy: httpsProxy,
				NoProxy:    noProxy,
			}
			if err := config.WriteProxyConfig(proxyConfig); err != nil {
				ui.PrintError("Failed to write Proxy configuration: %v", err)
				os.Exit(1)
			}
			ui.PrintSuccess("Proxy configuration written")
		} else {
			ui.PrintWarning("Skipping Proxy configuration")
		}

		// Step 5: Configure Container CIDR
		ui.PrintStep(5, totalSteps, "Configure Container Network CIDR")
		cidrVal := configModel.GetChoice(3)
		if cidrVal != "" && cidrVal != "172.31.0.0/16" {
			// Convert network address to BIP format (e.g., 172.31.0.0/16 -> 172.31.0.1/16)
			bip := strings.Replace(cidrVal, ".0/", ".1/", 1)
			cidrConfig := config.CIDRConfig{
				Configured: true,
				BIP:        bip,
			}
			if err := config.WriteCIDRConfig(cidrConfig); err != nil {
				ui.PrintError("Failed to write CIDR configuration: %v", err)
				os.Exit(1)
			}
			ui.PrintSuccess("Container network CIDR configuration written")
		} else {
			ui.PrintWarning("Skipping CIDR configuration")
		}
	}

	// Finalize
	if !inContainer {
		if err := system.RestartDocker(); err != nil {
			ui.PrintError("Failed to restart Docker service: %v", err)
			os.Exit(1)
		}

		if err := system.AddUserToDockerGroup(); err != nil {
			ui.PrintWarning("Failed to add user to docker group: %v", err)
		}
	} else {
		ui.PrintInfo("Running in container - skipping Docker service restart and group management")
	}

	ui.PrintCompletion()
}

func runScan(cmd *cobra.Command, args []string) {
	ui.PrintBanner(version)

	if _, err := exec.LookPath("docker"); err != nil {
		ui.PrintError("Docker not found on system - cannot scan")
		os.Exit(1)
	}

	ui.PrintInfo("Starting CVE vulnerability scan...")
	ui.PrintInfo("This may take a few minutes on first run (Trivy needs to download vulnerability database)")
	ui.PrintInfo("")

	if err := runTrivyScan(); err != nil {
		ui.PrintError("Scan failed: %v", err)
		os.Exit(1)
	}
}

// ImageInfo holds Docker image information
type ImageInfo struct {
	ID   string
	Name string
}

func getDockerImages() ([]ImageInfo, error) {
	cmd := exec.Command("docker", "images", "--format", "{{.ID}}|{{.Repository}}:{{.Tag}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var images []ImageInfo
	for _, line := range lines {
		if line != "" {
			parts := strings.SplitN(line, "|", 2)
			if len(parts) == 2 {
				images = append(images, ImageInfo{
					ID:   parts[0],
					Name: parts[1],
				})
			} else {
				images = append(images, ImageInfo{
					ID:   line,
					Name: line,
				})
			}
		}
	}
	return images, nil
}

func runTrivyScan() error {
	images, err := getDockerImages()
	if err != nil || len(images) == 0 {
		ui.PrintWarning("No images to scan or failed to list images")
		return nil
	}

	ui.PrintStep(1, 1, "Scanning Docker images")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	quiet := os.Getenv("DOCKER_PILOT_VERBOSE_TRIVY") != "1"

	scanner, err := trivylite.New(scanForceDBRefresh)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}
	defer scanner.Close()

	for _, image := range images {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════════")
		fmt.Printf("  SCANNING IMAGE: %s\n", image.Name)
		fmt.Printf("  IMAGE ID:     %s\n", image.ID)
		fmt.Println("═══════════════════════════════════════════════════════════════════")
		fmt.Println()

		report, scanErr := scanner.ScanImage(ctx, image.Name, quiet)
		if scanErr != nil {
			ui.PrintWarning("Image scan for %s completed with warnings: %v", image.Name, scanErr)
			continue
		}

		if os.Getenv("DOCKER_PILOT_DEBUG_SCAN") == "1" {
			dumpReport(report)
		}

		printScanReport(report)
	}

	ui.PrintSuccess("\nScan complete!")
	return nil
}

func dumpReport(report types.Report) {
	fmt.Println("=== DEBUG: scan report dump ===")
	fmt.Printf("ArtifactName: %s\n", report.ArtifactName)
	fmt.Printf("Results count: %d\n", len(report.Results))
	for i, r := range report.Results {
		fmt.Printf("  Result[%d]: Target=%q, Class=%q, Type=%q\n", i, r.Target, r.Class, r.Type)
		fmt.Printf("    Vulns count: %d\n", len(r.Vulnerabilities))
		fmt.Printf("    Packages count: %d\n", len(r.Packages))
		for j, v := range r.Vulnerabilities {
			fmt.Printf("    Vuln[%d]: ID=%s Pkg=%s Installed=%s Fixed=%s Severity=%q Status=%d\n",
				j, v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion, v.Severity, v.Status)
		}
	}
	fmt.Println("=== END debug dump ===")
}

func printScanReport(report types.Report) {
	total := 0
	critical := 0
	high := 0

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			total++
			switch v.Severity {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			}
		}
	}

	if total == 0 {
		ui.PrintSuccess("No vulnerabilities found")
		return
	}

	fmt.Printf("Total: %d vulnerabilities", total)
	if critical > 0 || high > 0 {
		fmt.Printf(" (CRITICAL: %d, HIGH: %d)", critical, high)
	}
	fmt.Println()

	for _, result := range report.Results {
		var vulns []types.DetectedVulnerability
		for _, v := range result.Vulnerabilities {
			if v.Severity == "CRITICAL" || v.Severity == "HIGH" {
				vulns = append(vulns, v)
			}
		}
		if len(vulns) == 0 {
			continue
		}
		fmt.Printf("  Target: %s\n", result.Target)
		for _, v := range vulns {
			fmt.Printf("    [%s] %s  %s  (installed: %s, fixed: %s)\n",
				v.Severity, v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion)
		}
	}
	fmt.Println()
}

// ContainerInfo represents Docker container inspection data
type ContainerInfo struct {
	ID    string `json:"Id"`
	Name  string
	State struct {
		Status       string
		Running      bool
		RestartCount int    `json:"RestartCount"`
		StartedAt    string `json:"StartedAt"`
	}
	Config struct {
		Image string
	}
	HostConfig struct {
		RestartPolicy struct {
			Name string
		}
	}
}

func runAiInspect(cmd *cobra.Command, args []string) {
	ui.PrintBanner(version)

	// Check if docker is available
	if _, err := exec.LookPath("docker"); err != nil {
		ui.PrintError("Docker not found on system - cannot inspect")
		os.Exit(1)
	}

	ui.PrintInfo("Starting AI-powered container health inspection...")
	ui.PrintInfo("")

	// Get all containers
	containers, err := getContainers()
	if err != nil {
		ui.PrintError("Failed to list containers: %v", err)
		os.Exit(1)
	}

	if len(containers) == 0 {
		ui.PrintInfo("No containers found on this host")
		return
	}

	// Analyze each container
	healthReport := analyzeContainers(containers)

	// Print report
	printHealthReport(healthReport)
}

func getContainers() ([]ContainerInfo, error) {
	// Get all container IDs
	cmd := exec.Command("docker", "ps", "-a", "-q")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	containerIDs := strings.Fields(string(output))
	var containers []ContainerInfo

	for _, id := range containerIDs {
		cmd := exec.Command("docker", "inspect", id)
		output, err := cmd.Output()
		if err != nil {
			continue // skip containers we can't inspect
		}

		var inspectResult []ContainerInfo
		if err := json.Unmarshal(output, &inspectResult); err != nil {
			continue
		}

		if len(inspectResult) > 0 {
			containers = append(containers, inspectResult[0])
		}
	}

	return containers, nil
}

// ContainerHealth holds health analysis for a single container
type ContainerHealth struct {
	Container   ContainerInfo
	Status      string // "healthy", "warning", "critical"
	Issues      []string
	Suggestions []string
}

func analyzeContainers(containers []ContainerInfo) []ContainerHealth {
	var reports []ContainerHealth

	for _, c := range containers {
		report := ContainerHealth{
			Container: c,
			Status:    "healthy",
		}

		// Trim leading slash from container name
		cName := strings.TrimPrefix(c.Name, "/")
		report.Container.Name = cName

		// Check 1: Is container running?
		if !c.State.Running {
			report.Status = "warning"
			report.Issues = append(report.Issues, "Container is not running")

			// Check restart policy
			if c.HostConfig.RestartPolicy.Name == "always" || c.HostConfig.RestartPolicy.Name == "unless-stopped" {
				report.Status = "critical"
				report.Issues = append(report.Issues, "Restart policy is set but container is not running - potential crash loop")
				report.Suggestions = append(report.Suggestions, fmt.Sprintf("Check logs: `docker logs %s`", cName))
				report.Suggestions = append(report.Suggestions, fmt.Sprintf("Try starting manually: `docker start %s`", cName))
			}
		}

		// Check 2: Restart count
		if c.State.RestartCount > 5 {
			if report.Status != "critical" {
				report.Status = "warning"
			}
			report.Issues = append(report.Issues, fmt.Sprintf("High restart count: %d", c.State.RestartCount))
			report.Suggestions = append(report.Suggestions, "Review container stability - investigate crash reasons")
		} else if c.State.RestartCount > 0 {
			report.Issues = append(report.Issues, fmt.Sprintf("Restart count: %d", c.State.RestartCount))
		}

		// Check 3: Image used (latest tag is not ideal for production)
		if strings.HasSuffix(c.Config.Image, ":latest") {
			report.Issues = append(report.Issues, "Using 'latest' tag - not recommended for production")
			report.Suggestions = append(report.Suggestions, "Use specific version tags for better reproducibility")
		}

		// If no issues found
		if len(report.Issues) == 0 && report.Status == "healthy" {
			report.Suggestions = append(report.Suggestions, "Container is running smoothly - keep monitoring!")
		}

		reports = append(reports, report)
	}

	return reports
}

func printHealthReport(reports []ContainerHealth) {
	// Summary counts
	healthyCount := 0
	warningCount := 0
	criticalCount := 0

	for _, r := range reports {
		switch r.Status {
		case "healthy":
			healthyCount++
		case "warning":
			warningCount++
		case "critical":
			criticalCount++
		}
	}

	ui.PrintInfo("Inspection complete - %d containers analyzed", len(reports))
	ui.PrintInfo("")

	if criticalCount > 0 {
		ui.PrintError("Critical: %d containers need immediate attention", criticalCount)
	}
	if warningCount > 0 {
		ui.PrintWarning("Warning: %d containers have potential issues", warningCount)
	}
	if healthyCount > 0 {
		ui.PrintSuccess("Healthy: %d containers are running well", healthyCount)
	}

	ui.PrintInfo("")
	ui.PrintInfo("=")

	// Detailed reports
	for i, r := range reports {
		fmt.Println("")
		fmt.Printf("Container %d/%d: %s\n", i+1, len(reports), r.Container.Name)
		fmt.Printf("  Image: %s\n", r.Container.Config.Image)
		fmt.Printf("  Status: %s", r.Container.State.Status)

		switch r.Status {
		case "healthy":
			ui.PrintSuccess("HEALTHY")
		case "warning":
			ui.PrintWarning("WARNING")
		case "critical":
			ui.PrintError("CRITICAL")
		}

		if len(r.Issues) > 0 {
			fmt.Println("  Issues:")
			for _, issue := range r.Issues {
				fmt.Printf("   - %s\n", issue)
			}
		}

		if len(r.Suggestions) > 0 {
			fmt.Println("  Suggestions:")
			for _, suggestion := range r.Suggestions {
				fmt.Printf("   - %s\n", suggestion)
			}
		}

		fmt.Println("")
	}
}
