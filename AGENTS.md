# AGENTS.md

## Build

- `make build` runs: `deps` → `ref-embed` (downloads lazydocker into `cmd/embed/`) → cross-compiles to `bin/docker-pilot` (GOEXPERIMENT=jsonv2 CGO_ENABLED=0 GOOS=linux GOARCH=amd64).
- `cmd/embed/` is gitignored. First build after clone downloads lazydocker (~20MB, compressed with upx). Requires `curl` and `upx`.
- `GOEXPERIMENT=jsonv2` is required because trivy depends on Go 1.26+ jsonv2 packages.
- `make test` runs `go test -v ./internal/...` only. Tests in `cmd/main_test.go` are **not** included.
- To force re-download embedded binaries: `FORCE_REDOWNLOAD=true make ref-embed`.
- Version is injected via ldflags: `-X main.version=$(git describe --tags --exact-match || echo "Dev")`.

## Architecture

- Single-binary CLI using spf13/cobra. Default (no subcommand) runs `config`.
- Two UI stacks coexist:
  - `internal/tui` — Bubble Tea + Lipgloss, the primary interactive config wizard used by `runConfig()`.
  - `internal/ui` — legacy survey-based helpers. Some `internal/config` Ask* functions still use survey but are NOT called by the main flow.
- `cmd/main.go` defines `rootCmd`, `configCmd`, `scanCmd`, `aiInspectCmd`. `cmd/tui.go` defines `tuiCmd`. Both files have `init()` functions that register commands on `rootCmd` — be aware when adding commands.
- `config` command flow: Bubble Tea TUI → collect choices in `tui.ConfigModel` → `runConfig()` in `cmd/main.go` reads choices and calls `internal/config` writers + `internal/system` for daemon-reload/restart.
- `scan` command: uses `internal/trivylite` (a minimal fork of trivy's scan pipeline) that registers only OS-level analyzers (apk, dpkg, rpm) and bypasses the full `pkg/commands/artifact` orchestration layer. Filters to CRITICAL,HIGH severity. Set `DOCKER_PILOT_VERBOSE_TRIVY=1` to disable quiet mode.
- **Trivy knowledge**: Use deepwiki (`deepwiki_ask_question` on `aquasecurity/trivy`) to look up Trivy CLI flags, scanning modes, DB paths, or other details before writing scan-related code.
- **Trivy cache**: Trivy downloads vulnerability databases (from `ghcr.io/aquasecurity`) to `~/.cache/trivy` (Linux) or `~/Library/Caches/trivy` (macOS). First scan is slow while the DB downloads. Mount this cache when running in containers to avoid repeated downloads. The DB repo can be overridden via `--db-repository` if air-gapped.
- **`internal/trivylite/`**: A minimal fork of trivy's scan pipeline. `scanner.go` is a copy of `pkg/scan/local/service.go` with `analyzer/all` replaced by `minimal_analyzer.go` (OS-only analyzers). `run.go` replicates the cache→applier→scanner→artifact initialization chain from `artifact/run.go` without misconfig/secret/license/RPC/JavaDB/K8s scanning.

## CI / Formatting

- CI (`.github/workflows/ci.yml`) checks `go fmt ./...` and `go mod tidy` with `git diff --exit-code`. Run both before pushing.
- Go 1.26. `go vet` is not in CI but was previously fixed — keep it clean.
- No linter config in repo. No pre-commit hook file found.

## Testing in container

- `make test-container` builds `Dockerfile` (based on `docker:cli`), mounts `/var/run/docker.sock` and the Trivy cache directory (auto-detects macOS vs Linux path).
- Requires Docker daemon running on the host.

## `internal/config/config.go` defaults

Enterprise customization point — constants at top of file:
```
DefaultRegistry, DefaultHTTPProxy, DefaultHTTPSProxy, DefaultNoProxy, DefaultBIP
```
These are SLES 15+ specific. Most other SLES-specific checks live in `internal/system/system.go` (os-release, zypper, systemctl).
