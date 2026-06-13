package trivylite

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	ospkgDetector "github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

// Service implements vulnerability detection for OS and language packages.
type Service struct {
	applier        applier.Applier
	osPkgScanner   ospkg.Scanner
	langPkgScanner langpkg.Scanner
	vulnClient     vulnerability.Client
}

func NewService(a applier.Applier, osPkgScanner ospkg.Scanner, langPkgScanner langpkg.Scanner,
	vulnClient vulnerability.Client) Service {
	return Service{
		applier:        a,
		osPkgScanner:   osPkgScanner,
		langPkgScanner: langPkgScanner,
		vulnClient:     vulnClient,
	}
}

func (s Service) Scan(ctx context.Context, targetName, artifactKey string, blobKeys []string, options types.ScanOptions) (
	types.ScanResponse, error) {
	detail, err := s.applier.ApplyLayers(ctx, artifactKey, blobKeys)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Debug("OS is not detected.")

		if len(detail.Packages) != 0 {
			detail.OS = ftypes.OS{Family: "none"}
		}

		if detail.Repository != nil {
			log.Debug("Package repository", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			log.Debug("Assuming OS", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			detail.OS = ftypes.OS{
				Family: detail.Repository.Family,
				Name:   detail.Repository.Release,
			}
		}
	case !detail.OS.Family.HasOSPackages():
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return types.ScanResponse{}, xerrors.Errorf("failed to apply layers: %w", err)
	}

	if !lo.IsEmpty(options.Distro) && !lo.IsEmpty(detail.OS) {
		log.Info("Overriding detected OS with provided distro", log.String("detected", detail.OS.String()),
			log.String("provided", options.Distro.String()))
		detail.OS = options.Distro

		for i := range detail.Packages {
			if detail.Packages[i].Name == "" {
				continue
			}
			p, err := purl.New(detail.OS.Family, types.Metadata{OS: &detail.OS}, detail.Packages[i])
			if err != nil {
				log.Error("Failed to create PackageURL", log.Err(err))
				continue
			}
			if p == nil {
				continue
			}
			detail.Packages[i].Identifier.PURL = p.Unwrap()
		}
	}

	target := types.ScanTarget{
		Name:         targetName,
		OS:           detail.OS,
		Repository:   lo.Ternary(lo.IsEmpty(options.Distro), detail.Repository, nil),
		Packages:     mergePkgs(detail.Packages, detail.ImageConfig.Packages, options),
		Applications: detail.Applications,
	}

	results, os, err := s.ScanTarget(ctx, target, options)
	if err != nil {
		return types.ScanResponse{}, err
	}
	return types.ScanResponse{
		Results: results,
		OS:      os,
		Layers:  detail.Layers,
	}, nil
}

func (s Service) ScanTarget(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Results, ftypes.OS, error) {
	if err := extension.PreScan(ctx, &target, options); err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("pre scan error: %w", err)
	}

	var results types.Results

	excludePackages(&target, options)

	vulnResults, eosl, err := s.scanVulnerabilities(ctx, target, options)
	if err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}
	target.OS.Eosl = eosl
	results = append(results, vulnResults...)

	for i := range results {
		s.vulnClient.FillInfo(results[i].Vulnerabilities, options.VulnSeveritySources)
	}

	if results, err = extension.PostScan(ctx, results); err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("post scan error: %w", err)
	}

	return results, target.OS, nil
}

func (s Service) scanVulnerabilities(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (
	types.Results, bool, error) {
	if !options.Scanners.AnyEnabled(types.SBOMScanner, types.VulnerabilityScanner) {
		return nil, false, nil
	}

	var eosl bool
	var results types.Results

	if slices.Contains(options.PkgTypes, types.PkgTypeOS) {
		vuln, detectedEOSL, err := s.osPkgScanner.Scan(ctx, target, options)
		switch {
		case errors.Is(err, ospkgDetector.ErrUnsupportedOS):
		case err != nil:
			return nil, false, xerrors.Errorf("unable to scan OS packages: %w", err)
		case vuln.Target != "":
			results = append(results, vuln)
			eosl = detectedEOSL
		}
	}

	if slices.Contains(options.PkgTypes, types.PkgTypeLibrary) {
		vulns, err := s.langPkgScanner.Scan(ctx, target, options)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, vulns...)
	}

	return results, eosl, nil
}

func excludePackages(target *types.ScanTarget, options types.ScanOptions) {
	filterPkgByRelationship(target, options)
	excludeDevDeps(target.Applications, options.IncludeDevDeps)
}

func filterPkgByRelationship(target *types.ScanTarget, options types.ScanOptions) {
	if slices.Compare(options.PkgRelationships, ftypes.Relationships) == 0 {
		return
	}

	filter := func(pkgs []ftypes.Package) []ftypes.Package {
		return lo.Filter(pkgs, func(pkg ftypes.Package, _ int) bool {
			return slices.Contains(options.PkgRelationships, pkg.Relationship)
		})
	}

	target.Packages = filter(target.Packages)
	for i, app := range target.Applications {
		target.Applications[i].Packages = filter(app.Packages)
	}
}

func excludeDevDeps(apps []ftypes.Application, include bool) {
	if include {
		return
	}

	onceInfo := sync.OnceFunc(func() {
		log.Info("Suppressing dependencies for development and testing. To display them, try the '--include-dev-deps' flag.")
	})

	for i := range apps {
		devDeps := set.New[string]()
		apps[i].Packages = lo.Filter(apps[i].Packages, func(pkg ftypes.Package, _ int) bool {
			if pkg.Dev {
				onceInfo()
				devDeps.Append(pkg.ID)
			}
			return !pkg.Dev
		})

		for j, pkg := range apps[i].Packages {
			if pkg.Relationship != ftypes.RelationshipRoot && pkg.Relationship != ftypes.RelationshipWorkspace {
				continue
			}
			apps[i].Packages[j].DependsOn = lo.Filter(apps[i].Packages[j].DependsOn, func(dep string, _ int) bool {
				return !devDeps.Contains(dep)
			})
		}
	}
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package, options types.ScanOptions) []ftypes.Package {
	if !options.ScanRemovedPackages || len(pkgsFromCommands) == 0 {
		return pkgs
	}

	uniqPkgs := set.New[string]()
	for _, pkg := range pkgs {
		uniqPkgs.Append(pkg.Name)
	}
	for _, pkg := range pkgsFromCommands {
		if uniqPkgs.Contains(pkg.Name) {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}
