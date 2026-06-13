package trivylite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	trivyDB "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	artimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

func cacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(dir, "trivy")
}

func ScanImage(ctx context.Context, imageRef string, quiet bool) (types.Report, error) {
	cacheOpts := cache.Options{
		CacheDir: cacheDir(),
	}
	c, cleanupCache, err := cache.New(cacheOpts)
	if err != nil {
		return types.Report{}, fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cleanupCache()

	if err := trivyDB.Init(cacheDir()); err != nil {
		return types.Report{}, fmt.Errorf("failed to init vulnerability database: %w", err)
	}

	app := applier.NewApplier(c)
	osScanner := ospkg.NewScanner()
	langScanner := langpkg.NewScanner()
	vulnClient := vulnerability.NewClient(dbTypes.Config{})
	localSvc := NewService(app, osScanner, langScanner, vulnClient)

	img, cleanupImg, err := image.NewContainerImage(ctx, imageRef, ftypes.ImageOptions{})
	if err != nil {
		return types.Report{}, fmt.Errorf("failed to open image %s: %w", imageRef, err)
	}
	defer cleanupImg()

	artOpt := artifact.Option{
		NoProgress:  quiet,
		ImageOption: ftypes.ImageOptions{},
	}
	art, err := artimage.NewArtifact(img, c, artOpt)
	if err != nil {
		return types.Report{}, fmt.Errorf("failed to create artifact: %w", err)
	}

	svc := scan.NewService(localSvc, art)
	return svc.ScanArtifact(ctx, types.ScanOptions{
		Scanners: types.Scanners{types.VulnerabilityScanner},
		PkgTypes: []string{"os", "library"},
	})
}
