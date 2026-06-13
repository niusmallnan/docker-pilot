package trivylite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	dbCfg "github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	trivyDB "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	artimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"github.com/google/go-containerregistry/pkg/name"
)

const defaultDBRepository = "public.ecr.aws/aquasecurity/trivy-db:2"

// Scanner holds initialized trivy state for scanning multiple images.
type Scanner struct {
	cache   cache.Cache
	closeFn func()
	svc     Service
}

// New creates a Scanner. It skips DB download if a local DB already exists,
// unless forceRefresh is true.
func New(forceRefresh bool) (*Scanner, error) {
	cd := cacheDir()
	dbDir := trivyDB.Dir(cd)

	verb := os.Getenv("DOCKER_PILOT_VERBOSE_TRIVY") == "1"
	log.InitLogger(verb, !verb)

	ctx := context.Background()
	skipUpdate := !forceRefresh

	dbRef, err := name.ParseReference(defaultDBRepository)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DB repository: %w", err)
	}

	if err := operation.DownloadDB(ctx, "docker-pilot", cd, []name.Reference{dbRef},
		false, skipUpdate, ftypes.RegistryOptions{}); err != nil {
		return nil, fmt.Errorf("failed to download vulnerability database: %w", err)
	}

	if err := trivyDB.Init(dbDir); err != nil {
		return nil, fmt.Errorf("failed to init vulnerability database: %w", err)
	}

	c, closeFn, err := cache.New(cache.Options{CacheDir: cd})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cache: %w", err)
	}

	app := applier.NewApplier(c)
	osScanner := ospkg.NewScanner()
	langScanner := langpkg.NewScanner()
	vulnClient := vulnerability.NewClient(dbCfg.Config{})

	return &Scanner{
		cache:   c,
		closeFn: closeFn,
		svc:     NewService(app, osScanner, langScanner, vulnClient),
	}, nil
}

// ScanImage scans a single container image for vulnerabilities.
func (s *Scanner) ScanImage(ctx context.Context, imageRef string, quiet bool) (types.Report, error) {
	img, cleanup, err := image.NewContainerImage(ctx, imageRef, ftypes.ImageOptions{
		ImageSources: ftypes.ImageSources{ftypes.DockerImageSource},
	})
	if err != nil {
		return types.Report{}, fmt.Errorf("failed to open image %s: %w", imageRef, err)
	}
	defer cleanup()

	art, err := artimage.NewArtifact(img, s.cache, artifact.Option{
		NoProgress: quiet,
		ImageOption: ftypes.ImageOptions{
			ImageSources: ftypes.ImageSources{ftypes.DockerImageSource},
		},
	})
	if err != nil {
		return types.Report{}, fmt.Errorf("failed to create artifact: %w", err)
	}

	scanSvc := scan.NewService(s.svc, art)
	return scanSvc.ScanArtifact(ctx, types.ScanOptions{
		Scanners:            types.Scanners{types.VulnerabilityScanner},
		PkgTypes:            []string{"os", "library"},
		PkgRelationships:    ftypes.Relationships,
		VulnSeveritySources: []dbTypes.SourceID{"auto"},
	})
}

// Close releases resources held by the Scanner.
func (s *Scanner) Close() {
	s.closeFn()
}

func cacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(dir, "trivy")
}
