package trivylite

import (
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/debian"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/release"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os/ubuntu"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/rpm"

	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/sysfile"
	_ "github.com/aquasecurity/trivy/pkg/fanal/handler/unpackaged"
)
