package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/bomly-dev/bomly-sdk/system"
	"go.uber.org/zap"

	"github.com/bomly-dev/bomly-sdk/model"
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

// Detector resolves dependency graphs through the Syft Go library (builtin)
// or the syft CLI binary (external).
type Detector struct {
	Logger              *zap.Logger
	WorkingDir          string
	SupportedEcosystems []model.Ecosystem
	SupportedManagers   []model.PackageManager
}

var packageManagerSupport = []sdkplugin.PackageManagerSupport{
	sdkplugin.Support(model.PackageManagerNPM, "package-lock.json", "package.json"),
	sdkplugin.Support(model.PackageManagerPNPM, "pnpm-lock.yaml", "package.json"),
	sdkplugin.Support(model.PackageManagerYarn, "yarn.lock", "package.json"),
	sdkplugin.Support(model.PackageManagerBun, "bun.lockb"),
	sdkplugin.Support(model.PackageManagerGradle, "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.lockfile*"),
	sdkplugin.Support(model.PackageManagerMaven, "pom.xml", "*pom.xml"),
	sdkplugin.Support(model.PackageManagerGoMod, "go.mod"),
	sdkplugin.Support(model.PackageManagerPip, "requirements.txt", "requirements-dev.txt", "requirements.in", "requirements.lock", "*requirements*.txt"),
	sdkplugin.Support(model.PackageManagerPipenv, "Pipfile", "Pipfile.lock"),
	sdkplugin.Support(model.PackageManagerPoetry, "poetry.lock", "pyproject.toml"),
	sdkplugin.Support(model.PackageManagerUV, "uv.lock", "pyproject.toml"),
	sdkplugin.Support(model.PackageManagerALPM, "var/lib/pacman/local/*/desc"),
	sdkplugin.Support(model.PackageManagerAPK, "lib/apk/db/installed"),
	sdkplugin.Support(model.PackageManagerConan, "conan.lock", "conanfile.txt", "conaninfo.txt"),
	sdkplugin.Support(model.PackageManagerConda, "conda-meta/*.json"),
	sdkplugin.Support(model.PackageManagerPub, "pubspec.yml", "pubspec.yaml", "pubspec.lock"),
	sdkplugin.Support(model.PackageManagerDPKG, "lib/dpkg/status", "lib/dpkg/status.d/*", "lib/opkg/info/*.control", "lib/opkg/status"),
	sdkplugin.Support(model.PackageManagerMix, "mix.lock"),
	sdkplugin.Support(model.PackageManagerRebar, "rebar.lock"),
	sdkplugin.Support(model.PackageManagerOTP, "*.app"),
	sdkplugin.Support(model.PackageManagerGitHubActions, ".github/workflows/*.yaml", ".github/workflows/*.yml", ".github/actions/*/action.yml", ".github/actions/*/action.yaml"),
	sdkplugin.Support(model.PackageManagerCabal, "cabal.project.freeze"),
	sdkplugin.Support(model.PackageManagerStack, "stack.yaml", "stack.yaml.lock"),
	sdkplugin.Support(model.PackageManagerHomebrew, "Cellar/*/*/.brew/*.rb", "Library/Taps/*/*/Formula/*.rb"),
	sdkplugin.Support(model.PackageManagerLuaRocks, "*.rockspec"),
	sdkplugin.Support(model.PackageManagerNuGet, "packages.lock.json", "*.deps.json"),
	sdkplugin.Support(model.PackageManagerNix, "nix/var/nix/db/db.sqlite", "nix/store/*.drv"),
	sdkplugin.Support(model.PackageManagerOpam, "*opam"),
	sdkplugin.Support(model.PackageManagerComposer, "composer.lock", "installed.json"),
	sdkplugin.Support(model.PackageManagerPear, "php/.registry/**/*.reg"),
	sdkplugin.Support(model.PackageManagerPDM, "pdm.lock", "pyproject.toml"),
	sdkplugin.Support(model.PackageManagerPortage, "var/db/pkg/*/*/CONTENTS"),
	sdkplugin.Support(model.PackageManagerSWIPLPack, "pack.pl"),
	sdkplugin.Support(model.PackageManagerRPackage, "DESCRIPTION"),
	sdkplugin.Support(model.PackageManagerRPM, "var/lib/rpmmanifest/container-manifest-2", "var/lib/rpm/Packages", "var/lib/rpm/Packages.db", "var/lib/rpm/rpmdb.sqlite", "usr/share/rpm/Packages", "usr/share/rpm/Packages.db", "usr/share/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/Packages.db", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
	sdkplugin.Support(model.PackageManagerBundler, "Gemfile.lock", "Gemfile.next.lock"),
	sdkplugin.Support(model.PackageManagerGemspec, "*.gemspec"),
	sdkplugin.Support(model.PackageManagerCargo, "Cargo.lock"),
	sdkplugin.Support(model.PackageManagerSnap, "snap/snapcraft.yaml", "snap/manifest.yaml", "doc/linux-modules-*/changelog.Debian.gz", "usr/share/snappy/dpkg.yaml"),
	sdkplugin.Support(model.PackageManagerCocoaPods, "Podfile.lock"),
	sdkplugin.Support(model.PackageManagerSwiftPM, "Package.resolved", ".package.resolved"),
	sdkplugin.Support(model.PackageManagerTerraform, ".terraform.lock.hcl"),
	sdkplugin.Support(model.PackageManagerWordPress, "wp-content/plugins/*/*.php"),
	sdkplugin.Support(model.PackageManagerSetupPy, "setup.py"),
}

// PackageManagerSupport returns Syft package-manager discovery metadata.
func (d Detector) PackageManagerSupport() []sdkplugin.PackageManagerSupport {
	values := make([]sdkplugin.PackageManagerSupport, len(packageManagerSupport))
	copy(values, packageManagerSupport)
	for idx := range values {
		values[idx].EvidencePatterns = append([]string(nil), values[idx].EvidencePatterns...)
	}
	return values
}

// Ready reports whether the detector is ready to run.
func (d Detector) Ready(context.Context, sdkplugin.DetectionRequest) error {
	return nil
}

// Applicable reports whether Syft should run for the requested project.
func (d Detector) Applicable(ctx context.Context, req sdkplugin.DetectionRequest) (bool, error) {
	_ = ctx

	if req.ExecutionTarget.Kind == sdkplugin.ExecutionTargetContainerImage {
		return true, nil
	}

	workingDir := syftWorkingDir(d.WorkingDir, req)

	if isSingleFileTarget(workingDir) {
		return true, nil
	}

	for _, candidate := range supportedFilesForManager(req.PackageManager) {
		exists, err := syftPatternExists(workingDir, candidate)
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

// Descriptor describes the Syft-backed detector.
func (d Detector) Descriptor() sdkplugin.DetectorDescriptor {
	supportedEcosystems := d.SupportedEcosystems
	supportedManagers := d.SupportedManagers
	return sdkplugin.DetectorDescriptor{
		Name:                Name,
		Technique:           sdkplugin.MultipleTechnique,
		SupportedEcosystems: supportedEcosystems,
		SupportedManagers:   supportedManagers,
		Tags:                []string{"graph-resolution", "component-targeting", "sbom-import", "detector-enrichment"},
	}
}

func supportedFilesForManager(manager model.PackageManager) []string {
	for _, support := range packageManagerSupport {
		if support.PackageManager == manager {
			return append([]string(nil), support.EvidencePatterns...)
		}
	}
	return nil
}

func syftPatternExists(dir string, pattern string) (bool, error) {
	if !strings.ContainsAny(pattern, "*?[") {
		exists, err := system.FileExists(filepath.Join(dir, filepath.FromSlash(pattern)))
		return err == nil && exists, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
	if err != nil {
		return false, err
	}
	return len(matches) > 0, nil
}

func syftWorkingDir(defaultWorkingDir string, req sdkplugin.DetectionRequest) string {
	if defaultWorkingDir != "" {
		return defaultWorkingDir
	}
	if req.ProjectPath != "" {
		return req.ProjectPath
	}
	return req.ExecutionTarget.Location
}

func isSingleFileTarget(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
