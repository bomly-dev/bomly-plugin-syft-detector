package plugin

import (
	"context"

	"github.com/bomly-dev/bomly-sdk"
)

// Name is the plugin's identity. It MUST equal the "id" field in
// bomly-plugin.json — Bomly refuses to load a plugin whose manifest id and
// runtime descriptor name disagree. It is also the descriptor name the Bomly
// CLI composition keys on when it embeds this detector ("syft-detector").
const Name = "syft-detector"

// supportedManagersFromSupport lists every package manager this detector
// declares evidence patterns for, in declaration order.
func supportedManagersFromSupport() []sdk.PackageManager {
	managers := make([]sdk.PackageManager, 0, len(packageManagerSupport))
	for _, support := range packageManagerSupport {
		managers = append(managers, support.PackageManager)
	}
	return managers
}

// supportedEcosystemsFromSupport derives the unique ecosystems behind the
// supported package managers, in first-seen order.
func supportedEcosystemsFromSupport() []sdk.Ecosystem {
	seen := make(map[sdk.Ecosystem]struct{}, len(packageManagerSupport))
	ecosystems := make([]sdk.Ecosystem, 0, len(packageManagerSupport))
	for _, support := range packageManagerSupport {
		ecosystem := support.PackageManager.Ecosystem()
		if ecosystem == "" {
			continue
		}
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		seen[ecosystem] = struct{}{}
		ecosystems = append(ecosystems, ecosystem)
	}
	return ecosystems
}

// Module packages the detector for both execution modes. The Bomly CLI
// composition embeds the Detector type directly and injects SupportedManagers
// and SupportedEcosystems from its own support catalog; managed execution
// uses this module, which sources the same axes from the package's own
// support table (packageManagerSupport).
func Module() sdk.Module {
	managers := supportedManagersFromSupport()
	ecosystems := supportedEcosystemsFromSupport()
	descriptor := Detector{
		SupportedManagers:   managers,
		SupportedEcosystems: ecosystems,
	}.Descriptor()
	return sdk.Module{
		Kind: sdk.PluginKindDetector,
		Detector: &sdk.DetectorModule{
			Descriptor: descriptor,
			Support:    Detector{}.PackageManagerSupport(),
			TargetKinds: []sdk.ExecutionTargetKind{
				sdk.ExecutionTargetContainerImage,
				sdk.ExecutionTargetFilesystem,
				sdk.ExecutionTargetGitRepository,
			},
			New: func(_ context.Context, host sdk.HostContext) (sdk.Detector, error) {
				return Detector{
					Logger:              host.Logger(),
					SupportedManagers:   managers,
					SupportedEcosystems: ecosystems,
				}, nil
			},
		},
	}
}
