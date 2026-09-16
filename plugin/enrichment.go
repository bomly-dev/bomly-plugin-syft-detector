package plugin

import (
	sdkplugin "github.com/bomly-dev/bomly-sdk/plugin"
)

var syftDetectorEnrichmentValues = []string{"golang", "java", "javascript", "python"}

func syftCommandArgs(target string, req sdkplugin.DetectionRequest) []string {
	args := []string{target, "-o", "spdx-json"}
	args = append(args, syftCatalogerSelectionArgs(req)...)
	if !req.EnrichmentEnabled {
		return args
	}

	for _, value := range syftDetectorEnrichmentValues {
		args = append(args, "--enrich", value)
	}
	return args
}
