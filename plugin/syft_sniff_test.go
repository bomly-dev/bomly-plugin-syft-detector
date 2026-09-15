package plugin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anchore/syft/syft/artifact"
	syftfile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/syftjson"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly-dev/bomly-sdk/sbom"
)

// The SDK's codec recognizes a syft-json document by the schema.url marker
// syft stamps, reproducing what syftjson.NewFormatDecoder().Identify does
// without linking syft. This module links syft anyway, so it is where the
// two are run against a document syft's own encoder wrote: a syft release
// that moved the marker fails here rather than turning a syft document into
// a generic unsupported-format error for every consumer of the SDK.
func TestSyftSniffAgreesWithSyftsOwnIdentify(t *testing.T) {
	fixture := mustSyftJSONFixture(t)

	id, version := syftjson.NewFormatDecoder().Identify(bytes.NewReader(fixture))
	if id != syftjson.ID || version == "" {
		t.Fatalf("syft did not identify its own output: id=%q version=%q", id, version)
	}
	target, err := sbom.DetectJSONTarget(fixture)
	if err != nil || target != sbom.TargetSyftJSON {
		t.Fatalf("sbom.DetectJSONTarget(syft output) = (%q, %v), want the syft target", target, err)
	}

	// And in the negative direction: what syft declines, the sniff declines.
	notSyft := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","schema":{"url":"https://example.com/schema.json"}}`)
	if id, _ := syftjson.NewFormatDecoder().Identify(bytes.NewReader(notSyft)); id == syftjson.ID {
		t.Fatalf("syft identified a non-syft document")
	}
	if target, err := sbom.DetectJSONTarget(notSyft); err != nil || target != sbom.TargetCycloneDX16JSON {
		t.Fatalf("sbom.DetectJSONTarget(non-syft) = (%q, %v), want the cyclonedx target", target, err)
	}
}

// mustSyftJSONFixture is a document written by syft's own encoder, so the
// agreement above is with syft as it is pinned here, not with a transcription.
func mustSyftJSONFixture(t *testing.T) []byte {
	t.Helper()

	app := syftpkg.Package{
		Name:      "demo-app",
		Version:   "1.0.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/demo-app@1.0.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
	}
	app.SetID()

	dependency := syftpkg.Package{
		Name:      "react",
		Version:   "18.2.0",
		Type:      syftpkg.NpmPkg,
		PURL:      "pkg:npm/react@18.2.0",
		Locations: syftfile.NewLocationSet(syftfile.NewLocation("package-lock.json")),
		Licenses:  syftpkg.NewLicenseSet(syftpkg.NewLicense("MIT")),
	}
	dependency.SetID()

	doc := syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages: syftpkg.NewCollection(app, dependency),
		},
		Relationships: []artifact.Relationship{
			{From: dependency, To: app, Type: artifact.DependencyOfRelationship},
		},
	}

	encoder, err := syftjson.NewFormatEncoderWithConfig(syftjson.EncoderConfig{Pretty: true})
	if err != nil {
		t.Fatalf("new syft encoder: %v", err)
	}
	var out bytes.Buffer
	if err := encoder.Encode(&out, doc); err != nil {
		t.Fatalf("encode syft json: %v", err)
	}
	return []byte(strings.TrimSpace(out.String()))
}
