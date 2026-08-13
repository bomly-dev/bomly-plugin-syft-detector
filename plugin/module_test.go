package plugin

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	sdk "github.com/bomly-dev/bomly-sdk"
	"github.com/bomly-dev/bomly-sdk/conformance"
	"go.uber.org/zap"
)

// testHost is a minimal HostContext for unit tests.
type testHost struct {
	config json.RawMessage
}

func (h testHost) Logger() *zap.Logger                 { return zap.NewNop() }
func (h testHost) HTTPClient() *sdk.HTTPClientProvider { return nil }
func (h testHost) Runtime() sdk.RuntimeInfo {
	return sdk.RuntimeInfo{Execution: sdk.ExecutionEmbedded}
}

func (h testHost) DecodeConfig(v any) error {
	payload := h.config
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	return json.Unmarshal(payload, v)
}

// TestModuleConstructsDetector checks the managed constructor produces a
// Detector carrying the package's own support axes — the same fields the
// Bomly CLI composition injects from its support catalog when it embeds the
// Detector type directly.
func TestModuleConstructsDetector(t *testing.T) {
	module := Module()
	if module.Detector == nil {
		t.Fatal("expected a detector module")
	}
	component, err := module.Detector.New(context.Background(), testHost{})
	if err != nil {
		t.Fatalf("construct detector: %v", err)
	}
	detector, ok := component.(Detector)
	if !ok {
		t.Fatalf("unexpected component type %T", component)
	}
	if len(detector.SupportedManagers) != len(packageManagerSupport) {
		t.Fatalf("supported managers = %d, want %d", len(detector.SupportedManagers), len(packageManagerSupport))
	}
	if len(detector.SupportedEcosystems) == 0 {
		t.Fatal("expected supported ecosystems to be derived")
	}
	if got := detector.Descriptor().Name; got != Name {
		t.Fatalf("descriptor name = %q, want %q", got, Name)
	}
}

// TestModuleTargetKinds pins the execution target kinds managed hosts see.
func TestModuleTargetKinds(t *testing.T) {
	want := []sdk.ExecutionTargetKind{
		sdk.ExecutionTargetContainerImage,
		sdk.ExecutionTargetFilesystem,
		sdk.ExecutionTargetGitRepository,
	}
	got := Module().Detector.TargetKinds
	if len(got) != len(want) {
		t.Fatalf("target kinds = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target kinds = %v, want %v", got, want)
		}
	}
}

// TestConformance runs the SDK conformance suite against the module,
// including the bomly-plugin.json identity cross-check.
func TestConformance(t *testing.T) {
	conformance.Test(t, conformance.Config{
		Module:       Module(),
		ManifestPath: filepath.Join("..", "bomly-plugin.json"),
	})
}

// TestProbeBinary builds the real plugin binary and probes it over the
// managed HashiCorp gRPC transport, asserting the served descriptor equals
// the in-process one. The binary is built with the same build tags as the
// running test so both variants stay probeable.
func TestProbeBinary(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not available; skipping managed-transport probe")
	}
	binaryPath := filepath.Join(t.TempDir(), "bomly-plugin-syft-detector")
	args := []string{"build"}
	if !IsBuiltin() {
		args = append(args, "-tags", "bomly_external_syft")
	}
	args = append(args, "-o", binaryPath, "./cmd/bomly-plugin-syft-detector")
	build := exec.Command(goBinary, args...)
	build.Dir = ".."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary: %v\n%s", err, output)
	}
	conformance.ProbeBinary(t, binaryPath, conformance.WithModule(Module()))
}
