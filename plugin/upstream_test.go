package plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// anchoreApacheLicenseSHA256 is the SHA-256 of the LICENSE file Syft ships,
// Anchore's copy of the Apache-2.0 text. A relicense, or any edit to that
// file, changes it.
const anchoreApacheLicenseSHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"

// TestUpstreamLicenseIsUnchanged fails a dependency bump that changes the
// licence of the Syft library this detector compiles in, so the change is
// read before it ships rather than found afterwards (bomly-planning#10).
func TestUpstreamLicenseIsUnchanged(t *testing.T) {
	const path = "github.com/anchore/syft"
	out, err := exec.Command("go", "mod", "download", "-json", path).Output()
	if err != nil {
		t.Fatalf("go mod download %s: %v", path, err)
	}
	var mod struct{ Version, Dir string }
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatalf("go mod download %s: decode: %v", path, err)
	}
	if mod.Dir == "" {
		t.Fatalf("go mod download %s: no module directory in %s", path, out)
	}
	data, err := os.ReadFile(filepath.Join(mod.Dir, "LICENSE"))
	if err != nil {
		t.Fatalf("%s@%s: read LICENSE: %v", path, mod.Version, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != anchoreApacheLicenseSHA256 {
		t.Errorf("%s@%s: LICENSE changed (sha256 %s, want %s). Read %s/LICENSE: if it is still Apache-2.0, update anchoreApacheLicenseSHA256; if not, do not take this bump: open an issue, since the licence is part of what users accept with this plugin",
			path, mod.Version, got, anchoreApacheLicenseSHA256, mod.Dir)
	}
}
