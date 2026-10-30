# bomly-plugin-syft-detector

Syft-backed dependency detector for
[Bomly](https://github.com/bomly-dev/bomly-cli).

It resolves dependency graphs by cataloguing filesystems, git repositories,
and container images with [Syft](https://github.com/anchore/syft), covering
40+ package-manager evidence formats — from language lockfiles (npm, Maven,
Go, Python, Cargo, ...) to OS package databases (apk, dpkg, rpm, alpm,
portage, Homebrew, ...).

> **Already inside the Bomly CLI.** This detector ships embedded in the
> `bomly` binary as the built-in `syft-detector` — you do not need to install
> this plugin to use Syft-backed detection. This repository is the detector's
> home as a standalone module: the Bomly CLI consumes the same code
> in-process, and the plugin binary serves it to hosts that run detectors as
> managed subprocesses.

## Identity

- Plugin id / descriptor name: `syft-detector`
- Kind: detector
- Target kinds: `container-image`, `filesystem`, `git-repository`
- Module path: `github.com/bomly-dev/bomly-plugin-syft-detector`

## Build variants

Two build-tag variants exist, mirroring the Bomly CLI's full and lite builds:

- **builtin** (default, no tags): vendors the Syft Go library and catalogues
  in-process. The `github.com/glebarez/sqlite` driver is registered for
  Syft's RPM cataloger.
- **external** (`-tags bomly_external_syft`): shells out to a `syft` CLI
  binary found on `PATH` (`syft <target> -o spdx-json`) and converts the SPDX
  output back into a Bomly dependency graph.

CI tests both variants. Release archives ship the builtin variant.

## Host-injected support axes

The Bomly CLI composition constructs the `Detector` type directly and injects
`SupportedManagers` and `SupportedEcosystems` from its own support catalog —
those exported fields are part of the stable constructor surface. Managed
execution uses `Module()`, which sources the same axes from the package's own
support table and declares per-package-manager evidence patterns through
`DetectorModule.Support`.

## Network behavior

Cataloguing reads local files, but three paths can reach the network:

- **Container images.** An image that is not available locally is pulled
  from its registry. The registry is whichever one the image reference names,
  with Docker Hub as the default. A name that resolves to no image can fall
  through to Syft's snap source, which queries `api.snapcraft.io`.
- **Go modules.** For a `go.mod` project, Syft runs `go list` through
  `golang.org/x/tools/go/packages` when a Go toolchain is on `PATH`. The `go`
  command downloads any module missing from the module cache from `GOPROXY`,
  which defaults to `proxy.golang.org`, and checks it against `sum.golang.org`.
- **Enrichment.** In the builtin variant, enrichment stays offline. Go and Java
  license lookups use only the local module cache and the local Maven
  repository (`WithUseNetwork(false)`). The external variant is different: it
  passes `--enrich golang,java,javascript,python` to the syft CLI, which turns
  on remote license lookups against the Go module proxy, Maven Central, the
  npm registry and PyPI.

## Upstream

The builtin variant compiles in Anchore's Syft, which is Apache-2.0.
`TestUpstreamLicenseIsUnchanged` in `plugin/upstream_test.go` fails any
dependency bump that changes Syft's `LICENSE` file, so a relicense gets read
before it ships.

## Access

`bomly-plugin.json` declares what the released (builtin) plugin touches, which
Bomly shows before you enable it. It is a disclosure, not a sandbox. Most of it
comes from the libraries Syft drives: stereoscope for images, and the Docker,
Podman and containerd clients.

| Access | Why |
| --- | --- |
| Reads `project` | The scan target: a directory, a single file, or a local image archive or OCI layout |
| Reads and writes `temp` | Extracted image layers, a daemon image export, unpacked archives, and SQLite scratch space for RPM databases |
| Reads and writes `home` | The Go module cache (`$GOPATH/pkg/mod`, `~/go/pkg/mod` by default) that `go list` fills. Also read: `~/.m2/repository` for Java enrichment, Docker's `~/.docker/config.json`, Podman's `~/.config/containers/containers.conf`, `~/.ssh/known_hosts` for Podman over SSH, and Docker Desktop's socket on macOS |
| Reads and writes `cache` | The Go build cache `go list` uses (`GOCACHE`, under the user cache directory) |
| Reads `any` | Podman's `/etc/containers` and `/usr/share/containers` configuration, `$XDG_RUNTIME_DIR/containers/auth.json`, the files `REGISTRY_AUTH_FILE`, `DOCKER_CONFIG` and `DOCKER_CERT_PATH` point at, `VCPKG_ROOT`, and the Go installation |
| Network `*` | Any container registry an image reference names, Go module downloads from whatever `GOPROXY` names (including `direct` VCS fetches), and the snap download host the Snapcraft API returns |
| Network `*.docker.io` | Docker Hub, the default registry for an unqualified image name |
| Network `api.snapcraft.io` | Syft's remote snap source |
| Network `proxy.golang.org`, `sum.golang.org` | The `go` command's default module proxy and checksum database |
| Environment `DOCKER_*`, `CONTAINER_*`, `CONTAINERD_*`, `REGISTRY_AUTH_FILE` | Docker, Podman and containerd connection and registry-credential settings |
| Environment `XDG_*` | Read at startup by the `adrg/xdg` library. `XDG_RUNTIME_DIR` locates the Podman and containerd sockets and the containers auth file |
| Environment `HOME`, `USERPROFILE`, `HOMEDRIVE`, `HOMEPATH` | Locating the home directory (`os.UserHomeDir` and `go-homedir`) |
| Environment `XDG_CACHE_HOME`, `LocalAppData`, `AppData` | The `go` command locating its build cache (`os.UserCacheDir`) and its `go env` file (`os.UserConfigDir`) |
| Environment `GO*`, `PATH` | `GOPATH`, `GOPROXY`, `GOPRIVATE` and `GONOPROXY` for Syft's Go cataloger, the `go` command's own settings, and finding `go`, `ssh` and Docker credential helpers |
| Environment `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (either case) | The registry client's own HTTP transport, which is not Bomly's host-provided client |
| Environment `TMPDIR`, `SQLITE_TMPDIR`, `VCPKG_ROOT` | Temporary-file locations, and the vcpkg checkout for C/C++ manifests |
| Starts `go` | `go list` for Go module graphs |
| Starts `ssh` | Reaching a Docker daemon when `DOCKER_HOST` is an `ssh://` URL |
| Starts `*` | Docker credential helpers (`docker-credential-<name>`), named by your Docker configuration |

Configuration you set changes these destinations and locations: `GOPROXY`,
`GOPATH`, `DOCKER_HOST`, the registry an image names, and the credential
helper Docker uses. The declaration lists the defaults. The external variant
(`-tags bomly_external_syft`) starts `syft` instead and inherits the syft CLI's
own access. It is not what the release archives ship, and this manifest does
not describe it.

## Configuration

The detector has no plugin-specific configuration keys. Target selection,
cataloger selection, and enrichment are driven per request by the host.

## Development

```sh
make test                               # builtin variant
go test -tags bomly_external_syft ./... # external variant
make build                              # build bin/bomly-plugin-syft-detector
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
