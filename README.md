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

Graph resolution itself is local. Network access happens only when the scan
target requires it:

- container-image targets pull the image (registry access) when it is not
  already available locally;
- Syft's optional enrichment stages are configured offline-safe: Go and Java
  license lookups use the local module cache and local Maven repository only
  (`WithUseNetwork(false)`); the external variant passes `--enrich
  golang,java,javascript,python` to the CLI, which honors the same local-first
  behavior for catalogued evidence.

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
