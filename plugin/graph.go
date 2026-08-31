//go:build !bomly_external_syft

package plugin

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	syftcpe "github.com/anchore/syft/syft/cpe"
	syftfile "github.com/anchore/syft/syft/file"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/bomly-dev/bomly-sdk"
)

func graphFromSyftSBOM(s *syftsbom.SBOM) (*sdk.Graph, error) {
	if s == nil {
		return nil, fmt.Errorf("syft sbom is nil")
	}

	packageCount := 0
	if s.Artifacts.Packages != nil {
		packageCount = s.Artifacts.Packages.PackageCount()
	}

	depsGraph := sdk.NewWithCapacity(packageCount)
	// Syft's relationships are keyed by its own artifact IDs, while a node is
	// keyed by its canonical package URL (ADR-0041). The two are no longer
	// the same string, so the mapping is kept explicitly rather than assumed
	// -- without it every edge looks up an ID no node has.
	nodeIDBySyftID := make(map[string]string, packageCount)
	if s.Artifacts.Packages != nil {
		for _, pkg := range s.Artifacts.Packages.Sorted() {
			node := graphFromSyftPackage(pkg)
			if node == nil {
				// No identity could be minted; the package is not something
				// this graph can say anything about.
				continue
			}
			if err := depsGraph.AddNode(node); err != nil {
				return nil, fmt.Errorf("add syft package %q: %w", node.NodeID(), err)
			}
			nodeIDBySyftID[string(pkg.ID())] = node.NodeID()
		}
	}

	for _, rel := range s.Relationships {
		if rel.Type != artifact.DependencyOfRelationship {
			continue
		}

		dependencySyftID, parentSyftID, ok := syftDependencyEdge(rel)
		if !ok {
			continue
		}
		dependencyID, okDep := nodeIDBySyftID[dependencySyftID]
		parentID, okParent := nodeIDBySyftID[parentSyftID]
		if !okDep || !okParent {
			// One end was skipped for want of identity, so the edge has
			// nothing to connect.
			continue
		}

		if err := depsGraph.AddEdge(parentID, dependencyID); err != nil {
			return nil, fmt.Errorf("add syft dependency %q -> %q: %w", parentID, dependencyID, err)
		}
	}

	return depsGraph, nil
}

// GraphContainerFromSBOM converts a Syft SBOM into one or more manifest-scoped graphs.
func GraphContainerFromSBOM(s *syftsbom.SBOM, manager sdk.PackageManager) (*sdk.GraphContainer, error) {
	return graphContainerFromSyftSBOM(s, manager)
}

func graphContainerFromSyftSBOM(s *syftsbom.SBOM, manager sdk.PackageManager) (*sdk.GraphContainer, error) {
	depsGraph, err := graphFromSyftSBOM(s)
	if err != nil {
		return nil, err
	}
	if depsGraph == nil || depsGraph.Size() == 0 {
		return sdk.SingleGraphContainer(nil, sdk.ManifestMetadata{}), nil
	}

	rootPackages := depsGraph.Roots()
	if len(rootPackages) == 0 {
		manifest := manifestMetadataFromPackages(depsGraph.DependencyNodes(), manager)
		return sdk.SingleGraphContainer(depsGraph, manifest), nil
	}

	groupedRoots := make(map[string][]string, len(rootPackages))
	groupedManifest := make(map[string]sdk.ManifestMetadata, len(rootPackages))
	groupOrder := make([]string, 0, len(rootPackages))
	for _, rootNode := range rootPackages {
		// Roots yields the union type; only a dependency node has the
		// coordinates a manifest is derived from.
		rootPkg, ok := rootNode.(*sdk.DependencyNode)
		if !ok {
			continue
		}
		manifest := manifestMetadataFromPackage(rootPkg, manager)
		key := manifestGroupKey(manifest, rootPkg.NodeID())
		if _, ok := groupedRoots[key]; !ok {
			groupOrder = append(groupOrder, key)
			groupedManifest[key] = manifest
		}
		groupedRoots[key] = append(groupedRoots[key], rootPkg.NodeID())
	}

	entries := make([]sdk.GraphEntry, 0, len(groupOrder))
	covered := make(map[string]struct{}, depsGraph.Size())
	for _, key := range groupOrder {
		entryGraph, visited, err := subgraphFromRoots(depsGraph, groupedRoots[key])
		if err != nil {
			return nil, err
		}
		for id := range visited {
			covered[id] = struct{}{}
		}
		manifest := groupedManifest[key]
		if manifest.Path == "" {
			manifest = manifestMetadataFromPackages(entryGraph.DependencyNodes(), manager)
		}
		entries = append(entries, sdk.GraphEntry{
			Graph:    entryGraph,
			Manifest: manifest,
		})
	}

	leftovers := make([]*sdk.DependencyNode, 0)
	for _, pkg := range depsGraph.DependencyNodes() {
		if _, ok := covered[pkg.NodeID()]; ok {
			continue
		}
		leftovers = append(leftovers, pkg)
	}
	if len(leftovers) > 0 {
		leftoverGraph, _, err := subgraphFromRoots(depsGraph, packageIDs(leftovers))
		if err != nil {
			return nil, err
		}
		entries = append(entries, sdk.GraphEntry{
			Graph:    leftoverGraph,
			Manifest: manifestMetadataFromPackages(leftovers, manager),
		})
	}

	return &sdk.GraphContainer{Entries: entries}, nil
}

// graphFromSyftPackage builds a dependency node from a Syft package, or nil
// when the package carries no identity a node can be minted from.
//
// Identity is the constructor's now (ADR-0041): a node's ID is its canonical
// package URL, so Syft's own artifact ID is no longer carried into the graph
// and the StableID fallback is gone with it. A package Syft catalogued
// without usable coordinates is skipped rather than admitted under a
// synthetic ID.
func graphFromSyftPackage(pkg syftpkg.Package) *sdk.DependencyNode {
	licenses := pkg.Licenses.ToSlice()
	locations := pkg.Locations.ToSlice()
	parsedPURL := parsePackageURL(pkg.PURL)
	packageManager := sdk.PackageManager(strings.ToLower(string(pkg.Type)))

	node, err := sdk.NewDependencyNode(sdk.Coordinates{
		Ecosystem:      sdk.Ecosystem(syftEcosystem(pkg, parsedPURL)),
		Name:           pkg.Name,
		Version:        pkg.Version,
		Org:            syftOrg(pkg, parsedPURL),
		PackageManager: packageManager,
		Type:           sdk.ParsePackageType(string(pkg.Type)),
		Language:       sdk.ParseLanguage(pkg.Language.String()),
		PURL:           pkg.PURL,
	})
	if err != nil {
		return nil
	}
	node.FoundBy = pkg.FoundBy
	node.Locations = graphLocations(locations)
	node.CPEs = graphCPEs(pkg.CPEs)
	sdk.SetDetectionLicenses(node, graphLicenses(licenses))

	return node
}

func syftDependencyEdge(rel artifact.Relationship) (dependencyID string, parentID string, ok bool) {
	dependency, ok := rel.From.(syftpkg.Package)
	if !ok {
		return "", "", false
	}
	parent, ok := rel.To.(syftpkg.Package)
	if !ok {
		return "", "", false
	}
	return string(dependency.ID()), string(parent.ID()), true
}

func graphLicenses(licenses []syftpkg.License) []sdk.PackageLicense {
	if len(licenses) == 0 {
		return nil
	}

	out := make([]sdk.PackageLicense, 0, len(licenses))
	for _, license := range licenses {
		out = append(out, sdk.PackageLicense{
			Value:          license.Value,
			SPDXExpression: license.SPDXExpression,
			Type:           sdk.LicenseType(license.Type),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		if out[i].SPDXExpression != out[j].SPDXExpression {
			return out[i].SPDXExpression < out[j].SPDXExpression
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func graphLocations(locations []syftfile.Location) []sdk.PackageLocation {
	if len(locations) == 0 {
		return nil
	}

	out := make([]sdk.PackageLocation, 0, len(locations))
	for _, location := range locations {
		out = append(out, sdk.PackageLocation{
			RealPath:   location.RealPath,
			AccessPath: location.AccessPath,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RealPath != out[j].RealPath {
			return out[i].RealPath < out[j].RealPath
		}
		return out[i].AccessPath < out[j].AccessPath
	})
	return out
}

func graphCPEs(cpes []syftcpe.CPE) []string {
	if len(cpes) == 0 {
		return nil
	}

	out := make([]string, 0, len(cpes))
	for _, cpe := range cpes {
		value := cpe.Attributes.String()
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func syftEcosystem(pkg syftpkg.Package, purl *packageurl.PackageURL) string {
	if purl != nil && purl.Type != "" {
		return purl.Type
	}
	if pkg.Type != "" {
		if purlType := pkg.Type.PackageURLType(); purlType != "" {
			return purlType
		}
	}
	if pkg.Language != "" {
		return strings.ToLower(pkg.Language.String())
	}
	return strings.ToLower(string(pkg.Type))
}

func syftOrg(pkg syftpkg.Package, purl *packageurl.PackageURL) string {
	if purl != nil && purl.Namespace != "" {
		if syftNameAlreadyQualified(pkg.Name, *purl) {
			return ""
		}
		return purl.Namespace
	}
	return ""
}

// parsePackageURL parses with anchore/packageurl-go rather than purlkit,
// deliberately. The result is fed to helpers that compare against Syft's own
// package URLs, and Syft's API speaks that type -- converting to purlkit and
// back would translate a value twice to hand it to a library that wanted the
// original. sdk.ParsePackageURL, the SDK's wrapper over the same fork, is
// gone; this is the fork used directly for Syft interop, not a Bomly identity
// decision. Bomly-side identity is minted by the node constructor.
func parsePackageURL(value string) *packageurl.PackageURL {
	parsed, err := packageurl.FromString(value)
	if err != nil {
		return nil
	}
	return &parsed
}

func syftNameAlreadyQualified(name string, purl packageurl.PackageURL) bool {
	qualifiedName := purl.Name
	if purl.Namespace != "" {
		qualifiedName = purl.Namespace + "/" + purl.Name
	}

	return name == qualifiedName ||
		strings.HasPrefix(name, qualifiedName+"/") ||
		name == "@"+qualifiedName
}

func manifestGroupKey(manifest sdk.ManifestMetadata, fallbackID string) string {
	if manifest.Path != "" {
		return manifest.Path
	}
	if manifest.Kind != "" {
		return string(manifest.Kind) + "::" + fallbackID
	}
	return fallbackID
}

func manifestMetadataFromPackages(packages []*sdk.DependencyNode, manager sdk.PackageManager) sdk.ManifestMetadata {
	for _, pkg := range packages {
		manifest := manifestMetadataFromPackage(pkg, manager)
		if manifest.Path != "" {
			return manifest
		}
	}
	for _, pkg := range packages {
		manifest := manifestMetadataFromPackage(pkg, manager)
		if manifest.Kind != "" {
			return manifest
		}
	}
	return sdk.ManifestMetadata{}
}

func manifestMetadataFromPackage(pkg *sdk.DependencyNode, manager sdk.PackageManager) sdk.ManifestMetadata {
	if pkg == nil {
		return sdk.ManifestMetadata{}
	}
	kind := manager.Name()
	if kind == "" {
		kind = pkg.PackageManager.Name()
	}
	if kind == "" {
		kind = string(pkg.PackageManager)
	}

	for _, location := range pkg.Locations {
		candidate := firstNonEmpty(location.RealPath, location.AccessPath)
		if candidate == "" {
			continue
		}
		return sdk.ManifestMetadata{
			Path: normalizeGraphPath(candidate),
			Kind: sdk.ManifestKind(kind),
		}
	}

	return sdk.ManifestMetadata{Kind: sdk.ManifestKind(kind)}
}

func normalizeGraphPath(value string) string {
	value = filepath.ToSlash(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "./")
	return strings.TrimLeft(value, "/")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func subgraphFromRoots(src *sdk.Graph, rootIDs []string) (*sdk.Graph, map[string]struct{}, error) {
	if src == nil {
		return nil, nil, fmt.Errorf("source graph is nil")
	}

	visited := make(map[string]struct{}, len(rootIDs))
	queue := make([]string, 0, len(rootIDs))
	for _, rootID := range rootIDs {
		if rootID == "" {
			continue
		}
		if _, ok := visited[rootID]; ok {
			continue
		}
		visited[rootID] = struct{}{}
		queue = append(queue, rootID)
	}

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]

		dependencies, err := src.DirectDependencies(currentID)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve syft dependencies for %q: %w", currentID, err)
		}
		for _, dependency := range dependencies {
			if _, ok := visited[dependency.NodeID()]; ok {
				continue
			}
			visited[dependency.NodeID()] = struct{}{}
			queue = append(queue, dependency.NodeID())
		}
	}

	entryGraph := sdk.NewWithCapacity(len(visited))
	for id := range visited {
		pkg, ok := src.Node(id)
		if !ok {
			return nil, nil, fmt.Errorf("syft package %q not found while building subgraph", id)
		}
		if err := entryGraph.AddNode(pkg.CloneNode()); err != nil {
			return nil, nil, fmt.Errorf("add syft subgraph package %q: %w", id, err)
		}
	}

	for id := range visited {
		dependencies, err := src.DirectDependencies(id)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve syft dependencies for %q: %w", id, err)
		}
		for _, dependency := range dependencies {
			if _, ok := visited[dependency.NodeID()]; !ok {
				continue
			}
			if err := entryGraph.AddEdge(id, dependency.NodeID()); err != nil {
				return nil, nil, fmt.Errorf("add syft subgraph dependency %q -> %q: %w", id, dependency.NodeID(), err)
			}
		}
	}

	return entryGraph, visited, nil
}

func packageIDs(packages []*sdk.DependencyNode) []string {
	ids := make([]string, 0, len(packages))
	for _, pkg := range packages {
		if pkg == nil {
			continue
		}
		ids = append(ids, pkg.NodeID())
	}
	return ids
}
