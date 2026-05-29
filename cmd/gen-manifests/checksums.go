package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/osbuild/images/pkg/container"
	"github.com/osbuild/images/pkg/depsolvednf"
	"github.com/osbuild/images/pkg/flatpak"
	"github.com/osbuild/images/pkg/manifest"
	"github.com/osbuild/images/pkg/ostree"
)

// manifestChecksum is the method reponsible for doing the hard work
func manifestChecksum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Checksums records manifest digests grouped by distro, image type, and config.
type Checksums struct {
	dir       string
	mu        sync.Mutex // serializes read/modify/write of multi-arch checksum files
	processed sync.Map   // key: group basename, value: struct{}
}

func newChecksums(dir string) *Checksums {
	return &Checksums{dir: dir}
}

func checksumGroupBasename(distro, imgType, config string) string {
	return fmt.Sprintf("%s-%s-%s", u(distro), u(imgType), u(config))
}

func parseGroupChecksumFile(data []byte) (map[string]string, error) {
	arches := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid checksum line %q", line)
		}
		arches[fields[0]] = fields[1]
	}
	return arches, nil
}

func formatGroupChecksumFile(arches map[string]string) string {
	keys := make([]string, 0, len(arches))
	for arch := range arches {
		keys = append(keys, arch)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, arch := range keys {
		fmt.Fprintf(&b, "%s %s\n", arch, arches[arch])
	}
	return b.String()
}

func writeGroupChecksumFileIfChanged(path string, arches map[string]string) error {
	want := formatGroupChecksumFile(arches)
	b, err := os.ReadFile(path)
	if err == nil && string(b) == want {
		return nil
	}
	return os.WriteFile(path, []byte(want), 0o644) //nolint:gosec // checksum artifacts are world-readable in git
}

func (c *Checksums) recordManifestChecksum(ms manifest.OSBuildManifest, depsolved map[string]depsolvednf.DepsolveResult, containers map[string][]container.Spec, commits map[string][]ostree.CommitSpec, flatpaks map[string][]flatpak.Spec, cr buildRequest, archName, filename string, metadata bool) error {
	var buf bytes.Buffer
	if err := save(&buf, false, ms, depsolved, containers, commits, flatpaks, cr, filename, metadata); err != nil {
		return err
	}
	digest := manifestChecksum(buf.Bytes())
	groupName := checksumGroupBasename(cr.Distro, cr.ImageType, cr.Config.Name)
	path := filepath.Join(c.dir, groupName)

	c.mu.Lock()
	defer c.mu.Unlock()

	arches := make(map[string]string)
	if b, readErr := os.ReadFile(path); readErr == nil {
		var err error
		arches, err = parseGroupChecksumFile(b)
		if err != nil {
			return fmt.Errorf("failed to parse checksum %q: %w", path, err)
		}
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("failed to read checksum %q: %w", path, readErr)
	}
	arches[archName] = digest
	if err := writeGroupChecksumFileIfChanged(path, arches); err != nil {
		return fmt.Errorf("failed to write checksum %q: %w", path, err)
	}
	c.processed.Store(groupName, struct{}{})
	return nil
}

func (c *Checksums) deleteStaleChecksums() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return fmt.Errorf("failed to read checksum directory %q: %w", c.dir, err)
	}
	for _, e := range entries {
		name := e.Name()
		if _, ok := c.processed.Load(name); ok || e.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(c.dir, name)); err != nil {
			return fmt.Errorf("failed to remove stale checksum %q: %w", name, err)
		}
	}
	return nil
}
