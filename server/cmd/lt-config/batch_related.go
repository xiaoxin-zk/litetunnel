package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func relatedBatchDirs(dir string) []string {
	manifestPath := filepath.Join(dir, batchManifestName)
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return []string{dir}
	}
	var m batchManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return []string{dir}
	}
	seen := map[string]struct{}{dir: {}}
	out := []string{dir}
	for _, f := range m.Files {
		if f.Path == "" {
			continue
		}
		d := filepath.Dir(f.Path)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}
