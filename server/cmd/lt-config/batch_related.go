package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// relatedBatchDirs 返回 manifest 涉及的全部目录。
//
// manifest 固定放在首个文件目录，但 Files 可以跨目录。恢复失败时必须把
// 整批目录一起保护起来，不能让调用方继续在其它目录执行单文件备份清理。
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
