package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverBatchAcrossDefaultLayout(t *testing.T) {
	root := t.TempDir()
	deploy := filepath.Join(root, "deploy")
	caddyDir := filepath.Join(deploy, "caddy")
	frpsDir := filepath.Join(deploy, "frps")
	for _, d := range []string{caddyDir, frpsDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	oldContent := map[string]string{
		filepath.Join(caddyDir, "Caddyfile"): "old caddy\n",
		filepath.Join(frpsDir, "frps.toml"):  "old frps\n",
		filepath.Join(root, ".env"):          "LT_X=old\n",
	}
	entries := make([]manifestEntry, 0, len(oldContent))
	for path, old := range oldContent {
		if err := os.WriteFile(path+backupSuffix, []byte(old), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("new "+old), 0o600); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, manifestEntry{
			Name:    filepath.Base(path),
			Path:    path,
			Existed: true,
			NewSum:  contentSum("new " + old),
			BakSum:  contentSum(old),
		})
	}

	m := batchManifest{Version: 1, Dir: caddyDir, Files: entries}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caddyDir, batchManifestName), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	p := paths{
		deployDir: deploy,
		envFile:   filepath.Join(root, ".env"),
		caddyOut:  filepath.Join(caddyDir, "Caddyfile"),
		frpsOut:   filepath.Join(frpsDir, "frps.toml"),
	}
	blocked := cleanupLeftovers(p)
	if len(blocked) != 0 {
		t.Fatalf("默认布局的批次恢复不应阻断任何目录，实际 %v", blocked)
	}

	for path, old := range oldContent {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", path, err)
		}
		if string(data) != old {
			t.Errorf("%s 应回滚为旧内容，实际 %q", path, data)
		}
		if _, err := os.Stat(path + backupSuffix); !os.IsNotExist(err) {
			t.Errorf("%s 的备份应已被恢复消耗，实际 err=%v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(caddyDir, batchManifestName)); !os.IsNotExist(err) {
		t.Errorf("恢复完成后批次记录应删除，实际 err=%v", err)
	}
}
