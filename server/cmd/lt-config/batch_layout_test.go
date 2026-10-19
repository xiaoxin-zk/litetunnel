package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 默认部署布局的崩溃恢复。
//
// 三个受管文件本来就不在同一棵子树下：Caddyfile 在 deploy/caddy、
// frps.toml 在 deploy/frps、.env 在 deploy 的父目录。批次记录只能放在
// 其中一个目录里，因此「按目录前缀判断越界」必然误拒正常布局——恢复
// 失败，目录被永久阻断，之后所有写盘都不可用。
//
// 这里模拟一次「文件已全部换新、记录还没落定」的崩溃，断言整批能按记录
// 回滚，且不产生阻断。
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
		// 崩溃现场：备份是旧内容，目标是已换上的新内容。
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

	// 记录放在第一个文件所在目录，与生产写入路径一致。
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
