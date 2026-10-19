package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

const (
	modeSecret os.FileMode = 0o600
	modeConfig os.FileMode = 0o644
)

func (e *envFile) set(key, value string) (bool, error) {
	if tlscfg.HasControlChars(key) || tlscfg.HasControlChars(value) {
		return false, fmt.Errorf("拒绝写入 %s：键或值含有换行或其他控制字符", key)
	}

	encoded := encodeEnvValue(value)

	changed := false
	found := false
	for i, line := range e.lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 1 || strings.TrimSpace(trimmed[:idx]) != key {
			continue
		}
		found = true
		next := key + "=" + encoded
		if e.lines[i] != next {
			e.lines[i] = next
			changed = true
		}
	}
	if !found {
		e.lines = append(e.lines, key+"="+encoded)
		return true, nil
	}
	return changed, nil
}

func (e *envFile) content() string {
	return strings.Join(e.lines, "\n") + "\n"
}

func (e *envFile) write() error {
	return writeFileAtomic(e.path, e.content(), modeSecret)
}

func ensureMode(path string, mode os.FileMode) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	want := mode.Perm()
	if fi.Mode().Perm() == want {
		return false, nil
	}
	if err := os.Chmod(path, want); err != nil {
		return false, err
	}
	return true, nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedChanged(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
