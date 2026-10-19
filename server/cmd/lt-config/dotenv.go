package main

import (
	"strings"
)

type envFile struct {
	path  string
	lines []string
}

func readEnvFile(path string) (*envFile, map[string]string, error) {
	raw, err := readConfigInput(path)
	if err != nil {
		return nil, nil, err
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}

	vars := make(map[string]string, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 1 {
			continue
		}
		vars[strings.TrimSpace(trimmed[:idx])] = decodeEnvValue(strings.TrimSpace(trimmed[idx+1:]))
	}
	return &envFile{path: path, lines: lines}, vars, nil
}

func decodeEnvValue(raw string) string {
	if raw == "" {
		return ""
	}
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return unescapeDollar(expandEnvEscapes(raw[1 : len(raw)-1]))
	}
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1]
	}
	return unescapeDollar(raw)
}

func expandEnvEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch s[i+1] {
		case '\\':
			b.WriteByte('\\')
			i++
		case '"':
			b.WriteByte('"')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func unescapeDollar(s string) string {
	return strings.ReplaceAll(s, "$$", "$")
}

func encodeEnvValue(v string) string {
	if v == "" {
		return ""
	}
	quote := strings.ContainsAny(v, " \t#\"'`")
	var b strings.Builder
	b.Grow(len(v) + 2)
	if quote {
		b.WriteByte('"')
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '$':
			b.WriteString("$$")
		case quote && c == '\\':
			b.WriteString(`\\`)
		case quote && c == '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
	if quote {
		b.WriteByte('"')
	}
	return b.String()
}
