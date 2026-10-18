package main

import (
	"os"
	"strings"
)

// 本文件是 .env 的**解析**单元：读文件、按 Compose 的 dotenv 语义解析一行，
// 以及与之互逆的编码（写出去的值必须能被 docker compose 读回同一个字符串）。
//
// # 为什么单独拆出来
//
// 这套编解码有**两个读者**：docker compose --env-file（值先按 dotenv 解析、
// 再做插值），以及本服务自己的 readEnvFile。两边对同一个值的理解必须完全
// 一致，否则「渲染用的凭据」与「容器里实际拿到的凭据」是两个不同的字符串——
// Caddy 拿着错的凭据签不出证书，而且查不出原因。
//
// 它也是 .env 处理里唯一「纯字符串」的部分：不碰磁盘、不碰权限、不碰备份。
// 放在 envfile.go 里时，它与「暂存/备份/替换/清理」那些有副作用的代码混在
// 一起，改动任意一处都得先分清自己读到哪一层了。拆开之后：
//
//	本文件             — 一行的语义（解析 + 编码）
//	envfile.go         — .env 的读改写与产物文件的权限
//	file_commit.go     — 单文件的临时文件/备份/替换/回滚
//	batch_recovery.go  — 启动时的批次回滚与残留清理
//
// 控制字符（换行等）不在这里处理：那是安全边界，由 set 拒绝（见 envfile.go）。
// 编码是本文件的职责，拒绝是调用方的职责，两件事不该混在一个函数里。

// envFile 是部署目录下的 .env，按行保存以便「只改动需要改的那几行」。
//
// 为什么不整体重写：.env 是运维手工维护的文件，里面全是注释与分组。
// 重写一遍等于把注释全部抹掉——那样下次出问题时，管理员手上就没有
// 任何线索了。所以这里只替换目标键的值。
type envFile struct {
	path  string
	lines []string
}

// readEnvFile 读取 .env，同时返回解析后的键值表（后者用于渲染）。
//
// 解析规则与 deploy/scripts/render.* 保持一致：忽略空行与 # 注释，
// 只认第一个 '='，键值两端去空白。
//
// 值的解码与 set 的编码互为逆运算（见 encodeEnvValue）：这套文件同时会被
// docker compose --env-file 解析，所以这里必须按 Compose 的 dotenv 语义
// 还原——双引号包裹的值先处理转义（\\ \" 等），单引号包裹的值按字面保留，
// 两种引号之外再统一把 Compose 的转义插值 $$ 还原成 $。老文件里没转义的
// 裸值不含这些序列，解码后原样不变。
func readEnvFile(path string) (*envFile, map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	// Split 会在结尾换行处多出一个空元素，保留它会写出一个多余的空行。
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
		// 同名键重复出现时以后者为准，与渲染脚本的解析顺序一致。
		vars[strings.TrimSpace(trimmed[:idx])] = decodeEnvValue(strings.TrimSpace(trimmed[idx+1:]))
	}
	return &envFile{path: path, lines: lines}, vars, nil
}

// decodeEnvValue 按 Compose 的 dotenv 语义还原一个值。
//
// 与 encodeEnvValue 互逆：读回来的值必须等于当初写进去的值，
// 否则「渲染用的凭据」与「容器里实际拿到的凭据」会是两个不同的字符串。
func decodeEnvValue(raw string) string {
	if raw == "" {
		return ""
	}
	// 双引号：转义序列有效（\\、\"、\n、\r、\t），随后再展开插值转义。
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return unescapeDollar(expandEnvEscapes(raw[1 : len(raw)-1]))
	}
	// 单引号：按字面保留（Compose 对单引号值不做转义与插值）。
	if len(raw) >= 2 && raw[0] == '\'' && raw[len(raw)-1] == '\'' {
		return raw[1 : len(raw)-1]
	}
	// 裸值：只有插值转义。
	return unescapeDollar(raw)
}

// expandEnvEscapes 处理双引号内的反斜杠转义序列。
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
			// 未知转义按字面保留，与 Compose 的容忍行为一致。
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// unescapeDollar 把 Compose 的插值转义 $$ 还原成 $。
//
// 按字面替换即可：值里连着三个以上的 $ 在合法凭据里不会出现，
// 也不值得为它维护一套扫描状态机。
func unescapeDollar(s string) string {
	return strings.ReplaceAll(s, "$$", "$")
}

// encodeEnvValue 把值序列化成 Compose 兼容的 .env 行值。
//
// 这份文件会被两个读者解析：
//
//   - docker compose --env-file：值先按 dotenv 语法解析，再做插值，
//     $NAME 与 ${NAME} 都会被当作变量引用展开——DNS 凭据里一个裸的 $
//     会让运行时拿到的值被插值改写，Caddy 拿着错的凭据签不出证书。
//   - 本服务自己的 readEnvFile（编码解码必须互逆，见上）。
//
// 规则：
//   - $ 一律写成 $$（Compose 的转义插值，两种引号下语义一致）；
//   - 含空白、#、引号等会破坏「一行一个值」结构的字符时，用双引号包裹，
//     并转义 \ 与 "（Compose 对双引号值处理这些转义序列）；
//   - 其余字符原样。
//
// 控制字符（换行等）不在这里处理：调用方 set 已经拒绝，那才是安全边界。
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
