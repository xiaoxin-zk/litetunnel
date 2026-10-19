package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// 本文件是 .env 的**读改写**单元：只替换目标键的值、保留注释与分组，以及
// 产物文件的权限口径。
//
// # 各部分在哪
//
//	dotenv.go          —— 一行的语义：按 Compose 的 dotenv 规则解析与编码
//	本文件              —— .env 的 set/content/write，以及产物文件的权限
//	file_commit.go     —— 单文件的临时文件/备份/替换/回滚（stagedFile）
//	batch_recovery.go  —— 启动时的批次回滚与残留清理
//	statcheck.go       —— 「路径在不在」的三态判定
//
// 拆开的原则是**副作用边界**：dotenv.go 是纯字符串函数，本文件只碰 .env 这
// 一个文件，file_commit.go 才涉及「先备份再替换再回滚」这套有状态的流程。
// 混在一起时，读代码的人很难分清某一行是「改内存里的行」还是「动磁盘上的文件」。

// 产物文件的权限。集中在这里定义，避免「某处 0644、某处 0600」这种
// 看代码看不出来、只有 ls -l 才能发现的分叉。
const (
	// modeSecret 用于含凭据的文件：.env 与 frps.toml。
	//
	// .env 里有 DNS API 凭据、JWT 密钥与数据库口令；frps.toml 里有 frps 的
	// 全局 token 与管理 API 密码。0644 意味着同机器上的**任何**普通账号都能
	// 读走它们——足以伪装成客户端接入网关，或者直接调用 frps 管理接口。
	//
	// 0600 不会挡住容器：lt-config 以 root 运行（deploy/systemd/lt-config.service
	// 的 User=root），文件属主就是 root，而以 root 运行的 frps 容器读属主为
	// root、属主位可读的文件，不需要任何额外能力位。
	modeSecret os.FileMode = 0o600
	// modeConfig 用于不含凭据的产物：Caddyfile 里只有域名与 {env.*} 引用，
	// 凭据在容器环境变量里。
	modeConfig os.FileMode = 0o644
)

// set 更新一个键，返回是否真的发生了变化。
//
// 同名键全部更新：解析时是「后者胜」，只改最后一个会让文件里留下一个
// 与生效值不一致的旧行，将来谁读到它都会得出错误结论。
func (e *envFile) set(key, value string) (bool, error) {
	// 值里出现换行，就等于往 .env 里追加额外的一行配置——包括白名单之外的键
	// （LT_CADDY_IMAGE 这类），而 Compose 的插值接受任何来自 .env 的键。
	//
	// 调用方 renderAndApply 已经校验过一次；这里是真正落笔的那一处，再挡一次：
	// 将来新增调用方时，漏掉校验的代价是整个权限边界。
	//
	// 拒绝控制字符是**调用方**的职责而不是 encodeEnvValue 的：编码只负责
	// 「把值写成 Compose 能读回同一个字符串的形式」，安全边界放在落笔这一处
	// 才只可能漏一次。
	if tlscfg.HasControlChars(key) || tlscfg.HasControlChars(value) {
		return false, fmt.Errorf("拒绝写入 %s：键或值含有换行或其他控制字符", key)
	}

	// 值必须按 Compose 的 dotenv 语义编码后落盘（见 dotenv.go 的 encodeEnvValue）：
	// 裸写的话，凭据里的 $ 会被 Compose 插值改写，容器拿到的是另一个字符串。
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

// content 返回写回磁盘的完整内容。
func (e *envFile) content() string {
	return strings.Join(e.lines, "\n") + "\n"
}

// write 原子写入 .env。
//
// 权限**无条件**为 0600：这个文件里有 DNS API 凭据、JWT 密钥与数据库口令。
// 早期版本只在「本次请求带了凭据字段」时才收紧权限，那等于让文件权限取决于
// 调用方这一次带了哪些字段——一个省略字段的合法请求就能把它放回 0644。
func (e *envFile) write() error {
	return writeFileAtomic(e.path, e.content(), modeSecret)
}

// ensureMode 把已存在文件的权限纠正到期望值，返回是否真的改动过。
//
// 内容没变时不会重写文件，但权限可能是早期版本留下的 0644（或被人手工放宽
// 过）：只比较内容就跳过的话，那份宽松权限会一直留在磁盘上。
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

// sortedKeys 返回有序键名，便于输出稳定的日志与结果。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedChanged 把变化的文件名转成稳定顺序的清单。
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
