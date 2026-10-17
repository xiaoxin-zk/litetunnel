package service

import (
	"errors"
	"strconv"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

// ParsePortList 解析 "22,80,443,10000-10100" 形式的端口列表。
//
// 同时支持单个端口与闭区间，非法片段会被忽略而不是让整次调用失败——
// 这是运营配置，容忍个别笔误比直接报错更实用。
func ParsePortList(s string) map[int]bool {
	out := make(map[int]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			start, err1 := strconv.Atoi(strings.TrimSpace(lo))
			end, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || start <= 0 || end < start || end > 65535 {
				continue
			}
			// 区间过大时截断，避免有人填 1-65535 把内存吃光。
			if end-start > 4096 {
				end = start + 4096
			}
			for p := start; p <= end; p++ {
				out[p] = true
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil && p > 0 && p <= 65535 {
			out[p] = true
		}
	}
	return out
}

// ParseDomainList 解析逗号分隔的域名列表，统一转小写并去掉 @ 前缀。
//
// 与 ParsePortList 一样采取宽容策略：忽略空项与格式明显错误的项，
// 不让一个笔误导致整份配置无法保存。
func ParseDomainList(s string) map[string]bool {
	out := make(map[string]bool)
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part), "@")))
		if part == "" || strings.ContainsAny(part, " \t\r\n/\\") {
			continue
		}
		// 只接受形如 a.b 的域名，避免把 IP 或路径写进来。
		if !strings.Contains(part, ".") {
			continue
		}
		out[part] = true
	}
	return out
}

// DomainInList 判断邮箱域名是否命中列表（含子域）。
func DomainInList(domain string, list map[string]bool) bool {
	if domain == "" || len(list) == 0 {
		return false
	}
	domain = strings.ToLower(domain)
	for d := range list {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// defaultTerms 是注册页默认展示的条款与禁止滥用说明。
var defaultTerms = func(*config.Config) string {
	return strings.Join([]string{
		"一、服务说明",
		"本平台提供内网穿透转发服务，仅用于合法的个人或企业自有系统访问。",
		"",
		"二、禁止行为",
		"1. 禁止用于任何违法违规用途，包括但不限于网络攻击、扫描探测、钓鱼、诈骗、传播违法信息；",
		"2. 禁止开放以下端口：25、110、143、465、587（邮件）、137-139、445（SMB）、3389（远程桌面）、",
		"   以及任何用于批量发送垃圾邮件或对外发起攻击的端口；",
		"3. 禁止利用本服务进行端口扫描、爆破、DDoS 攻击或作为跳板；",
		"4. 禁止传播恶意软件、挖矿程序或搭建任何形式的非法中继；",
		"5. 禁止转售、共享账号或超出授权范围使用。",
		"",
		"三、违规处置",
		"一经发现违规行为，平台有权立即停止服务、封禁账号、保留相关日志并配合有关部门调查。",
		"因违规行为导致的法律责任由使用者自行承担。",
		"",
		"四、其他",
		"平台会记录必要的连接与操作日志用于安全审计，日志保留不少于 6 个月。",
		"继续注册即表示你已阅读并同意上述条款。",
	}, "\n")
}

// splitHostPortLoose 宽松地拆出监听地址中的端口，用于生成默认的保护端口列表。
func splitHostPortLoose(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", errors.New("no port")
	}
	return addr[:i], addr[i+1:], nil
}
