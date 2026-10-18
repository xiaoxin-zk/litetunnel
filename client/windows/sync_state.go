package main

import "time"

// retryState 是一条隧道的重试退避状态。
type retryState struct {
	attempts int
	nextAt   time.Time
}

// tunnelErr 是一次 frpc 错误记录。
type tunnelErr struct {
	msg string
	at  time.Time
}

// countDisabledTunnels 统计当前处于停用状态的隧道。
//
// 停用的隧道不会拉起进程，也不该拉起——但如果日志里只说「0 条隧道运行中」，
// 用户会以为客户端坏了。这个数字用来把「没连」和「不该连」区分开。
func (a *App) countDisabledTunnels() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := 0
	for i := range a.tunnels {
		if a.tunnels[i].Status != tunnelStatusActive {
			n++
		}
	}
	return n
}

// appliedConfigOf 返回某条隧道最近一次写入磁盘的配置原文。
func (a *App) appliedConfigOf(id uint) string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.applied[id]
}

// cachedConfig 在服务端摘要与本地记账一致时返回缓存的配置原文。
//
// 摘要由服务端按**渲染结果**算出（见 service.FrpcConfigRev），所以
// 「摘要相同」就是「服务端此刻会生成的字节与本地这份完全相同」——
// 不依赖任何「哪些字段会影响配置」的推断。
//
// 摘要为空（老服务端）或与记账不符时返回 false，调用方照旧拉取。
func (a *App) cachedConfig(id uint, rev string) (string, bool) {
	if rev == "" {
		return "", false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.cfgRev[id] != rev {
		return "", false
	}
	text := a.applied[id]
	if text == "" {
		return "", false
	}
	return text, true
}
