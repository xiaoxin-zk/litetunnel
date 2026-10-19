package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

func (a *App) cleanupStaleConfigs(alive map[uint]bool) {
	dir, err := frpcTunnelsDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		a.setCleanupErr(fmt.Sprintf("无法读取本地配置文件目录（%s），已删除隧道的配置可能残留：%v", dir, err))
		return
	}

	var failures []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id64, perr := strconv.ParseUint(e.Name(), 10, 32)
		if perr != nil {
			continue
		}
		id := uint(id64)
		if alive[id] {
			continue
		}
		if a.mgr.Running(id) {
			a.warnConfigCleanup(id, "本地 frpc 进程尚未停止，配置文件暂未清理")
			continue
		}
		if rerr := removeFrpcConfig(id); rerr != nil {
			msg := "本地配置文件清理失败（其中含接入密钥）：" + rerr.Error()
			a.warnConfigCleanup(id, msg)
			failures = append(failures, fmt.Sprintf("隧道 %d：%s", id, rerr.Error()))
			continue
		}
		a.clearCleanupWarn(id)
		log.Printf("[client] 已清理隧道 %d 的本地配置（该隧道在服务端已不存在）", id)
	}
	if len(failures) > 0 {
		a.setCleanupErr("本地配置文件清理未完成（其中含接入密钥），将每轮同步自动重试：" +
			strings.Join(failures, "；"))
	} else {
		a.clearCleanupErr()
	}
}

func (a *App) setCleanupErr(msg string) {
	a.mu.Lock()
	a.cleanupErr = clampStatusText(msg)
	a.mu.Unlock()
}

func (a *App) clearCleanupErr() {
	a.mu.Lock()
	a.cleanupErr = ""
	a.mu.Unlock()
}

func (a *App) clearCleanupWarn(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cleanupWarned, id)
}

func (a *App) warnConfigCleanup(id uint, msg string) {
	a.mu.Lock()
	if a.cleanupWarned == nil {
		a.cleanupWarned = map[uint]bool{}
	}
	first := !a.cleanupWarned[id]
	a.cleanupWarned[id] = true
	a.mu.Unlock()

	if first {
		log.Printf("[client] 隧道 %d：%s", id, msg)
		a.emitNotice(msg)
	}
}

func (a *App) pruneTunnelState(alive map[uint]bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id := range a.tunnelErrs {
		if !alive[id] {
			delete(a.tunnelErrs, id)
		}
	}
	for id := range a.retries {
		if !alive[id] {
			delete(a.retries, id)
		}
	}
	for id := range a.applied {
		if !alive[id] {
			delete(a.applied, id)
		}
	}
	for id := range a.cfgRev {
		if !alive[id] {
			delete(a.cfgRev, id)
		}
	}
	for id := range a.cleanupWarned {
		if !alive[id] {
			delete(a.cleanupWarned, id)
		}
	}
	for id := range a.registered {
		if !alive[id] {
			delete(a.registered, id)
		}
	}
	for id := range a.registeredAt {
		if !alive[id] {
			delete(a.registeredAt, id)
		}
	}
	for id := range a.errEmitAt {
		if !alive[id] {
			delete(a.errEmitAt, id)
		}
	}
	for id := range a.connectAt {
		if !alive[id] {
			delete(a.connectAt, id)
		}
	}
	for id := range a.startGen {
		if !alive[id] {
			delete(a.startGen, id)
		}
	}
}
