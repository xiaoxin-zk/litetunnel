package main

import (
	"log"
	"os"
	"strconv"
)

// cleanupStaleConfigs 清掉「服务端已经没有」的隧道在本地留下的配置文件。
//
// # 为什么以磁盘为准，而不是只看「刚停掉的进程」
//
// 隧道可能在**网页端**被删除，或客户端删除请求在服务端完成之后遇到网络错误：
// 这时客户端这一侧既没有它的进程、也没有内存状态，上面那个「收进程」的循环
// 根本不会经过它，pruneTunnelState 又只清内存——磁盘上的 frpc.toml 就一直留着。
//
// 所以这里扫一遍隧道目录，凡是不在服务端清单里的都清掉。目录名是隧道 ID。
//
// 进程还没停下来的**刻意不删**：删了它仍在跑，而配置文件没了意味着下次排查时
// 什么都看不到；磁盘上的残留本身就是「待重试状态」，下一轮同步会再来一次。
func (a *App) cleanupStaleConfigs(alive map[uint]bool) {
	dir, err := frpcTunnelsDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// 目录不存在是正常的（还没建过隧道）。
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id64, perr := strconv.ParseUint(e.Name(), 10, 32)
		if perr != nil {
			// 不是隧道目录（用户自己放的东西），别动它。
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
			a.warnConfigCleanup(id, "本地配置文件清理失败（其中含接入密钥）："+rerr.Error())
			continue
		}
		// 清理成功：把「已提示过」的标记一并撤掉。
		//
		// 不撤的话这张表只增不减——反复遇到「清理失败 → 后来成功」的不同隧道，
		// 每个 ID 都会永久占一个条目。
		a.clearCleanupWarn(id)
		log.Printf("[client] 已清理隧道 %d 的本地配置（该隧道在服务端已不存在）", id)
	}
}

// clearCleanupWarn 撤掉「已提示过清理失败」的标记。
func (a *App) clearCleanupWarn(id uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cleanupWarned, id)
}

// warnConfigCleanup 就「配置清理失败」提示用户，同一隧道只提示一次。
//
// 不重复提示是因为它会每 20 秒重试一次：每次都弹提示只会把界面刷满，
// 而结论一直是同一个。真正的重试仍在继续（残留文件还在，下轮会再试）。
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

// pruneTunnelState 丢弃「服务端已经没有」的隧道留下的各种记录。
//
// 不按运行中的进程来清，是因为一条隧道可能因为启动失败而没有进程：
// 之后它被服务端删掉，这些记录就再也没有机会被访问或清理。
//
// 每张按隧道记账的表都要清，包括 applied：它存的是「最近一次写入磁盘的配置原文」，
// 每条几百字节到几 KB。反复「建了、删掉」会让它一直占着内存，
// 而它的用途（判断配置有没有变）只对还存在的隧道有意义。
//
// cleanupWarned 同理：它记的是「这条隧道的清理失败已经提示过了」，
// 隧道都不存在了，这个标记没有任何意义。
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
	// 摘要与配置原文是一对，必须同生共死：只清文本会留下一个孤儿摘要，
	// 它会让下一次同 id 的隧道（id 不会复用，但地图会一直长）永远命中不了。
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
	// 下面这几张表是后加的，同样要清：它们都是「按隧道 id 记账」的小结构，
	// 每项只有几十字节，但一条隧道被删掉之后就再没有人会读写它——
	// 反复「建了、报错、删掉」会让它们随进程寿命一直长下去，属于纯粹的泄漏。
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
	// 连接起点同理：一条隧道反复「建了、连不上、删掉」时，这些条目没有
	// 任何机会被再次访问，会随进程寿命一直留着。
	for id := range a.connectAt {
		if !alive[id] {
			delete(a.connectAt, id)
		}
	}
	// 启动代次：隧道已被服务端删除，它的进程也已经在 applySyncData 里停掉。
	// 留着的后果不是内存，而是**误判**——将来同 id 的退出回调（这台机器上
	// 不会有，但记录不清就是一次无法自证的历史残留）会被当成当前账号的。
	for id := range a.startGen {
		if !alive[id] {
			delete(a.startGen, id)
		}
	}
}
