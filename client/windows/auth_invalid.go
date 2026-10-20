package main

import (
	"log"
	"time"
)

// credentialRejected 处理「带着已保存的凭据仍被服务端 401 拒绝」。
//
// 最典型的场景：管理员在后台删除了这个用户（或禁用了账号、轮换了 API Key）。
// 旧版本只会在界面上显示一条同步错误，客户端仍然停在「已接入」状态，
// 隧道继续跑、按钮全部失败——用户必须自己发现并手动退出。
//
// 这里改成自动退出登录：清掉本地凭据、停掉所有隧道、回到登录页，
// 并提示原因，让「账号被删」立刻可见。
func (a *App) credentialRejected() {
	a.mu.Lock()
	// 没登录（例如正在用新 Key 尝试接入）时不算「凭据失效」。
	if a.authRejected || a.cfg == nil || a.cfg.APIKey == "" {
		a.mu.Unlock()
		return
	}
	a.authRejected = true
	a.mu.Unlock()

	log.Printf("[client] 服务器拒绝了当前凭据（401），账号可能已被删除或禁用，准备自动退出登录")

	go func() {
		// 调用方通常正持着同步锁，等它把这一轮收尾再退出，避免和同步互抢。
		timer := time.NewTimer(300 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-a.rootContext().Done():
			return
		case <-timer.C:
		}

		if _, err := a.logout(clearConfig, removeAllFrpcConfigs); err != nil {
			log.Printf("[client] 自动退出登录失败: %v", err)
			a.mu.Lock()
			a.authRejected = false
			a.mu.Unlock()
			// 退不出去时至少把原因显示出来，下一轮 401 会再试一次。
			a.setSyncErr(err)
			a.emitState()
			return
		}
		a.emitNotice("账号已在服务器端失效（可能被删除或禁用），已自动退出登录")
	}()
}
