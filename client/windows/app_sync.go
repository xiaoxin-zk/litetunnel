package main

// 本文件是「同步调度」这一职责里的**门闩**部分：谁可以进同步、怎么排队。
//
// # 为什么单独成文
//
// 同步门闩（syncGate）是 App 里最容易出死锁的一处：它是容量 1 的 channel，
// 拿不到就阻塞，而「拿到了却忘了放」会让之后所有同步、退出登录、关闭流程
// 全部挂死——界面表现是「点什么都不动」，日志里什么都没有。
//
// 它原来埋在 app.go 的构造与 Wails 生命周期之间，调用点分散在
// sync_schedule.go / auth.go / shutdown 里。单独成文之后，「进入同步必须先
// lockSync、且必须 defer unlockSync」这条规则有了唯一的落点，新增同步入口时
// 也不容易漏掉。
//
// 真正的调度逻辑（周期、退避、串行化一轮同步）在 sync_schedule.go。

import "context"

// syncGateChan 返回同步门闩，必要时惰性初始化。
//
// 惰性化是为了测试：测试直接构造 App 而没有走 NewApp，字段是零值。
func (a *App) syncGateChan() chan struct{} {
	a.gateOnce.Do(func() {
		if a.syncGate == nil {
			a.syncGate = make(chan struct{}, 1)
		}
	})
	return a.syncGate
}

// lockSync 取得同步门闩；ctx 结束则放弃等待并返回其错误。
//
// 取不到时调用方必须**直接返回**，不能继续往下走：后续的 unlockSync
// 会从空 channel 上接收，把自己挂在解锁那一步。
func (a *App) lockSync(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case a.syncGateChan() <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// lockSyncBlocking 是不可取消的等待，只给关闭流程用（见 shutdown）。
//
// 关闭流程要确认的是「那一轮同步真的收工了」，可取消的等待会在超时时
// 提前放弃，反而让这个确认失去意义（另有一层总超时兜底）。
func (a *App) lockSyncBlocking() {
	a.syncGateChan() <- struct{}{}
}

// unlockSync 释放同步门闩。
func (a *App) unlockSync() {
	<-a.syncGateChan()
}
