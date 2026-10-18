package service

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// AdminSetUserQuota 单独设定用户的流量配额（字节）。0 表示回落到分组配额。
func (s *Services) AdminSetUserQuota(id uint, quota int64) error {
	if quota < 0 {
		return fmt.Errorf("%w: 配额不能为负数", ErrInvalidParam)
	}
	// 与禁用/启用、分组调整等「数据库更新 + 运行时标记刷新」成对的操作共用
	// 同一把用户锁：并发的配额调整或状态切换交错执行时，各自的写库与内存
	// 写入可能以不同顺序完成，导致运行时标记与数据库短暂不一致。持有用户锁
	// 之后两者只可能是先后关系（版本校验见 refreshQuotaFor）。
	lock := s.userLock(id)
	lock.Lock()
	defer lock.Unlock()

	res := s.DB.Model(&model.User{}).Where("id = ?", id).Update("traffic_quota", quota)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	// 先递增版本号再刷新：让在途的旧快照（后台整表刷新、并发的另一笔
	// 配额调整）让路，随后的读取必然看到刚提交的配额。
	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

// AdminResetUserTraffic 清零用户已用流量。
//
// 必须先在采集器登记待协调标记、再清零（见 Runtime.pendingTrafficReset）：
// 清零后紧邻一轮的增量是清零前采样的旧流量，不拦的话最多一个采样周期后
// 它会重新加回用户用量——管理员看到「明明清零了又涨回来了」。
// 顺序反过来（先清零后登记）会有一个窗口：增量恰好插在两步之间落库，
// 标记拦不住它。
func (s *Services) AdminResetUserTraffic(id uint) error {
	// 「登记 + 清零写库（+ 失败撤销）」整段与采集的「快照 → 提交」互斥。
	//
	// 只让撤销拿锁还不够：采集可能已经取到**不含本用户标记**的快照，
	// 管理员随后清零写库，采集再提交那份快照里的旧增量——清零后的用量
	// 又被加回，正是这套标记要防的事。持有协调锁之后，两者只可能是
	// 先后关系：要么清零先落地（采集快照一定包含标记），要么采集先提交
	// （清零随后写绝对值 0，结果仍然正确）。
	unlockReset := s.Runtime.lockTrafficReset()
	defer unlockReset()

	// 记下本次登记的代次：撤销只能作用于这一笔。同一用户可能有并发的
	// 另一笔清零已成功登记，按用户整体撤销会把它的标记一并作废，
	// 那一笔清零前的旧增量随后就会被加回。
	gen := s.Runtime.MarkTrafficResetPending(id)
	res := s.DB.Model(&model.User{}).Where("id = ?", id).Updates(map[string]any{
		"traffic_used": 0,
		// 推进清零代次：采集器写增量时按它做条件更新。多副本下清零请求可能
		// 落在别的实例，进程内的标记对方看不见——代次在库里，谁都看得见。
		"traffic_reset_gen": gorm.Expr("traffic_reset_gen + 1"),
		"traffic_reset_at":  time.Now().AddDate(0, 1, 0),
	})
	if res.Error != nil {
		// 清零没写进去，登记的标记必须撤销：留着它，后续采集会错误地
		// 丢弃一轮**真实**用量。已在协调区间内，用加锁版本撤销——
		// 再取一次 resetMu 会自死锁。
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return res.Error
	}
	if res.RowsAffected == 0 {
		s.Runtime.unmarkTrafficResetPendingLocked(id, gen)
		return ErrNotFound
	}
	s.Runtime.BumpGuardVer()
	s.Runtime.SetQuotaExceeded(id, false)
	return nil
}

// refreshQuotaFor 刷新单个用户的超额标记。
//
// 读库与写标记之间存在窗口：并发的两笔配额调整，先发起的那笔可能读到
// 旧配额、却后完成写入，用旧结果覆盖新标记（用户被错误放行或被错误
// 拦截）。因此版本号在**读库之前**取，写入用 SetQuotaExceededIfVer
// 条件写；版本变了就说明期间有别的管理操作（或后台刷新）动过，重读重试。
//
// 调用方必须在**自己的数据库写入提交之后**先 BumpGuardVer，再调用本方法：
// 递增让在途的旧快照让路，之后的读取必然看到刚提交的新状态。
//
// 读取失败必须返回错误：标记留在旧值上（比如「超额」），调用方若把它
// 当成功上报，管理员会以为调整已生效，而插件还在按旧标记拦截——
// 「改了配额却没反应」且无处排查。
func (s *Services) refreshQuotaFor(id uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		u, err := s.LoadUser(id)
		if err != nil {
			return fmt.Errorf("刷新配额标记失败（用户 %d）: %w", id, err)
		}
		exceeded := s.QuotaExceeded(u)
		if s.Runtime.SetQuotaExceededIfVer(u.ID, exceeded, ver) {
			return nil
		}
		// 版本在读取期间被推进：这次算出的结果基于旧快照，丢弃重读。
	}
	return fmt.Errorf("刷新配额标记失败（用户 %d）：并发调整过于频繁，未能稳定写入", id)
}
