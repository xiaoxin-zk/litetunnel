package service

import (
	"errors"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// ListAllTunnels 分页查询全部隧道。
func (s *Services) ListAllTunnels(keyword, status string, userID uint, offset, limit int) ([]model.Tunnel, int64, error) {
	q := s.DB.Model(&model.Tunnel{})
	if keyword != "" {
		q = q.Where("name LIKE ?", "%"+keyword+"%")
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.Tunnel
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// AdminSetTunnelStatus 启用/停用任意隧道。
//
// 只负责「按 id 圈定目标」，状态切换与副作用全部交给 setTunnelStatus，
// 与用户侧共用同一套实现。这条路径原先自己写了一遍状态变更，于是漏掉了
// 用户侧有、这里没有的 HTTPS 入口校验：平台切回边缘模式后，管理员仍能把
// 旧 HTTPS 隧道重新启用，得到一条状态为运行中、实际永远连不上的隧道。
//
// 联动防火墙同样必须共用：不联动的话「停用」只改了数据库，主机防火墙上的
// 规则仍然放行——后台显示已停用，端口其实还开着。而启动时的规则对齐只负责
// 「补开活跃端口」，不会清理这种残留。
func (s *Services) AdminSetTunnelStatus(id uint, status string) error {
	_, err := s.AdminSetTunnelStatusResult(id, status)
	return err
}

// AdminSetTunnelStatusResult 是 AdminSetTunnelStatus 的结构化版本，
// 供 handler 把「数据库已更新、规则待处理」透给前端（见 TunnelMutationResult）。
func (s *Services) AdminSetTunnelStatusResult(id uint, status string) (TunnelMutationResult, error) {
	if status != model.TunnelStatusActive && status != model.TunnelStatusDisabled {
		return TunnelMutationResult{}, ErrInvalidParam
	}

	// 需要 Type 与 RemotePort 才能校验入口、操作防火墙，先取出来。
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}
	return s.setTunnelStatusResult(&t, status)
}

// AdminDeleteTunnel 删除任意隧道并回收其端口。
//
// 持隧道归属者的用户锁：与该用户的编辑、启停隧道共用（见 UpdateTunnel）。
func (s *Services) AdminDeleteTunnel(id uint) error {
	_, err := s.AdminDeleteTunnelResult(id)
	return err
}

// AdminDeleteTunnelResult 是 AdminDeleteTunnel 的结构化版本。
//
// 与用户侧 DeleteTunnelResult 完全同构：删除与「收回端口的意图」在同一个
// 事务里完成，提交后立刻尝试执行一次（见 outbox.go 的说明）。
func (s *Services) AdminDeleteTunnelResult(id uint) (TunnelMutationResult, error) {
	// 端口要在删除前读出来：记录删掉之后就查不回来了，
	// 而防火墙规则会一直留在宿主机上。
	var t model.Tunnel
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}

	// 锁在读完归属者之后取：与 setTunnelStatus、DeleteTunnel 的锁序一致
	// （先读记录、再按归属者锁住整个变更段）。
	lock := s.userLock(t.UserID)
	lock.Lock()
	defer lock.Unlock()

	// 归属者锁只能保护锁住之后的并发操作；锁前读取的 t 可能已经是旧快照。
	// 加锁后重新读取，尤其要拿到最新 RemotePort/Type，避免按旧端口回收，
	// 把并发更新留下的新防火墙规则永久留在宿主机上。
	if err := s.DB.First(&t, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return TunnelMutationResult{}, ErrNotFound
		}
		return TunnelMutationResult{}, err
	}

	// 事务内：删记录 + 登记收回端口的意图（与用户侧同一套语义）。
	var intents []portIntent
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ?", id).Delete(&model.Tunnel{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		if t.RemotePort <= 0 {
			return nil
		}
		gen, err := firewallIntentTx(tx, t.RemotePort, ProtoOfTunnel(t.Type), false)
		if err != nil {
			return err
		}
		intents = append(intents, portIntent{
			port: t.RemotePort, proto: ProtoOfTunnel(t.Type), open: false, gen: gen,
		})
		return nil
	})
	if err != nil {
		return TunnelMutationResult{}, err
	}

	pending, fatal, warnings := s.executePortIntentsAfterCommit(intents)
	if fatal != nil {
		// 同用户侧删除：删除已提交，不能返回 error 让管理员重试（只会得到
		// 「隧道不存在」），但必须写清「端口可能还开着、需要人工处理」。
		res := tunnelMutationResult(pending, warnings)
		res.Warning = "隧道已删除，但端口规则未能收回且无法自动重试（" +
			fatal.Error() + "），请手工关闭对应端口"
		return res, nil
	}
	return tunnelMutationResult(pending, warnings), nil
}

// ListClientSessions 分页查询客户端登录会话。
func (s *Services) ListClientSessions(userID uint, offset, limit int) ([]model.ClientSession, int64, error) {
	q := s.DB.Model(&model.ClientSession{})
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.ClientSession
	err := q.Order("last_seen_at desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// ---- 审计 ----
