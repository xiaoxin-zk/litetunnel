package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// GroupExpiry 描述这次操作要对「分组有效期」做什么，共三态：
//
//	Set=false          → 不修改（请求里没带这个字段）
//	Set=true, Value=nil → 清除（请求里显式给了 null）
//	Set=true, Value!=nil → 设为该时刻
//
// 必须区分三态：只有「非 nil 才更新」的写法会让「清空有效期」变成空操作，
// 旧值残留后到期调度会把刚改派的用户迁回默认分组。
type GroupExpiry struct {
	Set   bool
	Value *time.Time
}

// AdminSetUserGroup 调整用户分组与到期时间。
//
// 分组的存在性检查、用户行的更新放进同一事务，并按全局锁序
// （用户行 → 分组行，与 Redeem 一致）对两张行加 FOR UPDATE：
// 只在事务外查一下分组的话，「检查通过 → 更新用户」之间分组可能被删，
// 写出一个悬空的 group_id。
func (s *Services) AdminSetUserGroup(id, groupID uint, expiry GroupExpiry) error {
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, groupID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("%w: 分组不存在", ErrInvalidParam)
			}
			return err
		}

		updates := map[string]any{"group_id": groupID}
		if expiry.Set {
			if expiry.Value == nil {
				// 显式清除：写成 NULL，到期调度之后就不会再把这名用户迁走。
				updates["group_expire_at"] = nil
			} else {
				updates["group_expire_at"] = *expiry.Value
			}
		}
		res := tx.Model(&model.User{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		// 用户不存在时必须报错。不看 RowsAffected 的话，改一个不存在的
		// 用户会「成功」返回，管理员以为改好了，实际什么都没发生。
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		// 分组变化后刷新该用户所有隧道的限速快照。
		//
		// 快照必须按**生效分组**算，而不是按刚写进去的目标分组：给一个已经
		// 过期（或到期时间就在过去）的账号改派付费分组时，运行期实际回落到
		// 默认分组，把目标分组的限速写进快照会让「界面显示的限速」与真正
		// 生效的限速相反，且没有任何后续事件会纠正它——到期调度会先把用户
		// 迁回默认分组，之后这行快照就再也没人更新了。
		effective := &g
		expireAt := u.GroupExpireAt
		if expiry.Set {
			expireAt = expiry.Value
		}
		if expireAt != nil && !expireAt.After(time.Now()) {
			if dg := s.defaultGroupTx(tx); dg != nil {
				effective = dg
			}
		}
		return tx.Model(&model.Tunnel{}).Where("user_id = ?", id).
			Update("bandwidth_limit", effective.BandwidthLimit).Error
	})
	if err != nil {
		return err
	}

	// 配额刷新必须放在事务**提交之后**。
	//
	// 它内部要用主连接重新查一次用户，而 SQLite 默认只开一个连接
	// （store.go 里 SetMaxOpenConns(1)）：事务占着那唯一的连接时，
	// 这次查询永远等不到它释放，而事务又在等查询返回——整个请求就卡死在
	// 那里。管理后台的表现是「点一下没反应」，日志里什么都没有。
	//
	// 同样先递增版本号：改组会改变生效配额，在途的旧快照必须让路。
	s.Runtime.BumpGuardVer()
	return s.refreshQuotaFor(id)
}

// ListGroups 全部分组。
func (s *Services) ListGroups() ([]model.Group, error) {
	var list []model.Group
	err := s.DB.Order("priority desc, id asc").Find(&list).Error
	return list, err
}

// GroupInput 分组入参。
type GroupInput struct {
	Name                string `json:"name"`
	Description         string `json:"description"`
	MaxTunnels          int    `json:"max_tunnels"`
	MaxPorts            int    `json:"max_ports"`
	TrafficQuota        int64  `json:"traffic_quota"`
	BandwidthLimit      int64  `json:"bandwidth_limit"`
	AllowProtocols      string `json:"allow_protocols"`
	AllowCustomDomain   bool   `json:"allow_custom_domain"`
	AllowPrivilegedPort bool   `json:"allow_privileged_port"`
	Priority            int    `json:"priority"`
}

func (in *GroupInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 32 {
		return fmt.Errorf("%w: 分组名称需为 1-32 个字符", ErrInvalidParam)
	}
	if in.MaxTunnels < 0 || in.MaxPorts < 0 || in.TrafficQuota < 0 || in.BandwidthLimit < 0 {
		return fmt.Errorf("%w: 数值不能为负数", ErrInvalidParam)
	}
	// 协议白名单只接受已知取值，防止脏数据流入插件校验逻辑。
	allowed := map[string]bool{"tcp": true, "udp": true, "http": true, "https": true}
	parts := strings.Split(strings.ToLower(in.AllowProtocols), ",")
	cleaned := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !allowed[p] {
			return fmt.Errorf("%w: 不支持的协议 %q", ErrInvalidParam, p)
		}
		if !seen[p] {
			seen[p] = true
			cleaned = append(cleaned, p)
		}
	}
	if len(cleaned) == 0 {
		return fmt.Errorf("%w: 至少需要允许一种协议", ErrInvalidParam)
	}
	in.AllowProtocols = strings.Join(cleaned, ",")
	return nil
}

// CreateGroup 新建分组。
func (s *Services) CreateGroup(in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	g := &model.Group{
		Name:                in.Name,
		Description:         truncate(in.Description, 200),
		MaxTunnels:          in.MaxTunnels,
		MaxPorts:            in.MaxPorts,
		TrafficQuota:        in.TrafficQuota,
		BandwidthLimit:      in.BandwidthLimit,
		AllowProtocols:      in.AllowProtocols,
		AllowCustomDomain:   in.AllowCustomDomain,
		AllowPrivilegedPort: in.AllowPrivilegedPort,
		Priority:            in.Priority,
	}
	if err := s.DB.Create(g).Error; err != nil {
		return nil, fmt.Errorf("分组名称可能已存在: %w", err)
	}
	return g, nil
}

// UpdateGroup 更新分组，并同步刷新该组所有用户的隧道限速快照。
func (s *Services) UpdateGroup(id uint, in GroupInput) (*model.Group, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	var g model.Group
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		// FOR UPDATE 锁分组行：并发删除分组 / 核销兑换码 / 用户改组都以这一行
		// 为序（见 Redeem 里的锁序说明）。不锁的话，「检查存在 → 更新」之间
		// 分组可能被删，接口返回成功而分组已经没了，隧道限速快照也写进了
		// 一个已删除的分组。
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		updates := map[string]any{
			"name":                  in.Name,
			"description":           truncate(in.Description, 200),
			"max_tunnels":           in.MaxTunnels,
			"max_ports":             in.MaxPorts,
			"traffic_quota":         in.TrafficQuota,
			"bandwidth_limit":       in.BandwidthLimit,
			"allow_protocols":       in.AllowProtocols,
			"allow_custom_domain":   in.AllowCustomDomain,
			"allow_privileged_port": in.AllowPrivilegedPort,
			"priority":              in.Priority,
		}
		res := tx.Model(&model.Group{}).Where("id = ?", id).Updates(updates)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return tx.Model(&model.Tunnel{}).
			Where("user_id IN (?)", tx.Model(&model.User{}).Select("id").Where("group_id = ?", id)).
			Update("bandwidth_limit", in.BandwidthLimit).Error
	})
	if err != nil {
		return nil, err
	}
	if err := s.DB.First(&g, id).Error; err != nil {
		return nil, err
	}

	// 事务提交后刷新该组用户的超额标记。
	//
	// 配额可能被调低（原本没超额的变成超额）或调高（原本超额的可以放行了），
	// 而 Runtime.exceeded 是插件实时拦截的依据。不刷新的话要等下一轮成功
	// 采集才生效——frps 管理接口恰好不可用时，这个标记会一直停在旧值上：
	// 调低配额后用户还能继续建连接，调高配额后用户仍然被拒。
	//
	// 刷新失败要如实返回：分组本身已更新，但整组标记还停在旧值——
	// 把它报成成功，管理员不会知道「调低配额后用户仍能建连接」。
	// 错误信息里点明这一点，管理员重试即可（更新幂等）。
	//
	// 先递增版本号：让在途的旧快照让路，随后的整组读取看到刚提交的新配额。
	s.Runtime.BumpGuardVer()
	if err := s.refreshQuotaForGroup(id); err != nil {
		return &g, fmt.Errorf("分组已更新，但配额标记刷新失败（本组用户将沿用旧标记，重试本操作或等下一轮采集可纠正）: %w", err)
	}
	return &g, nil
}

// refreshQuotaForGroup 刷新某分组下所有用户的超额标记。
//
// 一次查询取出该组全部用户（带分组），而不是逐个 LoadUser：
// 一个分组可能有成百上千个用户，逐个查会把一次管理操作变成一串查询。
//
// 与 refreshQuotaFor 同样的版本协调：版本号在读库之前取，逐个条件写；
// 中途版本被推进（另一笔管理操作/后台刷新）就整组重读重试——否则
// 先发起的旧快照会用旧配额覆盖后完成的新标记。调用方必须已在自己
// 的数据库写入提交之后 BumpGuardVer。
func (s *Services) refreshQuotaForGroup(groupID uint) error {
	const maxPasses = 3
	for pass := 0; pass < maxPasses; pass++ {
		ver := s.Runtime.GuardVer()
		var users []model.User
		if err := s.DB.Preload("Group").Where("group_id = ?", groupID).Find(&users).Error; err != nil {
			// 读取失败必须返回错误：整组标记都停在旧值，调用方不能把这次
			// 操作当成功上报（见 refreshQuotaFor 的说明）。
			return fmt.Errorf("刷新分组 %d 的配额标记失败: %w", groupID, err)
		}
		stable := true
		for i := range users {
			s.EnsureTrafficPeriod(&users[i])
			if !s.Runtime.SetQuotaExceededIfVer(users[i].ID, s.QuotaExceeded(&users[i]), ver) {
				// 版本已推进：本组这一轮的结果基于旧快照，剩下的人
				// 不再写，整组重来（否则同一组里会出现新旧混杂）。
				stable = false
				break
			}
		}
		if stable {
			return nil
		}
	}
	return fmt.Errorf("刷新分组 %d 的配额标记失败：并发调整过于频繁，未能稳定写入", groupID)
}

// DeleteGroup 删除分组。默认分组、仍被占用的分组、仍有未核销升级码的分组
// 不允许删除。
//
// 检查未核销兑换码的原因：GenerateCodes 允许生成指向任意现存分组的升级码，
// 而分组一删，这些码就成了废纸——兑换时按 group_id 找不到分组，
// 返回「兑换码无效」，用户拿着一张永远用不掉的码。管理员删分组时
// 看不到这层关联，必须由这里拦下来：先停用/删除这些码，或迁移到别的分组。
//
// 检查与删除放进同一事务：分开的话，「检查通过 → 删除」之间仍可能插进
// 一次兑换（见 Redeem 里对分组行的 FOR UPDATE），事务至少保证
// 这两个步骤看到的是同一个数据库状态。
func (s *Services) DeleteGroup(id uint) error {
	return s.DB.Transaction(func(tx *gorm.DB) error {
		// FOR UPDATE 锁住分组行：GenerateCodes 与 AdminSetUserGroup 对
		// 同一行加锁（见 Redeem 里的全局锁序说明）。不锁的话，
		// 生成一批升级码或分配用户可以插进「计数检查 → 删除」之间，
		// 检查看到的是旧快照，删掉的分组背后已经挂上了新引用。
		var g model.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&g, id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if g.IsDefault {
			return fmt.Errorf("%w: 默认分组不允许删除", ErrInvalidParam)
		}
		var used int64
		if err := tx.Model(&model.User{}).Where("group_id = ?", id).Count(&used).Error; err != nil {
			return err
		}
		if used > 0 {
			return fmt.Errorf("%w: 仍有 %d 个用户属于该分组，请先迁移", ErrInvalidParam, used)
		}
		// 只看未核销的：已用尽/已停用的码本来就不能再兑换，
		// 指向已删除分组对它们没有影响。
		var pending int64
		if err := tx.Model(&model.RedeemCode{}).
			Where("group_id = ? AND status = ?", id, model.RedeemStatusUnused).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return fmt.Errorf("%w: 还有 %d 张指向该分组的未核销升级码，请先停用或删除它们",
				ErrInvalidParam, pending)
		}
		res := tx.Delete(&model.Group{}, id)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}
