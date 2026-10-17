package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 兑换码字符集：剔除 0/O、1/I/L 等易混淆字符，降低人工输入错误。
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// 单张兑换码面值的上限。
//
// 不设上限的话，一个手滑的超大 Value 会让兑换后的数值**溢出成负数**：
// 流量配额变负后，EffectiveQuota 把非正值当成「继承分组配额」，
// 超额保护对这个人直接失效。上限必须卡在「加到任何现存值上都不会溢出
// int64」的量级，同时兑换时还会再查一次溢出（老数据里可能已存在
// 超上限的码，见 Redeem）。
const (
	// maxRedeemTrafficValue 单张流量码上限：1 PiB。
	maxRedeemTrafficValue = int64(1) << 50
	// maxRedeemBalanceValue 单张余额码上限：1 亿元（以分为单位）。
	maxRedeemBalanceValue = int64(10_000_000_00)
	// maxRedeemDurationValue 单张时长码上限：100 年（天）。
	maxRedeemDurationValue = int64(36500)
)

// GenerateCodesInput 批量生成入参。
type GenerateCodesInput struct {
	Count    int        `json:"count"`
	Type     string     `json:"type"`
	Value    int64      `json:"value"`
	GroupID  uint       `json:"group_id"`
	MaxUses  int        `json:"max_uses"`
	ExpireAt *time.Time `json:"expire_at"`
	Remark   string     `json:"remark"`
}

// GenerateCodes 批量生成兑换码。
func (s *Services) GenerateCodes(adminID uint, in GenerateCodesInput) ([]model.RedeemCode, error) {
	if in.Count < 1 || in.Count > 500 {
		return nil, fmt.Errorf("%w: 单批生成数量需在 1-500 之间", ErrInvalidParam)
	}
	switch in.Type {
	case model.RedeemTypeTraffic:
		if in.Value <= 0 {
			return nil, fmt.Errorf("%w: 流量值必须大于 0", ErrInvalidParam)
		}
		if in.Value > maxRedeemTrafficValue {
			return nil, fmt.Errorf("%w: 单张流量码上限为 %s", ErrInvalidParam, FormatBytes(maxRedeemTrafficValue))
		}
	case model.RedeemTypeBalance:
		if in.Value <= 0 {
			return nil, fmt.Errorf("%w: 金额必须大于 0", ErrInvalidParam)
		}
		if in.Value > maxRedeemBalanceValue {
			return nil, fmt.Errorf("%w: 单张余额码上限为 %.2f 元", ErrInvalidParam, float64(maxRedeemBalanceValue)/100)
		}
	case model.RedeemTypeGroup:
		if in.GroupID == 0 {
			return nil, fmt.Errorf("%w: 升级分组必须指定目标分组", ErrInvalidParam)
		}
		// 分组存在性检查移到了下面的写事务里（对分组行 FOR UPDATE）：
		// 事务外检查、稍后才插入码的话，删除分组可能从检查通过之后
		// 插进来，生成一批指向已删除分组的码——又是废纸。
	case model.RedeemTypeDuration:
		if in.Value <= 0 {
			return nil, fmt.Errorf("%w: 天数必须大于 0", ErrInvalidParam)
		}
		if in.Value > maxRedeemDurationValue {
			return nil, fmt.Errorf("%w: 单张时长码上限为 %d 天", ErrInvalidParam, maxRedeemDurationValue)
		}
	default:
		return nil, fmt.Errorf("%w: 不支持的兑换码类型", ErrInvalidParam)
	}
	if in.MaxUses <= 0 {
		in.MaxUses = 1
	}

	// 批次号带随机后缀：秒级时间戳在同一秒内两次生成会撞号，而管理页
	// 正是按批次号筛选的——两批码混在一个批次里，批次维度就失去了意义。
	// 6 个随机十六进制字符（crypto/rand），同秒撞上 2^24 分之一的概率
	// 在这里完全可以接受；即便真撞了也只是批次展示合并，不影响兑换。
	suffix, err := randomHex(3)
	if err != nil {
		return nil, err
	}
	batchNo := fmt.Sprintf("B%s-%s", time.Now().Format("20060102150405"), suffix)
	codes := make([]model.RedeemCode, 0, in.Count)
	seen := make(map[string]struct{}, in.Count)
	for len(codes) < in.Count {
		code, err := newCode()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[code]; dup {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, model.RedeemCode{
			Code:      code,
			BatchNo:   batchNo,
			Type:      in.Type,
			Value:     in.Value,
			GroupID:   in.GroupID,
			MaxUses:   in.MaxUses,
			Status:    model.RedeemStatusUnused,
			ExpireAt:  in.ExpireAt,
			CreatedBy: adminID,
			Remark:    truncate(in.Remark, 200),
		})
	}

	// 分组升级码：分组存在性检查与写码放进同一事务，并对分组行 FOR UPDATE
	// ——与 DeleteGroup、AdminSetUserGroup 用同一把分组行锁互斥。
	// 不锁的话，删除分组可以插进「检查通过 → 插入码」之间，
	// 生成一批指向已删除分组的码；锁住行之后，删除会等到本事务提交，
	// 提交后那批码是未核销状态，DeleteGroup 的检查会拦住它。
	if in.Type == model.RedeemTypeGroup {
		err := s.DB.Transaction(func(tx *gorm.DB) error {
			var g model.Group
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&g, in.GroupID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("%w: 目标分组不存在", ErrInvalidParam)
				}
				return err
			}
			return tx.Create(&codes).Error
		})
		if err != nil {
			return nil, err
		}
		return codes, nil
	}

	// 唯一索引冲突时整批回滚，避免生成半截数据。
	if err := s.DB.Create(&codes).Error; err != nil {
		return nil, fmt.Errorf("生成兑换码失败: %w", err)
	}
	return codes, nil
}

// RedeemResult 兑换结果。
type RedeemResult struct {
	Type    string `json:"type"`
	Value   int64  `json:"value"`
	Message string `json:"message"`
}

// Redeem 用户兑换。全部校验与写入在同一事务内完成，防止并发重复兑换。
func (s *Services) Redeem(userID uint, code, ip string) (*RedeemResult, error) {
	code = normalizeCode(code)
	if code == "" {
		return nil, ErrCodeInvalid
	}

	var result RedeemResult
	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var c model.RedeemCode
		err := tx.Where("code = ?", code).First(&c).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 这里**不**写审计：这条记录会随事务一起回滚，写了等于没写。
			// 无效尝试统一在事务之外补记（见下面的 err 分支）。
			return ErrCodeInvalid
		}
		if err != nil {
			return err
		}

		switch c.Status {
		case model.RedeemStatusDisabled:
			return ErrCodeDisabled
		case model.RedeemStatusUsedUp:
			return ErrCodeUsed
		}
		if c.ExpireAt != nil && c.ExpireAt.Before(time.Now()) {
			return ErrCodeExpired
		}
		if c.MaxUses > 0 && c.UsedCount >= c.MaxUses {
			return ErrCodeUsed
		}

		// ---- 抢占核销权 ----
		//
		// 用条件更新（CAS）而不是「先读后写」。并发下多个事务会同时读到
		// UsedCount 的同一个旧值，若各自在 Go 里算 newUsed 再写回，就会丢失更新
		// —— 表现为一次兑换码被核销多次。
		//
		// 把「校验上限 + 自增」合并成一条带条件的 UPDATE 后，由数据库保证
		// 只有一个事务能让 RowsAffected=1，其余全部为 0。
		// 这比 SELECT ... FOR UPDATE 更轻：没有显式锁，也不依赖隔离级别。
		//
		// 这一步必须在发放权益**之前**：抢不到就直接返回错误、事务回滚，
		// 不会出现「没抢到却已经加了流量」这种脏状态。
		claim := tx.Model(&model.RedeemCode{}).
			Where("id = ? AND status = ? AND (max_uses <= 0 OR used_count < max_uses)",
				c.ID, model.RedeemStatusUnused).
			Update("used_count", gorm.Expr("used_count + 1"))
		if claim.Error != nil {
			return claim.Error
		}
		if claim.RowsAffected == 0 {
			// 已被别人抢走、或用尽、或已停用。
			return ErrCodeUsed
		}

		// 抢到后若已达上限，标记为用尽。条件更新，重复执行无副作用。
		if err := tx.Model(&model.RedeemCode{}).
			Where("id = ? AND max_uses > 0 AND used_count >= max_uses", c.ID).
			Update("status", model.RedeemStatusUsedUp).Error; err != nil {
			return err
		}

		// ---- 锁住用户行（全局锁序：用户行 → 分组行）----
		//
		// 配额、余额、有效期都是「读快照 → 覆盖写回」，而码的 CAS 只保护
		// UsedCount：同一用户并发兑换两张流量码时，两个事务会读到同一个
		// 旧配额，各自写回「旧值 + 自己那张」——两张码都被核销，
		// 权益只多了一份（丢失更新）。
		//
		// FOR UPDATE 让同一用户的权益变更在此串行：后来者读到的一定是
		// 前者提交后的值。SQLite 单连接天然串行（锁子句是空操作）；
		// Postgres 下真正生效。
		//
		// 先用户后分组的顺序与 AdminSetUserGroup 一致；反过来
		// （分组 → 用户）的话，「改分组」与「兑换」交叉等待会成死锁。
		var u model.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&u, userID).Error; err != nil {
			return ErrNotFound
		}

		updates := map[string]any{}
		switch c.Type {
		case model.RedeemTypeTraffic:
			// 若用户此前继承分组配额，则以「分组配额 + 兑换值」作为显式配额。
			base := u.TrafficQuota
			if base == 0 {
				var g model.Group
				if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
					First(&g, u.GroupID).Error; err == nil {
					base = g.TrafficQuota
				}
			}
			// 溢出检查：负的配额会被 EffectiveQuota 当成「继承分组配额」，
			// 超额保护直接失效。生成侧已有面值上限，这里兜住老数据里
			// 可能存在的超上限码。
			if c.Value > math.MaxInt64-base {
				return fmt.Errorf("%w: 流量额度已达上限，无法再兑换这张码", ErrCodeInvalid)
			}
			updates["traffic_quota"] = base + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("流量额度已增加 %s", FormatBytes(c.Value))}

		case model.RedeemTypeBalance:
			if c.Value > math.MaxInt64-u.Balance {
				return fmt.Errorf("%w: 余额已达上限，无法再兑换这张码", ErrCodeInvalid)
			}
			updates["balance"] = u.Balance + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("余额已增加 %.2f 元", float64(c.Value)/100)}

		case model.RedeemTypeGroup:
			// FOR UPDATE 锁住分组行（锁序 user → group）：与 DeleteGroup
			// 的事务互斥。不锁的话有个窄窗口——这里读到分组存在，删除分组
			// 随后提交，我们再把 group_id 写上去：用户拿到一个指向已删除
			// 分组的悬空引用，运行期只能回落到默认分组，界面上却显示
			// 「已升级」。Postgres 下 FOR UPDATE 会让 DeleteGroup 的删除
			// 等到本事务提交；SQLite 全库锁，天然串行。分组确实已删时
			// 仍按「码无效」处理，核销随事务回滚，码还能用。
			var g model.Group
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&g, c.GroupID).Error; err != nil {
				return ErrCodeInvalid
			}
			updates["group_id"] = g.ID
			// 升级分组时同步刷新该用户所有隧道的限速快照。
			if err := tx.Model(&model.Tunnel{}).Where("user_id = ?", u.ID).
				Update("bandwidth_limit", g.BandwidthLimit).Error; err != nil {
				return err
			}
			result = RedeemResult{Type: c.Type, Value: int64(g.ID),
				Message: fmt.Sprintf("已升级到分组「%s」", g.Name)}

		case model.RedeemTypeDuration:
			// 从「现有到期时间」顺延：读的是加锁后的最新快照，
			// 并发兑换多张时长码时依次叠加，不会互相覆盖。
			base := time.Now()
			if u.GroupExpireAt != nil && u.GroupExpireAt.After(base) {
				base = *u.GroupExpireAt
			}
			updates["group_expire_at"] = base.AddDate(0, 0, int(c.Value))
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("分组有效期已延长 %d 天", c.Value)}

		default:
			return ErrCodeInvalid
		}

		if err := tx.Model(&model.User{}).Where("id = ?", u.ID).Updates(updates).Error; err != nil {
			return err
		}

		// 核销计数已在前面用 CAS 完成，这里不再写 used_count，
		// 否则又会退回「读-改-写」的老问题。
		//
		// 流水与权益必须同生共死：写不进去就整体回滚。忽略这个错误的话，
		// 会出现「权益已发放但查不到流水」——事后对不上账，且无从追查。
		return s.recordRedeem(tx, userID, c.ID, code, c.Type, c.Value, "success", ip)
	})
	if err != nil {
		// 无效兑换码在事务之外补一条审计。
		//
		// 这类尝试是风控最关心的信号（有人在撞码），而它原先写在事务里，
		// 紧接着就随回滚消失了——等于从来没记录过。
		if errors.Is(err, ErrCodeInvalid) {
			_ = s.recordRedeem(s.DB, userID, 0, code, "", 0, "invalid", ip)
		}
		return nil, err
	}

	// 兑换成功后立刻重算运行时的超额标记。
	//
	// 这个标记是插件实时拦截的依据，平时靠流量采集刷新。而兑换（加流量、
	// 换分组、延长有效期）恰恰是为了让已经超额的账号重新能用——如果 frps
	// 管理接口恰好不可用，采集刷不动，用户就会看到「兑换成功了，但连接
	// 依然被拒」，而且等多久都不会恢复。
	s.refreshQuotaFor(userID)
	return &result, nil
}

// recordRedeem 写一条兑换流水。
//
// 返回错误而不是吞掉：成功兑换那条流水必须与权益同一个事务，
// 写不进去就得整体回滚——否则权益发放了却查不到记录，事后对不上账。
func (s *Services) recordRedeem(tx *gorm.DB, userID, codeID uint, code, rtype string, value int64, result, ip string) error {
	return tx.Create(&model.RedeemRecord{
		UserID: userID,
		CodeID: codeID,
		Code:   code,
		Type:   rtype,
		Value:  value,
		Result: result,
		IP:     ip,
	}).Error
}

// ListRedeemCodes 分页查询兑换码。
func (s *Services) ListRedeemCodes(keyword, status, batchNo string, offset, limit int) ([]model.RedeemCode, int64, error) {
	q := s.DB.Model(&model.RedeemCode{})
	if keyword != "" {
		q = q.Where("code LIKE ?", "%"+strings.ToUpper(keyword)+"%")
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if batchNo != "" {
		q = q.Where("batch_no = ?", batchNo)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.RedeemCode
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

// SetRedeemCodeStatus 禁用/启用兑换码。
func (s *Services) SetRedeemCodeStatus(id uint, status string) error {
	if status != model.RedeemStatusDisabled && status != model.RedeemStatusUnused {
		return ErrInvalidParam
	}
	res := s.DB.Model(&model.RedeemCode{}).Where("id = ?", id).Update("status", status)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteRedeemCode 删除兑换码（已使用的保留流水，仅删除码本身）。
func (s *Services) DeleteRedeemCode(id uint) error {
	res := s.DB.Where("id = ?", id).Delete(&model.RedeemCode{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ListRedeemRecords 分页查询兑换流水。
func (s *Services) ListRedeemRecords(userID uint, offset, limit int) ([]model.RedeemRecord, int64, error) {
	q := s.DB.Model(&model.RedeemRecord{})
	if userID > 0 {
		q = q.Where("user_id = ?", userID)
	}
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var list []model.RedeemRecord
	err := q.Order("id desc").Offset(offset).Limit(limit).Find(&list).Error
	return list, total, err
}

func newCode() (string, error) {
	groups := make([]string, 3)
	for g := 0; g < 3; g++ {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		var sb strings.Builder
		for _, b := range buf {
			sb.WriteByte(codeAlphabet[int(b)%len(codeAlphabet)])
		}
		groups[g] = sb.String()
	}
	return "LT-" + strings.Join(groups, "-"), nil
}

// normalizeCode 统一大小写与分隔符，容忍用户输入时的空格与大小写差异。
func normalizeCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "LT-") {
		if len(s) == 12 {
			s = "LT-" + s[:4] + "-" + s[4:8] + "-" + s[8:]
		}
	}
	return s
}
