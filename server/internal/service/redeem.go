package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 兑换码字符集：剔除 0/O、1/I/L 等易混淆字符，降低人工输入错误。
const codeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

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
	case model.RedeemTypeBalance:
		if in.Value <= 0 {
			return nil, fmt.Errorf("%w: 金额必须大于 0", ErrInvalidParam)
		}
	case model.RedeemTypeGroup:
		if in.GroupID == 0 {
			return nil, fmt.Errorf("%w: 升级分组必须指定目标分组", ErrInvalidParam)
		}
		var cnt int64
		if err := s.DB.Model(&model.Group{}).Where("id = ?", in.GroupID).Count(&cnt).Error; err != nil {
			return nil, err
		}
		if cnt == 0 {
			return nil, fmt.Errorf("%w: 目标分组不存在", ErrInvalidParam)
		}
	case model.RedeemTypeDuration:
		if in.Value <= 0 {
			return nil, fmt.Errorf("%w: 天数必须大于 0", ErrInvalidParam)
		}
	default:
		return nil, fmt.Errorf("%w: 不支持的兑换码类型", ErrInvalidParam)
	}
	if in.MaxUses <= 0 {
		in.MaxUses = 1
	}

	batchNo := fmt.Sprintf("B%s", time.Now().Format("20060102150405"))
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
			s.recordRedeem(tx, userID, 0, code, "", 0, "invalid", ip)
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

		var u model.User
		if err := tx.First(&u, userID).Error; err != nil {
			return ErrNotFound
		}

		updates := map[string]any{}
		switch c.Type {
		case model.RedeemTypeTraffic:
			// 若用户此前继承分组配额，则以「分组配额 + 兑换值」作为显式配额。
			base := u.TrafficQuota
			if base == 0 {
				var g model.Group
				if err := tx.First(&g, u.GroupID).Error; err == nil {
					base = g.TrafficQuota
				}
			}
			updates["traffic_quota"] = base + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("流量额度已增加 %s", FormatBytes(c.Value))}

		case model.RedeemTypeBalance:
			updates["balance"] = u.Balance + c.Value
			result = RedeemResult{Type: c.Type, Value: c.Value,
				Message: fmt.Sprintf("余额已增加 %.2f 元", float64(c.Value)/100)}

		case model.RedeemTypeGroup:
			var g model.Group
			if err := tx.First(&g, c.GroupID).Error; err != nil {
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

		newUsed := c.UsedCount + 1
		codeUpdates := map[string]any{"used_count": newUsed}
		if c.MaxUses > 0 && newUsed >= c.MaxUses {
			codeUpdates["status"] = model.RedeemStatusUsedUp
		}
		if err := tx.Model(&model.RedeemCode{}).Where("id = ?", c.ID).Updates(codeUpdates).Error; err != nil {
			return err
		}

		s.recordRedeem(tx, userID, c.ID, code, c.Type, c.Value, "success", ip)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Services) recordRedeem(tx *gorm.DB, userID, codeID uint, code, rtype string, value int64, result, ip string) {
	_ = tx.Create(&model.RedeemRecord{
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
