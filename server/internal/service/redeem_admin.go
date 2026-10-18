package service

// 兑换码管理：生成、查询、启停与删除。
//
// 与用户核销事务（redeem.go）分开：前者是管理员操作，后者要保证
// 并发下的权益一致性，两者的失败处理与审查重点不同。

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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
