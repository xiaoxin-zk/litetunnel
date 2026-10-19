package service

import (
	"errors"
	"log"
	"strings"
	"time"

	"gorm.io/gorm/clause"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const stepUpGrantTTL = 15 * time.Minute

var (
	ErrStepUpTOTPNotEnabled = errors.New("该账号尚未启用双因素认证，无法完成二次验证")
	ErrStepUpNoSession      = errors.New("登录状态已失效，请重新登录后再试")
)

// StepUpEnabled 读取敏感操作二次验证开关，默认关闭。
func (s *Services) StepUpEnabled() bool {
	return s.Settings.Bool(KeyStepUpEnabled)
}

// HasStepUpGrant 判断当前会话是否在有效期内通过过二次验证。
// 查询失败按未授权处理（fail-closed），避免数据库异常时反而放行高危操作。
func (s *Services) HasStepUpGrant(adminID uint, sessionKey string) bool {
	if adminID == 0 || sessionKey == "" {
		return false
	}
	var n int64
	err := s.DB.Model(&model.StepUpGrant{}).
		Where("admin_id = ? AND session_key = ? AND expires_at > ?", adminID, sessionKey, time.Now()).
		Count(&n).Error
	if err != nil {
		log.Printf("[stepup] 查询授权状态失败（管理员 %d），按未授权处理: %v", adminID, err)
		return false
	}
	return n > 0
}

// VerifyAdminStepUp 校验动态口令并写入会话级授权，返回授权到期时间。
// 口令沿用全站防重放：同一个时间步只能使用一次。
func (s *Services) VerifyAdminStepUp(adminID uint, code, sessionKey string) (time.Time, error) {
	if adminID == 0 || strings.TrimSpace(sessionKey) == "" {
		return time.Time{}, ErrStepUpNoSession
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return time.Time{}, ErrInvalidParam
	}

	var a model.Admin
	if err := s.DB.First(&a, adminID).Error; err != nil {
		return time.Time{}, err
	}
	if !a.TOTPEnabled || a.TOTPSecret == "" {
		return time.Time{}, ErrStepUpTOTPNotEnabled
	}
	step, ok := auth.VerifyTOTPStep(a.TOTPSecret, code, time.Now())
	if !ok {
		return time.Time{}, ErrTOTPInvalid
	}
	if !s.ClaimTOTPStep(a.ID, step) {
		return time.Time{}, ErrTOTPReplay
	}

	expires := time.Now().Add(stepUpGrantTTL)
	row := model.StepUpGrant{AdminID: a.ID, SessionKey: sessionKey, ExpiresAt: expires}
	if err := s.DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "admin_id"}, {Name: "session_key"}},
		DoUpdates: clause.AssignmentColumns([]string{"expires_at"}),
	}).Create(&row).Error; err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

// DropStepUpGrant 吊销某管理员全部会话的二次验证授权（改密、重置 TOTP 时调用）。
func (s *Services) DropStepUpGrant(adminID uint) {
	if adminID == 0 {
		return
	}
	if err := s.DB.Where("admin_id = ?", adminID).Delete(&model.StepUpGrant{}).Error; err != nil {
		log.Printf("[stepup] 清理管理员 %d 的授权失败: %v", adminID, err)
	}
}

// PurgeExpiredStepUpGrants 由维护任务调用，清掉过期授权行。
func (s *Services) PurgeExpiredStepUpGrants(now time.Time) {
	if err := s.DB.Where("expires_at < ?", now).Delete(&model.StepUpGrant{}).Error; err != nil {
		log.Printf("[cleanup] 清理过期二次验证授权失败: %v", err)
	}
}
