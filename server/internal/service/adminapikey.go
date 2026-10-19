package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const (
	AdminAPIKeyPrefix = "ltadm_"
	AdminKeyScopeRead = "read"
)

type AdminAPIKeyInput struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expires_in_days"`
}

type AdminAPIKeyView struct {
	ID         uint       `json:"id"`
	Name       string     `json:"name"`
	Masked     string     `json:"masked"`
	Scope      string     `json:"scope"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func maskAdminKey(prefix string) string {
	if prefix == "" {
		return AdminAPIKeyPrefix + "****"
	}
	return AdminAPIKeyPrefix + prefix + strings.Repeat("*", 8)
}

// CreateAdminAPIKey 生成只读 Key，明文只在此刻返回一次。
func (s *Services) CreateAdminAPIKey(creatorID uint, in AdminAPIKeyInput) (string, AdminAPIKeyView, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "外部集成"
	}
	if len([]rune(name)) > 64 {
		return "", AdminAPIKeyView{}, fmt.Errorf("%w: Key 名称不能超过 64 字", ErrInvalidParam)
	}
	if in.ExpiresInDays < 0 || in.ExpiresInDays > 3650 {
		return "", AdminAPIKeyView{}, fmt.Errorf("%w: 有效期需为 0-3650 天（0 表示长期有效）", ErrInvalidParam)
	}

	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", AdminAPIKeyView{}, err
	}
	body := hex.EncodeToString(raw)
	prefix := body[:8]
	plain := AdminAPIKeyPrefix + prefix + "_" + body

	row := model.AdminAPIKey{
		Name:      name,
		Prefix:    prefix,
		KeyHash:   auth.HashAPIKey(plain),
		Scope:     AdminKeyScopeRead,
		CreatedBy: creatorID,
	}
	if in.ExpiresInDays > 0 {
		exp := time.Now().AddDate(0, 0, in.ExpiresInDays)
		row.ExpiresAt = &exp
	}
	if err := s.DB.Create(&row).Error; err != nil {
		return "", AdminAPIKeyView{}, err
	}
	return plain, adminKeyView(row), nil
}

func adminKeyView(row model.AdminAPIKey) AdminAPIKeyView {
	return AdminAPIKeyView{
		ID: row.ID, Name: row.Name, Masked: maskAdminKey(row.Prefix), Scope: row.Scope,
		LastUsedAt: row.LastUsedAt, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt,
	}
}

func (s *Services) ListAdminAPIKeys() ([]AdminAPIKeyView, error) {
	var rows []model.AdminAPIKey
	if err := s.DB.Order("id DESC").Find(&rows).Error; err != nil {
		return nil, err
	}
	views := make([]AdminAPIKeyView, 0, len(rows))
	for _, r := range rows {
		views = append(views, adminKeyView(r))
	}
	return views, nil
}

func (s *Services) RevokeAdminAPIKey(id uint) error {
	res := s.DB.Delete(&model.AdminAPIKey{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ResolveAdminAPIKey 供只读接口组鉴权：命中后返回创建者身份，便于审计追责。
func (s *Services) ResolveAdminAPIKey(plain string) (uint, string, string, bool) {
	plain = strings.TrimSpace(plain)
	if !strings.HasPrefix(plain, AdminAPIKeyPrefix) {
		return 0, "", "", false
	}
	var row model.AdminAPIKey
	err := s.DB.Where("key_hash = ?", auth.HashAPIKey(plain)).First(&row).Error
	if err != nil {
		return 0, "", "", false
	}
	if row.ExpiresAt != nil && time.Now().After(*row.ExpiresAt) {
		return 0, "", "", false
	}
	if row.Scope != AdminKeyScopeRead {
		return 0, "", "", false
	}
	now := time.Now()
	if err := s.DB.Model(&model.AdminAPIKey{}).Where("id = ?", row.ID).
		Update("last_used_at", now).Error; err != nil {
		log.Printf("[admin-key] 更新 Key %d 最近使用时间失败: %v", row.ID, err)
	}
	return row.CreatedBy, row.Name, row.Scope, true
}
