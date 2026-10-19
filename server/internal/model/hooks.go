package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gorm.io/gorm"
)

func NewIncarnation() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(fmt.Sprintf("生成账号标识失败: %v", err))
	}
	return hex.EncodeToString(buf)
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.Incarnation == "" {
		u.Incarnation = NewIncarnation()
	}
	return nil
}

func BackfillIncarnations(db *gorm.DB) error {
	var ids []uint
	if err := db.Model(&User{}).
		Where("incarnation IS NULL OR incarnation = ''").
		Pluck("id", &ids).Error; err != nil {
		return err
	}
	for start := 0; start < len(ids); start += 200 {
		end := start + 200
		if end > len(ids) {
			end = len(ids)
		}
		for _, id := range ids[start:end] {
			if err := db.Model(&User{}).
				Where("id = ? AND (incarnation IS NULL OR incarnation = '')", id).
				Update("incarnation", NewIncarnation()).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func IncarnationOf(db *gorm.DB, userID uint) (string, error) {
	var u User
	if err := db.Select("id", "incarnation").First(&u, userID).Error; err != nil {
		return "", err
	}
	return u.Incarnation, nil
}
