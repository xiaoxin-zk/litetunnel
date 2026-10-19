package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"gorm.io/gorm"
)

// NewIncarnation 生成账号生命周期标识。
//
// 用密码学随机数而不是 ID 派生：标识的全部意义是「同一个 ID 的两次生命周期
// 必须得到不同的值」，任何可预测或可推导的写法都会把这条保证交还给调用方。
func NewIncarnation() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// 拿不到随机数时宁可让创建失败，也不要写一个可预测的标识——
		// 那会让「ID 复用不影响旧待办」的保证静默失效。
		panic(fmt.Sprintf("生成账号标识失败: %v", err))
	}
	return hex.EncodeToString(buf)
}

// BeforeCreate 在插入账号前补上生命周期标识。
//
// 放在模型钩子里而不是逐个创建路径里赋值：注册、管理端创建、播种和测试
// 都走 Create，任何新增路径都不会漏。显式赋值的（导入、迁移回放）保持原值。
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.Incarnation == "" {
		u.Incarnation = NewIncarnation()
	}
	return nil
}

// BackfillIncarnations 为历史账号补上标识。
//
// 迁移期不能靠 BeforeCreate：那些行早就在库里了。逐行更新而不是一条 SQL，
// 是因为 SQLite 与 PostgreSQL 的随机函数不同，而这段代码要在两种方言下都
// 只跑一次、且失败可重试（幂等：只处理空值）。
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
			if err := db.Model(&User{}).Where("id = ?", id).
				Update("incarnation", NewIncarnation()).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// IncarnationOf 读取账号当前的生命周期标识；账号不存在时返回空串。
//
// 调用方（断流重试）用它判断待办是否还属于当前账号：读不到账号与读到空
// 标识都必须按「不属于」处理，不能退化成「不校验」。
func IncarnationOf(db *gorm.DB, userID uint) (string, error) {
	var u User
	if err := db.Select("id", "incarnation").First(&u, userID).Error; err != nil {
		return "", err
	}
	return u.Incarnation, nil
}
