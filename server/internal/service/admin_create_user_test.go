package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// 这个文件守的是「管理员创建用户的分组赋值」：
//
//  1. 用户插入与分组赋值在同一事务——分组赋值失败时用户记录不能残留
//     （原先分两步，第二步失败接口报错、库里已经多了个半成品账号，
//     管理员重试会撞「用户名已存在」）；
//  2. 分组赋值前对分组行 FOR UPDATE——与其他动分组的路径（DeleteGroup、
//     AdminSetUserGroup、Redeem）互斥，并发删除分组时写不出悬空 group_id。
//     并发本身无法在 SQLite 单连接下复现，这里验证的是行为语义：
//     指向已删除/不存在分组的赋值必须被拒绝。

func TestAdminCreateUserAssignsGroupAndRemark(t *testing.T) {
	svc := newTestServices(t, nil)

	g := &model.Group{Name: "vip3", AllowProtocols: "tcp"}
	if err := svc.DB.Create(g).Error; err != nil {
		t.Fatalf("建分组失败: %v", err)
	}

	u, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "newadminuser", Email: "newadminuser@example.com",
		Password: "Str0ng-Passw0rd!", GroupID: g.ID, Remark: "后台建的号",
	})
	if err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	if u.GroupID != g.ID {
		t.Fatalf("分组应被赋值，实际 %d（期望 %d）", u.GroupID, g.ID)
	}
	if u.Remark != "后台建的号" {
		t.Fatalf("备注应被写入，实际 %q", u.Remark)
	}
}

func TestAdminCreateUserRejectsMissingGroupWithoutResidue(t *testing.T) {
	svc := newTestServices(t, nil)

	_, err := svc.AdminCreateUser(AdminCreateUserInput{
		Username: "ghostgroup", Email: "ghostgroup@example.com",
		Password: "Str0ng-Passw0rd!", GroupID: 99999,
	})
	if !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("指向不存在分组的创建应被拒绝，实际 %v", err)
	}

	// 关键断言：用户记录不能残留。残留的后果是管理员重试撞「用户名已存在」，
	// 且库里留下一个分组、备注都不对的半成品账号。
	var cnt int64
	if err := svc.DB.Model(&model.User{}).Where("username = ?", "ghostgroup").Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("创建失败后用户记录不应残留，库里仍有 %d 条", cnt)
	}
}
