package service

import (
	"errors"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

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

	var cnt int64
	if err := svc.DB.Model(&model.User{}).Where("username = ?", "ghostgroup").Count(&cnt).Error; err != nil {
		t.Fatal(err)
	}
	if cnt != 0 {
		t.Fatalf("创建失败后用户记录不应残留，库里仍有 %d 条", cnt)
	}
}
