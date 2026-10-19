package service

import (
	"fmt"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestListTunnelsPage(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "paging", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	for i := 0; i < 5; i++ {
		tun := &model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("t%d", i), Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 25565 + i, RemotePort: 20000 + i,
			Status: model.TunnelStatusActive,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}

	all, total, version, err := svc.ListTunnelsPage(u.ID, 0, 0)
	if err != nil {
		t.Fatalf("取全部失败: %v", err)
	}
	if total != 5 || len(all) != 5 {
		t.Fatalf("不分页应返回 5 条（total=%d），实际 %d 条", total, len(all))
	}
	if version == "" {
		t.Fatal("应返回清单版本，供客户端跨页校验")
	}

	page, total, version2, err := svc.ListTunnelsPage(u.ID, all[1].ID, 2)
	if err != nil {
		t.Fatalf("分页失败: %v", err)
	}
	if total != 5 {
		t.Fatalf("总数不应受分页影响，实际 %d", total)
	}
	if version2 != version {
		t.Fatalf("清单未变时版本应一致：%s != %s", version2, version)
	}
	if len(page) != 2 {
		t.Fatalf("单页应有 2 条，实际 %d", len(page))
	}
	if page[0].ID != all[2].ID || page[1].ID != all[3].ID {
		t.Fatalf("游标分页内容应与全量顺序一致：实际 %d,%d（期望 %d,%d）",
			page[0].ID, page[1].ID, all[2].ID, all[3].ID)
	}

	empty, total, _, err := svc.ListTunnelsPage(u.ID, all[4].ID, 2)
	if err != nil {
		t.Fatalf("越界分页失败: %v", err)
	}
	if len(empty) != 0 || total != 5 {
		t.Fatalf("游标到底后应为空、总数仍为 5，实际 %d 条 / total=%d", len(empty), total)
	}
}

func TestListTunnelsPageVersionDetectsCompensatingChange(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "pagever", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	for i := 0; i < 4; i++ {
		tun := &model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("t%d", i), Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 27000 + i, RemotePort: 23000 + i,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}

	first, total1, version1, err := svc.ListTunnelsPage(u.ID, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || total1 != 4 {
		t.Fatalf("前置条件不满足：%d 条 / total=%d", len(first), total1)
	}

	if err := svc.DB.Delete(&model.Tunnel{}, first[0].ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DB.Create(&model.Tunnel{
		UserID: u.ID, Name: "new", Type: model.ProxyTypeTCP,
		LocalIP: "127.0.0.1", LocalPort: 27009, RemotePort: 23009,
	}).Error; err != nil {
		t.Fatal(err)
	}

	_, total2, version2, err := svc.ListTunnelsPage(u.ID, first[len(first)-1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total2 != total1 {
		t.Fatalf("本用例构造的是数量相抵（total 不变），实际 %d → %d", total1, total2)
	}
	if version2 == version1 {
		t.Fatal("版本必须变化，否则客户端发现不了漏项")
	}
}

func TestListTunnelsPageVersionTracksStatusAndEdit(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "pagever2", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	tun := &model.Tunnel{
		UserID: u.ID, Name: "t", Type: model.ProxyTypeTCP, LocalIP: "127.0.0.1",
		LocalPort: 25565, RemotePort: 24000, Status: model.TunnelStatusActive,
	}
	if err := svc.DB.Create(tun).Error; err != nil {
		t.Fatalf("建隧道失败: %v", err)
	}

	verOf := func() string {
		t.Helper()
		_, _, v, err := svc.ListTunnelsPage(u.ID, 0, 10)
		if err != nil {
			t.Fatalf("取版本失败: %v", err)
		}
		return v
	}

	v1 := verOf()

	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("status", model.TunnelStatusDisabled).Error; err != nil {
		t.Fatal(err)
	}
	v2 := verOf()
	if v2 == v1 {
		t.Fatal("状态变更必须反映到清单版本，否则多页同步会按旧状态对账")
	}

	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("remote_port", 24001).Error; err != nil {
		t.Fatal(err)
	}
	v3 := verOf()
	if v3 == v2 {
		t.Fatal("配置变更必须反映到清单版本")
	}

	if err := svc.DB.Model(&model.Tunnel{}).Where("id = ?", tun.ID).
		Update("traffic_used", 12345).Error; err != nil {
		t.Fatal(err)
	}
	if v4 := verOf(); v4 != v3 {
		t.Fatal("采集字段变更不应改变清单版本（会让多页同步被无谓打断）")
	}
}

func TestListTunnelsPageStableUnderDeletion(t *testing.T) {
	svc := newTestServices(t, nil)

	u := &model.User{Username: "pagedel", Password: "not-used", Status: model.UserStatusActive}
	if err := svc.DB.Create(u).Error; err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	for i := 0; i < 4; i++ {
		tun := &model.Tunnel{
			UserID: u.ID, Name: fmt.Sprintf("t%d", i), Type: model.ProxyTypeTCP,
			LocalIP: "127.0.0.1", LocalPort: 26000 + i, RemotePort: 22000 + i,
		}
		if err := svc.DB.Create(tun).Error; err != nil {
			t.Fatalf("建隧道失败: %v", err)
		}
	}

	first, _, _, err := svc.ListTunnelsPage(u.ID, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 {
		t.Fatalf("第一页应有 2 条，实际 %d", len(first))
	}

	if err := svc.DB.Delete(&model.Tunnel{}, first[0].ID).Error; err != nil {
		t.Fatal(err)
	}

	rest, _, _, err := svc.ListTunnelsPage(u.ID, first[len(first)-1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 2 {
		t.Fatalf("删除不应让后续页漏项：应取到 2 条，实际 %d 条", len(rest))
	}
	if rest[0].ID != 2 || rest[1].ID != 1 {
		t.Fatalf("后续页顺序应按 id 倒序，实际 %d,%d", rest[0].ID, rest[1].ID)
	}
}
