package service

import (
	"fmt"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestListTunnelsPage 覆盖「隧道清单分页与总数」。
//
// 客户端接入信息接口按 offset/limit 分页返回：总数必须不受分页影响
// （客户端据此判断还有没有下一页），单页内容按 id 倒序与不分页时一致。
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

	// 不分页：全部返回，总数一致。
	all, total, err := svc.ListTunnelsPage(u.ID, 0, 0)
	if err != nil {
		t.Fatalf("取全部失败: %v", err)
	}
	if total != 5 || len(all) != 5 {
		t.Fatalf("不分页应返回 5 条（total=%d），实际 %d 条", total, len(all))
	}

	// 第二页：offset=2、limit=2。
	page, total, err := svc.ListTunnelsPage(u.ID, 2, 2)
	if err != nil {
		t.Fatalf("分页失败: %v", err)
	}
	if total != 5 {
		t.Fatalf("总数不应受分页影响，实际 %d", total)
	}
	if len(page) != 2 {
		t.Fatalf("单页应有 2 条，实际 %d", len(page))
	}
	// 倒序排列：第一页是 id 最大的两条，第二页接下去。
	if page[0].ID != all[2].ID || page[1].ID != all[3].ID {
		t.Fatalf("分页内容应与全量顺序一致：实际 %d,%d（期望 %d,%d）",
			page[0].ID, page[1].ID, all[2].ID, all[3].ID)
	}

	// 越界页：返回空列表，但总数仍然正确。
	empty, total, err := svc.ListTunnelsPage(u.ID, 10, 2)
	if err != nil {
		t.Fatalf("越界分页失败: %v", err)
	}
	if len(empty) != 0 || total != 5 {
		t.Fatalf("越界页应为空、总数仍为 5，实际 %d 条 / total=%d", len(empty), total)
	}
}

// TestListTunnelsPageIsolatedByUser 覆盖「分页不串号」。
func TestListTunnelsPageIsolatedByUser(t *testing.T) {
	svc := newTestServices(t, nil)

	mk := func(name string, n int) *model.User {
		t.Helper()
		u := &model.User{Username: name, Password: "not-used", Status: model.UserStatusActive}
		if err := svc.DB.Create(u).Error; err != nil {
			t.Fatalf("建用户失败: %v", err)
		}
		for i := 0; i < n; i++ {
			tun := &model.Tunnel{
				UserID: u.ID, Name: fmt.Sprintf("%s-%d", name, i), Type: model.ProxyTypeTCP,
				LocalIP: "127.0.0.1", LocalPort: 30000 + i, RemotePort: 21000 + i,
			}
			if err := svc.DB.Create(tun).Error; err != nil {
				t.Fatalf("建隧道失败: %v", err)
			}
		}
		return u
	}
	u1 := mk("u1", 2)
	mk("u2", 3)

	page, total, err := svc.ListTunnelsPage(u1.ID, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(page) != 2 {
		t.Fatalf("只应取到自己那 2 条，实际 %d 条 / total=%d", len(page), total)
	}
	for _, tun := range page {
		if tun.UserID != u1.ID {
			t.Fatalf("分页结果串到了别的用户: %+v", tun)
		}
	}
}
