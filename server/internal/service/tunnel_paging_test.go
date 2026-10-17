package service

import (
	"fmt"
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestListTunnelsPage 覆盖「隧道清单游标分页与总数」。
//
// 客户端接入信息接口按 before_id 游标分页：总数必须不受分页影响
// （客户端据此做一致性校验），单页内容按 id 倒序与全量顺序一致。
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

	// 第二页：以第一页第 2 条的 id 为游标（id < 游标）。
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

	// 游标走到最后一条之后：空列表，总数仍然正确。
	empty, total, _, err := svc.ListTunnelsPage(u.ID, all[4].ID, 2)
	if err != nil {
		t.Fatalf("越界分页失败: %v", err)
	}
	if len(empty) != 0 || total != 5 {
		t.Fatalf("游标到底后应为空、总数仍为 5，实际 %d 条 / total=%d", len(empty), total)
	}
}

// TestListTunnelsPageVersionDetectsCompensatingChange 覆盖「数量相抵」的变更。
//
// 分页期间删掉一条**已取到**的隧道、同时新增一条 id 更大的：总数不变，
// 新隧道落在游标之前永远取不到。只比条数发现不了，版本（总数 + 最大 id）
// 必须变化，客户端据此整轮重取。
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

	// 数量相抵：删一条已取到的，再新增一条。
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

// TestListTunnelsPageStableUnderDeletion 覆盖「分页期间删除不导致漏项」。
//
// offset 分页在删除后会跳过一条：删掉第 1 页的某条之后，第 2 页的
// offset 越过了一条本来该返回的记录。游标分页只依赖 id 单调性，
// 删除不会让后面几页漏掉记录。
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

	// 分页期间删掉第一页里的一条（模拟用户同时在网页端删除）。
	if err := svc.DB.Delete(&model.Tunnel{}, first[0].ID).Error; err != nil {
		t.Fatal(err)
	}

	// 按游标取下一页：剩下的两条都必须取到，不能因为删除而漏项。
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
