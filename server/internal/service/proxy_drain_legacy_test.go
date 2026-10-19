package service

import (
	"context"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func TestLegacyPendingWithoutIncarnationMarkedManual(t *testing.T) {
	svc := newTestServices(t, nil)
	u := newLifecycleUser(t, svc, "legacy-drain")

	name := FrpUserOf(u.ID) + ".mc"
	f := newFakeFrpsProxies(t, proxyJSON(name, "client-a", time.Now().Unix()-60))
	f.install(svc)

	rec := model.ProxyDrainPending{
		UserID:   u.ID,
		Prefix:   FrpUserOf(u.ID) + ".",
		Deleted:  true,
		IntentAt: time.Now().Add(-time.Minute).Unix(),
		NextAt:   time.Now().Add(-time.Minute),
		Fence:    "legacy-fence",
	}
	if err := svc.DB.Create(&rec).Error; err != nil {
		t.Fatalf("造遗留待办失败: %v", err)
	}

	svc.retryPendingProxyDrains(context.Background())

	if got := f.closedNames(); len(got) != 0 {
		t.Fatalf("缺少账号标识的遗留待办不得自动关闭代理，实际关闭了 %v", got)
	}
	row, ok := loadDrainPending(t, svc, u.ID)
	if !ok {
		t.Fatal("遗留待办必须保留，不能删除（它是唯一的线索）")
	}
	if !row.Exhausted {
		t.Error("遗留待办应转成终态，避免每轮空转")
	}
	if row.LastErr == "" {
		t.Error("终态必须写明原因，否则管理员不知道为什么要人工处理")
	}
}
