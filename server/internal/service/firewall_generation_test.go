package service

import (
	"testing"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// TestFirewallPendingGenerationGuardsWrites 覆盖「旧意图覆盖/删除新意图」。
//
// 落库发生在锁外：旧意图的写回可能晚于新意图。无条件 upsert/delete 时，
// 旧的「收回」会顶掉新的「放行」，或旧任务把新待办删掉——重启后动作就错了。
func TestFirewallPendingGenerationGuardsWrites(t *testing.T) {
	svc := newTestServices(t, nil)

	// 先放行（gen 1）、再收回（gen 2）：同一端口后来的意图覆盖先前的。
	svc.markFirewallPending(20001, "tcp", true)
	svc.markFirewallPending(20001, "tcp", false)

	// 模拟旧意图（gen 1）的落库晚到：条件写必须拒绝它，不能顶掉 gen 2。
	svc.persistPending(20001, pendingFW{open: true, proto: "tcp", gen: 1})

	var rec model.FirewallPending
	if err := svc.DB.First(&rec, 20001).Error; err != nil {
		t.Fatalf("应有一条待办记录: %v", err)
	}
	if rec.Open || rec.Generation != 2 {
		t.Fatalf("旧代写回不应覆盖新代，得到 open=%v gen=%d", rec.Open, rec.Generation)
	}

	// 旧任务（gen 1）的删除不应删掉新代记录。
	svc.dropPending(20001, 1)
	if err := svc.DB.First(&rec, 20001).Error; err != nil {
		t.Fatalf("旧代删除不应影响新代记录: %v", err)
	}

	// 同代删除应真正清除。
	svc.dropPending(20001, 2)
	if err := svc.DB.First(&rec, 20001).Error; err == nil {
		t.Fatal("同代删除应清除记录")
	}
}

// TestFirewallPendingLoadSeedsGeneration 覆盖「重启后新意图的代次仍单调」。
func TestFirewallPendingLoadSeedsGeneration(t *testing.T) {
	svc := newTestServices(t, nil)
	svc.markFirewallPending(20002, "tcp", true) // gen 1
	svc.persistPending(20002, pendingFW{open: true, proto: "tcp", gen: 1})

	// 模拟重启：代次来自落库序列，重启后取号仍然单调递增（不会撞回旧值）。
	svc.fwPending = nil
	svc.loadPendingFirewall()

	svc.markFirewallPending(20002, "tcp", false)
	svc.persistPending(20002, pendingFW{open: false, proto: "tcp", gen: 1}) // 旧代写回

	var rec model.FirewallPending
	if err := svc.DB.First(&rec, 20002).Error; err != nil {
		t.Fatalf("应有一条待办记录: %v", err)
	}
	if rec.Open {
		t.Fatal("重启后旧代写回不应覆盖新代")
	}
}
