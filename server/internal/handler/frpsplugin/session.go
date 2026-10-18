package frpsplugin

// 会话登记与准入快照。
//
// 本文件负责「这个身份现在拿到了什么权限快照」：把登录会话落到数据库、
// 在心跳时刷新准入快照、以及把会话生命周期的两个轻量回调（Ping / CloseProxy）
// 分派到 runtime。
//
// 与 identity.go 的分界：identity.go 决定「你是谁」，本文件决定「你的准入
// 状态什么时候会过期」。分开是因为两者的失败模式完全不同——前者错了是
// 身份被冒充，后者错了是已撤销/已禁用的账号继续被放行。

import (
	"encoding/json"
	"log"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

type closeProxyContent struct {
	User      userInfo `json:"user"`
	ProxyName string   `json:"proxy_name"`
}

type pingContent struct {
	User         userInfo `json:"user"`
	PrivilegeKey string   `json:"privilege_key"`
	Timestamp    int64    `json:"timestamp"`
}

func (h *Handler) onCloseProxy(req *request) response {
	var content closeProxyContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return allow()
	}
	if content.User.RunID != "" {
		h.svc.Runtime.TouchSession(content.User.RunID)
	}
	return allow()
}

func (h *Handler) onPing(req *request) response {
	var content pingContent
	if err := json.Unmarshal(req.Content, &content); err != nil {
		return allow()
	}
	if content.User.RunID != "" {
		h.svc.Runtime.TouchSession(content.User.RunID)
		h.svc.TouchClientSession(content.User.RunID)
		// 顺带按需刷新会话的准入快照：多副本时账号可能在别的实例被禁用/超额，
		// 本地内存标记不会变。放在 Ping（周期性事件）而不是每次新建连接，
		// 既能让状态在一个 Ping 周期内收敛，又不会把查库压到连接热路径上。
		h.svc.RefreshSessionGuard(content.User.RunID)
	}
	return allow()
}

// ---- 会话落库 ----

// UpsertClientSession 记录/更新一次客户端登录会话，返回写库是否成功。
//
// 只有 onLogin 在凭据校验通过后才会调用本方法，
// 因此该表是后续插件回调判断身份可信度的唯一依据。
//
// 返回错误必须被调用方处理：写库失败却把会话登记进内存的话，这个会话会被
// 后续 Ping 的准入刷新判为「查不到可信会话」而**永久**拒绝——而缓存命中
// 路径不会重新执行会话写入，数据库恢复也救不回来。
func (h *Handler) UpsertClientSession(userID uint, username, runID, addr, version, osName, arch string) error {
	if runID == "" {
		return nil
	}
	now := time.Now()
	s := model.ClientSession{
		UserID:     userID,
		Username:   username,
		RunID:      runID,
		Addr:       addr,
		Version:    version,
		OS:         osName,
		Arch:       arch,
		Online:     true,
		LastSeenAt: now,
	}

	fields := map[string]any{
		"user_id":      userID,
		"username":     username,
		"online":       true,
		"last_seen_at": now,
	}
	// 空值不参与更新。
	//
	// 这个方法有两条调用路径：onLogin（四个字段都有值）与
	// resolveUser 的凭据复核补登记（只有 user / run_id，其余拿不到）。
	// 无脑 Assign 的话，补登记会把登录时记录的真实来源 IP 与版本号
	// 抹成空——而恰好是这两个字段在排查连接问题时最有用。
	if addr != "" {
		fields["addr"] = addr
	}
	if version != "" {
		fields["version"] = version
	}
	if osName != "" {
		fields["os"] = osName
	}
	if arch != "" {
		fields["arch"] = arch
	}

	if err := h.svc.DB.Where("run_id = ?", runID).Assign(fields).FirstOrCreate(&s).Error; err != nil {
		log.Printf("[plugin] 写入客户端会话失败（run_id=%s）: %v", runID, err)
		return err
	}
	return nil
}
