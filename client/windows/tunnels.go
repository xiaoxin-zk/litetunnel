package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/client/internal/localsvc"
)

// 隧道状态，与服务端 model.Tunnel 的取值一致。
const (
	tunnelStatusActive   = "active"
	tunnelStatusDisabled = "disabled"
)

// ListLocalServices 枚举本机正在监听的服务，供用户在建隧道时点选。
//
// 刻意不要求已登录：用户完全可能在连接之前就想看看自己有哪些服务，
// 而这个动作既不访问网络、也不涉及账号数据。
func (a *App) ListLocalServices() ([]localsvc.Service, error) {
	return localsvc.List()
}

// CreateTunnel 创建一条隧道。
//
// remotePort 传 0 表示由服务端自动分配：客户端刻意不暴露「远程端口」
// 这个概念，用户只需要知道「本机服务跑在哪个端口」。
// 端口池的挑选、系统占用排除、保留端口过滤全在服务端完成。
func (a *App) CreateTunnel(name, tunnelType, localIP string, localPort, remotePort int, subdomain string) (State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}

	// subdomain 只对 HTTP/HTTPS 有意义：那两类隧道没有公网端口，
	// 靠域名区分。服务端在两者都为空时会直接拒绝，所以必须带上。
	payload, err := json.Marshal(map[string]any{
		"name":        strings.TrimSpace(name),
		"type":        strings.TrimSpace(tunnelType),
		"local_ip":    strings.TrimSpace(localIP),
		"local_port":  localPort,
		"remote_port": remotePort,
		"subdomain":   strings.TrimSpace(subdomain),
	})
	if err != nil {
		return a.GetState(), err
	}
	if _, err := a.do(http.MethodPost, base+"/api/user/tunnels", apiKey, payload); err != nil {
		return a.GetState(), err
	}
	// 建完立刻同步：新建的隧道会带上下发的公网地址，
	// 让用户马上看到「该发给朋友哪个地址」。
	return a.Refresh()
}

// BatchFailure 记录批量创建中一条失败。
type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

// BatchResult 是批量创建的结果。
//
// 不绑定 created 字段：建完就调 Refresh 重新拉列表，
// 那条路径已经保证了列表与配置都是最新的，再解析一遍是多余的。
type BatchResult struct {
	Message  string         `json:"message"`
	Failures []BatchFailure `json:"failures"`
}

// CreateTunnelsBatch 批量创建隧道。
//
// 服务端逐条创建、不整体回滚：用户要的是一批端口尽可能都建好，
// 而不是「一条失败就全都没了」。失败原因逐条带回，用户才知道
// 该去改哪一个。
func (a *App) CreateTunnelsBatch(namePrefix, tunnelType, localIP string, ports []int) (BatchResult, State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	payload, err := json.Marshal(map[string]any{
		"name_prefix": strings.TrimSpace(namePrefix),
		"type":        strings.TrimSpace(tunnelType),
		"local_ip":    strings.TrimSpace(localIP),
		"ports":       ports,
	})
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	raw, err := a.do(http.MethodPost, base+"/api/user/tunnels/batch", apiKey, payload)
	if err != nil {
		return BatchResult{}, a.GetState(), err
	}

	var out BatchResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return BatchResult{}, a.GetState(), err
	}

	// 建完立刻同步：新建的隧道会带上下发的公网地址。
	// 同步失败时不把整体判为失败——隧道其实已经建好了。
	state, rerr := a.Refresh()
	if rerr != nil {
		return out, a.GetState(), nil
	}
	return out, state, nil
}

// DeleteTunnel 删除一条隧道，并清掉它在本机留下的配置。
//
// 顺序是「服务端删除 → 停进程 → 删本地配置」：
//   - 先删本地配置的话，正在跑的 frpc 会在下一次重连时读不到自己的配置；
//   - 本地配置必须删：frpc.toml 里含客户端接入密钥与 frps 全局 token，
//     隧道都删了、凭据还留在磁盘上，任何能读到这个目录的进程都能拿去接入。
func (a *App) DeleteTunnel(id uint) (State, error) {
	// 与后台同步互斥：否则同步可能刚按旧清单把这条隧道的进程拉起来，
	// 而我们紧接着删掉了它的配置文件——进程还在，配置没了。
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d", base, id)
	if _, err := a.do(http.MethodDelete, endpoint, apiKey, nil); err != nil {
		return a.GetState(), err
	}

	// 停进程：它已经没有服务端记录，继续跑只会刷重连错误。
	//
	// 停止失败时**不能继续删配置**：进程还在跑，配置文件却被删了——用户看到
	// 「已删除」，而 frpc 仍在后台占着端口转发，且下次排查时连它用的是哪份
	// 配置都查不到。这种情况必须如实报错，并把清理留给下一轮同步
	// （cleanupStaleConfigs 会在进程停下之后接手）。
	if err := a.mgr.Stop(id); err != nil {
		msg := "隧道已在服务端删除，但本地 frpc 进程停止失败，配置文件暂未清理：" + err.Error()
		a.emitNotice(msg)
		return a.GetState(), errors.New(msg)
	}

	// 状态记录一并清掉：这条隧道不会再回来了。
	a.clearTunnelErr(id)
	a.clearRetry(id)

	state := a.syncAndState()
	if err := removeFrpcConfig(id); err != nil {
		// 删除失败必须让用户知道：磁盘上还留着一份含凭据的配置。
		a.emitNotice("隧道已删除，但本地配置文件删除失败（其中含接入密钥）：" + err.Error())
		return a.GetState(), err
	}
	return state, nil
}

// StartTunnel 启用一条隧道并立即建立连接。
//
// 两步都不能省，而且顺序不能反：
//   - 先把服务端状态置为 active——它会开放防火墙端口，并让这条隧道
//     出现在后续下发的配置里；
//   - 再为本机拉起这条隧道自己的 frpc 进程。
//
// 反过来（先起进程）拿到的是「隧道还是停用状态」的配置，frps 那边
// 直接拒绝建代理，用户看到的就是「开关打开了却一直连不上」。
func (a *App) StartTunnel(id uint) (State, error) {
	// 整段操作与后台同步互斥。
	//
	// 不互斥的话有一个很难复现的竞态：后台同步先读到「这条隧道已停用」
	// 的清单，用户此刻点了开启，同步随后拿着那份旧清单把刚起来的进程
	// 停掉——用户看到的就是「点了开启，一闪又断了」。
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusActive {
		if err := a.setTunnelStatus(base, apiKey, id, tunnelStatusActive); err != nil {
			return a.GetState(), err
		}
		// 服务端状态已经改了，本机缓存也要跟上：GetState 直接读它，
		// 不更新的话返回给前端的快照仍是「已停用」——用户点了开启，
		// 界面上的开关却弹回去，直到下一轮后台同步（≤20 秒）才纠正。
		a.applyLocalStatus(id, tunnelStatusActive)
		if nt, ok := a.findTunnel(id); ok {
			t = nt
		}
	}
	if err := a.startTunnelProcess(t); err != nil {
		a.noteStartFailure(id, t.Name, "启动失败："+err.Error())
		return a.GetState(), err
	}
	// 退避由 startTunnelProcess → writeAndStart 在**启动之前**清掉。
	// 用户主动点开当然要立刻重试，而不是等上一次失败留下的退避时间。

	// 进程已经拉起来了，先返回，同步放后台。
	//
	// 同步会逐条拉取活动隧道的配置（每条一次 HTTP，超时 15 秒），隧道一多
	// 或网络一慢，按钮就要转很久——而用户此刻关心的是「这条隧道起没起来」。
	// frpc 一报 start proxy success，界面就会通过 registered 立刻变成
	// 「运行中」，完全不必等这次同步。
	//
	// 后台同步照常执行（拿最新的隧道清单与状态），只是不再挡着返回。
	state := a.GetState()
	a.emitState()
	go func() {
		// syncMu 此刻还被本函数持有（defer 解锁），所以这个协程会先等一下，
		// 等 StartTunnel 返回后再同步——不会与它重叠。
		a.syncMu.Lock()
		defer a.syncMu.Unlock()
		a.syncAndState()
	}()
	return state, nil
}

// StopTunnel 断开一条隧道并停用它。
//
// 顺序与 StartTunnel 相反：**先改服务端状态，再停本机进程**。
//
// 这里曾经是先停进程、再请求服务端停用，失败时会静默反转用户的操作：
// 服务端请求失败后状态仍是 active，而下一轮自动同步（≤20 秒）会按服务端
// 状态把进程重新拉起来——用户看到「停用失败」，然后隧道自己又跑起来了，
// 而且找不到是谁干的。
//
// 反过来之后，失败发生在本机进程被停掉之前，提示与实际状态一致；
// 而「服务端已停用、本机进程还在」这种中间态会被下一轮同步收掉，
// 是自愈的。代价是有一瞬间服务端已停用而进程还没停——frpc 可能刷一两行
// 重连错误，比「操作被静默反转」好得多。
func (a *App) StopTunnel(id uint) (State, error) {
	// 与 StartTunnel 同理：必须和后台同步互斥，否则会被旧清单重新拉起来。
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	base, apiKey, err := a.currentCredential()
	if err != nil {
		return a.GetState(), err
	}
	t, ok := a.findTunnel(id)
	if !ok {
		return a.GetState(), errors.New("找不到这条隧道，请等待同步完成后重试")
	}
	if t.Status != tunnelStatusDisabled {
		if err := a.setTunnelStatus(base, apiKey, id, tunnelStatusDisabled); err != nil {
			return a.GetState(), err
		}
		// 与 StartTunnel 同理：本机缓存先落下，界面上的开关立刻响应。
		a.applyLocalStatus(id, tunnelStatusDisabled)
	}
	if err := a.stopTunnelProcess(t); err != nil {
		return a.GetState(), err
	}

	// 与 StartTunnel 对称：不在这里等整轮同步。
	//
	// 同步会为每条活动隧道各发一次配置请求（超时 15 秒），隧道一多或网络
	// 一慢，停止按钮就要转很久——而本机进程其实已经停了、状态也已经更新。
	// 后台同步照常跑（拿最新清单做最终对账），只是不再挡着返回。
	//
	// syncMu 仍由本函数持有（defer 解锁），因此这个协程会在返回之后才开始同步。
	state := a.GetState()
	a.emitState()
	go func() {
		a.syncMu.Lock()
		defer a.syncMu.Unlock()
		a.syncAndState()
	}()
	return state, nil
}

// applyLocalStatus 就地更新本机缓存的隧道状态。
//
// 只动本机那一份：服务端状态由调用方在此之前改完。抽出来是为了让开关操作
// 与「返回给前端的快照」保持一致——快照落后一轮同步，用户会以为操作没生效。
func (a *App) applyLocalStatus(id uint, status string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			a.tunnels[i].Status = status
			return
		}
	}
}

// syncAndState 在**已持有 syncMu** 的前提下对账一次并广播最新状态。
//
// 单独抽出来是因为开关操作需要在同一把锁内完成「改状态 → 起停进程 →
// 重新对账」，中间不能让后台同步插进来；而 Refresh 自己会去抢锁，
// 在锁内调用它就是死锁。
func (a *App) syncAndState() State {
	if _, err := a.applySync(); err != nil {
		a.setSyncErr(err)
	}
	state := a.GetState()
	a.emitState()
	return state
}

// setTunnelStatus 修改隧道在服务端的启用状态。
func (a *App) setTunnelStatus(base, apiKey string, id uint, status string) error {
	payload, err := json.Marshal(map[string]string{"status": status})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/api/user/tunnels/%d/status", base, id)
	_, err = a.do(http.MethodPost, endpoint, apiKey, payload)
	return err
}

// findTunnel 在当前隧道清单里找一条隧道。
func (a *App) findTunnel(id uint) (TunnelVO, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for i := range a.tunnels {
		if a.tunnels[i].ID == id {
			return a.tunnels[i], true
		}
	}
	return TunnelVO{}, false
}

// Redeem 使用兑换码。
//
// 返回服务端给出的结果文案（例如「流量额度已增加 10 GB」），
// 由调用方直接提示用户——不同兑换码类型的文案差别很大，
// 在客户端里猜类型容易说错。
func (a *App) Redeem(code string) (string, State, error) {
	base, apiKey, err := a.currentCredential()
	if err != nil {
		return "", a.GetState(), err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return "", a.GetState(), errors.New("请输入兑换码")
	}

	payload, err := json.Marshal(map[string]string{"code": code})
	if err != nil {
		return "", a.GetState(), err
	}
	raw, err := a.do(http.MethodPost, base+"/api/user/redeem", apiKey, payload)
	if err != nil {
		return "", a.GetState(), err
	}

	var out struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &out)

	// 兑换可能改变配额或分组，同步一次让界面立刻反映最新状态。
	state, rerr := a.Refresh()
	if rerr != nil {
		return out.Message, a.GetState(), nil
	}
	return out.Message, state, nil
}
