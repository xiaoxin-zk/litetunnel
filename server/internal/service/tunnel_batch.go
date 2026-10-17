package service

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

// MaxBatchTunnels 是单次批量创建的上限。
//
// 取 20：足以覆盖「开一串连续端口的游戏服」这个主要场景，
// 又不至于让一次误操作把端口池占满。真正的上限仍由分组配置决定——
// 这里只是防止一次请求带来无上限的循环。
const MaxBatchTunnels = 20

// CreateTunnelBatchInput 是批量创建隧道的入参。
type CreateTunnelBatchInput struct {
	// NamePrefix 是名称前缀，每条隧道会被命名为「前缀_本机端口」。
	//
	// 用前缀而不是让用户逐个起名：批量创建的场景下（比如开一串
	// 连续端口的游戏服），逐条命名是纯粹的负担，而「前缀_端口」
	// 既保证唯一，又能一眼看出隧道与端口的对应关系。
	NamePrefix string `json:"name_prefix"`
	Type       string `json:"type"`
	LocalIP    string `json:"local_ip"`
	// Ports 是待映射的本机端口。公网端口一律由服务端自动分配。
	Ports []int `json:"ports"`
}

// BatchFailure 记录一条创建失败。
type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

// BatchCreateResult 是批量创建的结果。
type BatchCreateResult struct {
	Created  []model.Tunnel `json:"created"`
	Failures []BatchFailure `json:"failures"`
}

// CreateTunnelsBatch 批量创建隧道。
//
// 逐条创建、**不整体回滚**：用户要的是一批端口尽可能都建好，
// 而不是「一条失败就全都没了」。每条失败的原因单独返回，
// 用户才知道该去改哪一个。
//
// 遇到数量/端口上限时提前结束：后续每一条都会以完全相同的原因失败，
// 继续尝试只是把同一个错误重复播报十几遍。
func (s *Services) CreateTunnelsBatch(u *model.User, in CreateTunnelBatchInput) (*BatchCreateResult, error) {
	prefix := strings.TrimSpace(in.NamePrefix)
	// 前缀会拼成「前缀_端口」，所以要预留端口部分的位置。
	// 隧道名上限是 32 位，端口最多 5 位加分隔符共 6 位。
	if len(prefix) < 1 || len(prefix) > 24 || !IsSafeName(prefix) {
		return nil, fmt.Errorf("%w: 名称前缀需为 1-24 位字母、数字或下划线", ErrInvalidParam)
	}
	if strings.HasPrefix(strings.ToLower(prefix), "lt") {
		return nil, fmt.Errorf("%w: 名称前缀不能以 lt 开头", ErrInvalidParam)
	}

	ports := dedupeBatchPorts(in.Ports)
	if len(ports) == 0 {
		return nil, fmt.Errorf("%w: 请至少填写一个有效的本机端口", ErrInvalidParam)
	}
	if len(ports) > MaxBatchTunnels {
		return nil, fmt.Errorf("%w: 一次最多创建 %d 条隧道", ErrInvalidParam, MaxBatchTunnels)
	}

	res := &BatchCreateResult{
		Created:  make([]model.Tunnel, 0, len(ports)),
		Failures: make([]BatchFailure, 0),
	}

	// 整批持有该用户的锁，而不是每条各自去抢：
	// 后者会让「删除该用户」插在两条之间，剩下的隧道就建给一个已经
	// 不存在的账号了（记录与防火墙规则都留着，而账号没了）。
	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	for _, port := range ports {
		// 分隔符用下划线而不是连字符：隧道名沿用 IsSafeName 的字符集
		// （字母数字下划线），连字符会被拒绝。
		name := fmt.Sprintf("%s_%d", prefix, port)

		// 自动分配端口撞车要换端口重试，与单条创建（CreateTunnel）一致：
		// 候选端口是在加锁之前读到的，并发批量创建时可能已被别的账号占掉。
		// 不重试的话，端口池明明还有空位，这一条却被记成失败——而且批量
		// 场景恰恰是最容易撞上的（一次要挑好几个端口）。
		// 只有端口冲突才重试；重名、超上限、参数错重试多少次都是同一个结果。
		var (
			t   *model.Tunnel
			err error
		)
		for attempt := 1; attempt <= portAllocAttempts; attempt++ {
			t, err = s.createTunnelLocked(u, TunnelInput{
				Name:      name,
				Type:      in.Type,
				LocalIP:   in.LocalIP,
				LocalPort: port,
			}, false)
			if err == nil || !isPortConflict(err) {
				break
			}
			log.Printf("[tunnel] 批量创建端口分配撞车（%s，第 %d/%d 次尝试），重新随机分配后重试",
				name, attempt, portAllocAttempts)
		}
		if err != nil {
			// 逐条回报失败原因，同样要把数据库原文翻译一遍：
			// 批量失败列表里出现 "UNIQUE constraint failed" 这种内容，
			// 用户既看不懂，也不知道该怎么改。
			res.Failures = append(res.Failures, BatchFailure{
				LocalPort: port,
				Name:      name,
				Reason:    describeTunnelWriteError(err).Error(),
			})
			// 上限类错误后续每一条都会重复出现，直接结束，
			// 避免把同一个原因播报二十遍。
			if errors.Is(err, ErrTunnelLimit) || errors.Is(err, ErrPortLimit) {
				break
			}
			continue
		}
		res.Created = append(res.Created, *t)
	}

	// 防火墙放行挪到用户锁临界区之外异步补做。
	//
	// helper 不可达时，单次探测/操作的网络调用可达 10 秒；在锁内逐条
	// 同步放行的话，20 条的批次能拖上几分钟，同一用户的其他隧道操作
	// 全部排队。改为：放行失败本就进重试队列兜底（见 applyPortIntent），
	// 这里再用一个协程按序补一次立即尝试，让规则尽快生效——协程只拿
	// 端口锁，不碰用户锁，不会阻塞该用户的任何其他操作。
	if len(res.Created) > 0 {
		created := res.Created
		go func() {
			for i := range created {
				if created[i].RemotePort > 0 {
					s.applyPortIntent(created[i].RemotePort, ProtoOfTunnel(created[i].Type), true)
				}
			}
		}()
	}
	return res, nil
}

// dedupeBatchPorts 去掉重复与越界的端口，保持用户填写的顺序。
//
// 保持顺序而不是排序：用户按 25565、25566、25567 的顺序填，
// 建出来的隧道列表也应当是这个顺序，否则他会怀疑自己填错了。
func dedupeBatchPorts(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
