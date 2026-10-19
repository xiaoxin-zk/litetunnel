package service

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

const MaxBatchTunnels = 20

type CreateTunnelBatchInput struct {
	NamePrefix string `json:"name_prefix"`
	Type       string `json:"type"`
	LocalIP    string `json:"local_ip"`
	Ports      []int  `json:"ports"`
}

type BatchFailure struct {
	LocalPort int    `json:"local_port"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

type BatchCreateResult struct {
	Created          []model.Tunnel `json:"created"`
	Failures         []BatchFailure `json:"failures"`
	FirewallFailures []BatchFailure `json:"firewall_failures"`
}

func (s *Services) CreateTunnelsBatch(u *model.User, in CreateTunnelBatchInput) (*BatchCreateResult, error) {
	prefix := strings.TrimSpace(in.NamePrefix)
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

	lock := s.userLock(u.ID)
	lock.Lock()
	defer lock.Unlock()

	for _, port := range ports {
		name := fmt.Sprintf("%s_%d", prefix, port)

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
			res.Failures = append(res.Failures, BatchFailure{
				LocalPort: port,
				Name:      name,
				Reason:    describeTunnelWriteError(err).Error(),
			})
			if errors.Is(err, ErrTunnelLimit) || errors.Is(err, ErrPortLimit) {
				break
			}
			continue
		}
		res.Created = append(res.Created, *t)
	}

	if len(res.Created) > 0 {
		for i := range res.Created {
			t := &res.Created[i]
			if t.RemotePort <= 0 {
				continue
			}
			if perr := s.markFirewallPending(t.RemotePort, ProtoOfTunnel(t.Type), true); perr != nil {
				reason := "隧道已创建，但防火墙放行未进入重试队列（队列已满），请稍后重试"
				if errors.Is(perr, ErrFirewallQueueUnavailable) {
					reason = "隧道已创建，但防火墙放行未进入重试队列（队列不可用，数据库故障），请稍后重试"
				}
				res.FirewallFailures = append(res.FirewallFailures, BatchFailure{
					LocalPort: t.LocalPort,
					Name:      t.Name,
					Reason:    reason,
				})
			}
		}
		s.KickFirewall()
	}
	return res, nil
}

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
