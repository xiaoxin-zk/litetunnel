package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// fetchTunnelConfig 拉取某条隧道专属的配置文本。
//
// 只取这一条：配置文件里只有一条 [[proxies]]，进程之间不会互相干扰。
func (a *App) fetchTunnelConfig(ctx context.Context, base, apiKey string, id uint) (string, string, error) {
	endpoint := fmt.Sprintf("%s/api/user/client/config?tunnel_id=%d", base, id)
	text, rev, err := a.getRawWithRev(ctx, endpoint, apiKey)
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(text), rev, nil
}

// cfgResult 是一条隧道的配置拉取结果。
type cfgResult struct {
	tunnel TunnelVO
	text   string
	// rev 是服务端**随这份正文**给出的摘要(响应头 X-Config-Rev)。
	// 老服务端为空,由调用方退回清单里的 config_rev。
	rev string
	err error
}

// streamTunnelConfigs 并发拉取一批隧道的配置，结果按**完成顺序**流出。
//
// 为什么值得单独做这一步：逐条串行时整轮同步的耗时约等于「隧道数 × 单次往返」，
// 十几条隧道就能让界面长时间停在「连接中」。而这一步只读网络、不碰本地状态，
// 是整条链路上唯一能安全并发的一段。
//
// 返回的是通道而不是汇总好的 map：调用方每收到一条就立刻处理（起进程、记失败），
// 不必等最慢的那一条。单次请求超时可达 15 秒，先汇总再处理的话，
// 已经取到配置的隧道会被它挡住整整一个超时周期。代价是处理顺序不再是
// 隧道清单顺序——日志与失败记录的先后取决于网络快慢，这是可接受的取舍。
//
// 出错也**不中断**：错误作为一条结果流出，由调用方逐条记录，
// 一条隧道拉取失败不会掩盖其他隧道的对账。
// 单次请求的超时由 a.http 自己的 Timeout 兜底；整轮还有 ctx 截止时间
// （调用方传入），到点后未派发的任务直接放弃，由下一轮同步补上。
// 通道在全部结果流出（或截止）后关闭，调用方 range 到结束即可。
//
// 第二个返回值是**实际派发出去的条数**：调用方据此推进续传位置
// （见 applySyncData 里的 syncStart）。不能用「收到的结果条数」代替——
// 截止时 worker 的 fetch 失败后可能直接返回、不再投递结果，那样算出来
// 的位置会原地不动，下一轮又从头开始处理同一批隧道。
func (a *App) streamTunnelConfigs(ctx context.Context, base, apiKey string, tunnels []TunnelVO) (<-chan cfgResult, *atomic.Int64) {
	dispatched := &atomic.Int64{}
	results := make(chan cfgResult, len(tunnels))
	if len(tunnels) == 0 {
		close(results)
		return results, dispatched
	}

	workers := configFetchConcurrency
	if workers > len(tunnels) {
		workers = len(tunnels)
	}

	jobs := make(chan TunnelVO)
	// 结果通道带足缓冲：worker 写完就能去领下一个任务，不会因为主协程
	// 还在处理上一条结果而空等。

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-jobs:
					if !ok {
						return
					}
					text, rev, err := a.fetchTunnelConfig(ctx, base, apiKey, t.ID)
					select {
					case results <- cfgResult{tunnel: t, text: text, rev: rev, err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// 派发与收集分开：派发放在独立协程里，主协程专心收结果。
	// 若在这里同步派发，jobs 写满时就会和收结果互相卡死。
	// 派发同样受 ctx 约束：截止后不再派发剩余任务（close(jobs) 让
	// worker 正常退出，wg.Wait 才不会卡住，results 才能关闭）。
	go func() {
		defer close(jobs)
		for _, t := range tunnels {
			select {
			case <-ctx.Done():
				return
			case jobs <- t:
				dispatched.Add(1)
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	return results, dispatched
}
