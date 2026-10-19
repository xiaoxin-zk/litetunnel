package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client 是跨实例控制面状态存储：Redis 故障时调用方必须按 fail-closed
// 或持久化数据库兜底策略处理，不能把不可用误当成“没有状态”。
type Client struct {
	redis *redis.Client
	prefix string
}

func New(addr, password string, db int, prefix string) (*Client, error) {
	if addr == "" {
		return nil, nil
	}
	if prefix == "" {
		prefix = "litetunnel:"
	}
	return &Client{redis: redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db}), prefix: prefix}, nil
}

func (c *Client) Enabled() bool { return c != nil && c.redis != nil }

func (c *Client) Ping(ctx context.Context) error {
	if !c.Enabled() { return fmt.Errorf("redis 未配置") }
	return c.redis.Ping(ctx).Err()
}

func (c *Client) key(parts ...string) string {
	v := c.prefix
	for _, p := range parts { v += p + ":" }
	return v
}

// IncrementWindow 原子地增加窗口计数，首次写入时设置过期时间。
func (c *Client) IncrementWindow(ctx context.Context, key string, window time.Duration) (int64, error) {
	if !c.Enabled() { return 0, fmt.Errorf("redis 未配置") }
	script := redis.NewScript(`local n = redis.call('INCR', KEYS[1]); if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end; return n`)
	return script.Run(ctx, c.redis, []string{c.key(key)}, window.Milliseconds()).Int64()
}

func (c *Client) GetInt(ctx context.Context, key string) (int64, error) {
	if !c.Enabled() { return 0, fmt.Errorf("redis 未配置") }
	return c.redis.Get(ctx, c.key(key)).Int64()
}

func (c *Client) Delete(ctx context.Context, key string) error {
	if !c.Enabled() { return fmt.Errorf("redis 未配置") }
	return c.redis.Del(ctx, c.key(key)).Err()
}

// BumpVersion 单调推进一个「失效版本」。
//
// 不能用「INCR + 一年过期」：key 过期后计数从 1 重新开始，而别的实例本地
// 缓存里可能还记着 500 —— Observe 只接受更大的版本，于是新的失效通知被
// 永久忽略，跨实例 fencing 就失效了。
//
// 这里的做法是：不存在时用纳秒时间戳作为起点，存在时 +1；并且**不设过期**。
// 时间戳远大于任何按次累加的值，即使 key 被手工删除/淘汰，重新生成的起点
// 也一定大于此前观察到的版本。
func (c *Client) BumpVersion(ctx context.Context, key string) (int64, error) {
	if !c.Enabled() {
		return 0, fmt.Errorf("redis 未配置")
	}
	script := redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if not v then
  redis.call('SET', KEYS[1], ARGV[1])
  return tonumber(ARGV[1])
end
local n = tonumber(v) + 1
redis.call('SET', KEYS[1], n)
return n`)
	return script.Run(ctx, c.redis, []string{c.key(key)}, time.Now().UnixNano()).Int64()
}

func NewFence() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil { return fmt.Sprintf("%d", time.Now().UnixNano()) }
	return hex.EncodeToString(buf)
}
