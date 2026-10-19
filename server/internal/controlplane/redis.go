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

func (c *Client) BumpVersion(ctx context.Context, key string) (int64, error) {
	return c.IncrementWindow(ctx, key, 365*24*time.Hour)
}

func NewFence() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil { return fmt.Sprintf("%d", time.Now().UnixNano()) }
	return hex.EncodeToString(buf)
}
