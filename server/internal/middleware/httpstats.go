package middleware

import (
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// HTTPStats 只保留告警需要的最小计数：总请求与 5xx。
// 用原子计数而不是落库，避免为每个请求写一行日志。
type HTTPStats struct {
	total  atomic.Int64
	err5xx atomic.Int64
}

var httpStats HTTPStats

type HTTPStatsSnapshot struct {
	Total  int64 `json:"total"`
	Errors int64 `json:"errors"`
}

// HTTPStatsMiddleware 只统计 /api/ 接口的响应。
// 静态资源与 SPA 回退不参与：它们请求量大且几乎不会 5xx，
// 计入分母会把真实的接口错误率稀释到永远触发不了阈值。
func HTTPStatsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}
		httpStats.total.Add(1)
		c.Next()
		if c.Writer.Status() >= 500 {
			httpStats.err5xx.Add(1)
		}
	}
}

// SnapshotAndReset 取走上一窗口的计数，供告警任务计算错误率。
func HTTPStatsSnapshotAndReset() HTTPStatsSnapshot {
	return HTTPStatsSnapshot{
		Total:  httpStats.total.Swap(0),
		Errors: httpStats.err5xx.Swap(0),
	}
}
