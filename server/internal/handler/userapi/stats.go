package userapi

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/handler/shared"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
)

func (h *Handler) StatsOverview(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	u, err := h.svc.LoadUser(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	tunnels, err := h.svc.ListTunnels(uid)
	if err != nil {
		shared.Fail(c, err)
		return
	}
	online := 0
	for i := range tunnels {
		if h.svc.IsTunnelOnline(&tunnels[i]) {
			online++
		}
	}
	httpx.OK(c, gin.H{
		"traffic_used":     u.TrafficUsed,
		"traffic_quota":    h.svc.EffectiveQuota(u),
		"traffic_exceeded": h.svc.QuotaExceeded(u),
		"balance":          u.Balance,
		"tunnel_total":     len(tunnels),
		"tunnel_online":    online,
		"group_name":       groupName(h.svc.EffectiveGroup(u)),
	})
}

func groupName(g *model.Group) string {
	if g == nil {
		return "未分组"
	}
	return g.Name
}

func (h *Handler) TrafficStats(c *gin.Context) {
	uid := middleware.CurrentUserID(c)
	days := 7
	if v, err := strconv.Atoi(c.DefaultQuery("days", "7")); err == nil && v > 0 && v <= 90 {
		days = v
	}
	type row struct {
		Date     string `json:"date"`
		InBytes  int64  `json:"in_bytes"`
		OutBytes int64  `json:"out_bytes"`
	}
	var rows []row
	err := h.svc.DB.Model(&model.TrafficDaily{}).
		Select("date, SUM(in_bytes) AS in_bytes, SUM(out_bytes) AS out_bytes").
		Where("user_id = ? AND date >= ?", uid, time.Now().AddDate(0, 0, -days+1).Format("2006-01-02")).
		Group("date").Order("date asc").Scan(&rows).Error
	if err != nil {
		shared.Fail(c, err)
		return
	}
	httpx.OK(c, rows)
}
