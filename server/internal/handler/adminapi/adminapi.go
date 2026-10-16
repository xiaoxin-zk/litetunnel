// Package adminapi 实现管理员后台 API。
//
// 该包只注册在「管理侧监听地址」上（默认 127.0.0.1），与用户侧端口物理隔离；
// 且使用独立的管理域 JWT，用户令牌在此处必然校验失败。

package adminapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/middleware"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

// Handler 管理后台处理器。
//
// 登录已合并到 authapi，因此这里不再持有登录锁定器。
type Handler struct {
	svc *service.Services
}

// New 构造处理器。
func New(svc *service.Services) *Handler { return &Handler{svc: svc} }

// audit 记录一次管理操作。所有写操作都必须调用。
//
// 返回写入结果，供「审计是这次操作的必要保障」的调用点判断；多数调用点
// 忽略它即可——写失败已经由 WriteAudit 记了带上下文的错误日志，
// 不会像以前那样静默消失。
func (h *Handler) audit(c *gin.Context, action, target, targetID, detail string) error {
	adminID, adminName, _ := middleware.CurrentAdminID(c)
	return h.svc.WriteAudit(adminID, adminName, action, target, targetID, detail, httpx.ClientIP(c))
}

// failWithReason 把原始错误信息交给管理员。
//
// shared.Fail 对未识别的错误统一返回「服务内部错误」并把真实原因留在日志里——
// 对大部分接口这是对的，但这里不行：渲染、校验、重启失败的原因就是管理员
// 接下来要修的东西，换成一句笼统的提示只会让他去猜。
func failWithReason(c *gin.Context, err error) {
	if errors.Is(err, service.ErrInvalidParam) {
		httpx.Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	httpx.Fail(c, http.StatusBadGateway, err.Error())
}

func parseID(c *gin.Context) (uint, error) {
	v, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || v == 0 {
		return 0, errors.New("非法 ID")
	}
	return uint(v), nil
}
