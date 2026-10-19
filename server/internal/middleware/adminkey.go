package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// AdminKeyResolver 校验管理员只读 Key，返回创建者身份与作用域。
type AdminKeyResolver func(plain string) (adminID uint, name, scope string, ok bool)

// AdminReadAuth 用于管理员只读接口组：优先 Bearer JWT，
// 没有 Bearer 时才尝试 X-Admin-Key。Key 只能读，写接口组不挂这条链路。
func AdminReadAuth(secret string, resolve IdentityResolver, keyResolve AdminKeyResolver) gin.HandlerFunc {
	return func(c *gin.Context) {
		if tokenStr := extractToken(c); tokenStr != "" {
			claims, err := auth.Parse(secret, auth.DomainAdmin, tokenStr)
			if err != nil {
				httpx.Unauthorized(c, "登录状态已失效，请重新登录")
				return
			}
			if !checkIdentity(c, resolve, claims.UserID, claims.Version) {
				return
			}
			// auditor（审计只读）本来就只该读：所有写接口都挂在
			// AdminAuth(super/operator) 之后，这里必须放行它，
			// 否则该角色登录后连 /profile 都拿不到，面板直接不可用。
			switch claims.Role {
			case "super", "operator", "auditor":
			default:
				httpx.Forbidden(c, "当前角色无此操作权限")
				return
			}
			c.Set(CtxAdminID, claims.UserID)
			c.Set(CtxAdminName, claims.Username)
			c.Set(CtxAdminRole, claims.Role)
			if claims.IssuedAt != nil {
				c.Set(CtxSessionID, strconv.FormatInt(claims.IssuedAt.Unix(), 10))
			}
			c.Next()
			return
		}

		key := strings.TrimSpace(c.GetHeader("X-Admin-Key"))
		if key == "" {
			httpx.Unauthorized(c, "缺少访问令牌")
			return
		}
		if keyResolve == nil {
			httpx.Unauthorized(c, "管理员 Key 无效或已过期")
			return
		}
		adminID, name, scope, ok := keyResolve(key)
		if !ok || adminID == 0 {
			httpx.Unauthorized(c, "管理员 Key 无效或已过期")
			return
		}
		if scope != "read" {
			httpx.Forbidden(c, "该 Key 没有读取权限")
			return
		}
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead:
		default:
			httpx.Forbidden(c, "管理员 Key 只能用于只读接口")
			return
		}
		c.Set(CtxAdminID, adminID)
		c.Set(CtxAdminName, "key:"+name)
		c.Set(CtxAdminRole, "apikey")
		c.Set(CtxAuthMethod, "admin_api_key")
		c.Next()
	}
}
