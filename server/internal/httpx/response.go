// Package httpx 统一 API 响应结构与分页参数。
package httpx

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Response 统一响应体。所有接口一律返回该结构，便于前端统一处理。
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Page 分页结果。
type Page struct {
	List     any   `json:"list"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

// OK 返回成功。
func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{Code: 0, Message: "ok", Data: data})
}

// PageOK 返回分页成功。
func PageOK(c *gin.Context, list any, total int64, page, pageSize int) {
	OK(c, Page{List: list, Total: total, Page: page, PageSize: pageSize})
}

// Fail 返回业务失败。HTTP 状态码与业务码保持一致，便于网关与前端判断。
func Fail(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, Response{Code: status, Message: message})
}

// BadRequest 参数错误。
func BadRequest(c *gin.Context, message string) { Fail(c, http.StatusBadRequest, message) }

// Unauthorized 未认证。
func Unauthorized(c *gin.Context, message string) { Fail(c, http.StatusUnauthorized, message) }

// Forbidden 无权限。
func Forbidden(c *gin.Context, message string) { Fail(c, http.StatusForbidden, message) }

// NotFound 资源不存在。
func NotFound(c *gin.Context, message string) { Fail(c, http.StatusNotFound, message) }

// Conflict 冲突。
func Conflict(c *gin.Context, message string) { Fail(c, http.StatusConflict, message) }

// ServerError 服务端错误。
func ServerError(c *gin.Context, message string) { Fail(c, http.StatusInternalServerError, message) }

// maxPage 是允许的最大页码。
//
// OFFSET 越大数据库要跳过的行越多，恶意的大页码能把一次列表查询拖成
// 全表扫描；而且 (page-1)*pageSize 在窄 int 平台上可能溢出。设个上限，
// 异常页码直接夹到边界，比让查询自己扛要稳。
const maxPage = 100000

// Pagination 解析分页参数，带安全上限，防止恶意超大 page_size 拖垮数据库。
func Pagination(c *gin.Context) (page, pageSize, offset int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ = strconv.Atoi(c.DefaultQuery("page_size", "20"))
	if page < 1 {
		page = 1
	}
	if page > maxPage {
		page = maxPage
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset = (page - 1) * pageSize
	return
}

// ClientIP 取真实客户端 IP。仅在部署时由可信反代注入 X-Forwarded-For 时才可信。
func ClientIP(c *gin.Context) string {
	return c.ClientIP()
}
