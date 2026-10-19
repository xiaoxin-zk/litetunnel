package httpx

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type Page struct {
	List     any   `json:"list"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

func OK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, Response{Code: 0, Message: "ok", Data: data})
}

func PageOK(c *gin.Context, list any, total int64, page, pageSize int) {
	OK(c, Page{List: list, Total: total, Page: page, PageSize: pageSize})
}

func Fail(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, Response{Code: status, Message: message})
}

func BadRequest(c *gin.Context, message string) { Fail(c, http.StatusBadRequest, message) }

func Unauthorized(c *gin.Context, message string) { Fail(c, http.StatusUnauthorized, message) }

func Forbidden(c *gin.Context, message string) { Fail(c, http.StatusForbidden, message) }

func NotFound(c *gin.Context, message string) { Fail(c, http.StatusNotFound, message) }

func Conflict(c *gin.Context, message string) { Fail(c, http.StatusConflict, message) }

func ServerError(c *gin.Context, message string) { Fail(c, http.StatusInternalServerError, message) }

const maxPage = 100000

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

func ClientIP(c *gin.Context) string {
	return c.ClientIP()
}
