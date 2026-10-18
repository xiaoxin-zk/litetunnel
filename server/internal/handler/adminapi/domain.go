package adminapi

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
)

// DomainStatus 返回宿主机配置服务的健康度与证书状态。
//
// 归在只读组：这些信息（helper 通不通、证书还有几天到期）是排查问题的
// 第一手材料，审计角色同样需要看到。
func (h *Handler) DomainStatus(c *gin.Context) {
	// 整份 DTO 原样返回，不要再挑字段拼 gin.H：
	// desired / applied / pending 才是这一页的核心（「保存了」与「生效了」
	// 是不是同一份），漏掉它们时管理页读不到字段，只能显示成空白或
	// 「状态一致」——恰好把最该看到的差异藏起来了。
	// DTO 里只有域名、模式与证书状态，没有任何凭据。
	httpx.OK(c, h.svc.DomainStatus())
}

// DomainApply 把当前设置渲染成 Caddyfile / frps.toml 并（默认）应用。
//
// 与 /settings 分成两个接口是刻意的：保存配置是「记下来」，下发是
// 「改宿主机上的文件并重启容器」。后者可能失败（helper 没起、镜像拉不到、
// 配置校验不通过），而失败时不能让「保存」也跟着回滚——管理员需要
// 保留着填好的值去修环境。
func (h *Handler) DomainApply(c *gin.Context) {
	var req struct {
		// Apply 为 false 时只渲染与校验，不动容器。默认应用。
		Apply *bool `json:"apply"`
	}
	// 空 body 合法：界面上的「保存并应用」不带参数，按默认值执行。
	// 但非空且解析失败必须是 400：以前这里忽略了解析错误，一段写坏的
	// JSON（例如 apply 拼错）会被当成「没传参数」而按 apply=true 执行，
	// 调用方本意可能是演练，结果真把容器重建了。
	if c.Request.ContentLength != 0 && c.Request.Body != nil {
		if err := c.ShouldBindJSON(&req); err != nil {
			httpx.BadRequest(c, "请求体不是合法 JSON")
			return
		}
	}
	apply := true
	if req.Apply != nil {
		apply = *req.Apply
	}

	res, err := h.svc.ApplyDomainConfig(apply)
	if err != nil {
		h.audit(c, "domain.apply_failed", "domain", "", err.Error())
		failWithReason(c, err)
		return
	}
	h.audit(c, "domain.apply", "domain", "",
		fmt.Sprintf("下发域名与证书配置（变化文件：%s）", strings.Join(res.Changed, ", ")))
	httpx.OK(c, res)
}

// DomainDNSCheck 检查面板域名、隧道根域名与一个随机子域的解析。
func (h *Handler) DomainDNSCheck(c *gin.Context) {
	records, err := h.svc.DomainDNSCheck(c.Request.Context())
	if err != nil {
		failWithReason(c, err)
		return
	}
	httpx.OK(c, gin.H{"records": records})
}
