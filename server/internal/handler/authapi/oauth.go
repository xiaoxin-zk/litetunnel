package authapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xiaoxin-zk/litetunnel/server/internal/auth"
	"github.com/xiaoxin-zk/litetunnel/server/internal/httpx"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/service"
)

const oauthStateTTL = 600

func oauthStateCookie(provider string) string { return "lt_oauth_state_" + provider }

func oauthSecure(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

func (h *Handler) oauthRedirect(c *gin.Context, query string) {
	target := h.svc.PanelBaseURL() + "/login?" + query
	if h.svc.PanelBaseURL() == "" {
		target = "/login?" + query
	}
	c.Redirect(http.StatusFound, target)
}

func (h *Handler) oauthFail(c *gin.Context, reason string) {
	h.oauthRedirect(c, "oauth_error="+url.QueryEscape(reason))
}

func (h *Handler) OAuthStart(c *gin.Context) {
	provider := c.Param("provider")
	if !h.svc.OAuthAvailable(provider) {
		h.oauthFail(c, service.ErrOAuthDisabled.Error())
		return
	}

	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		httpx.Fail(c, http.StatusInternalServerError, "生成登录请求失败，请重试")
		return
	}
	state := hex.EncodeToString(buf)

	// state 放 HttpOnly cookie，Path 限定在回调路径，回调时逐项比对，成功与否都清掉。
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthStateCookie(provider), state, oauthStateTTL, "/api/auth/oauth", "", oauthSecure(c), true)

	target, err := h.svc.OAuthAuthorizeURL(provider, state)
	if err != nil {
		h.oauthFail(c, service.ErrOAuthDisabled.Error())
		return
	}
	c.Redirect(http.StatusFound, target)
}

func (h *Handler) OAuthCallback(c *gin.Context) {
	provider := c.Param("provider")
	if !h.svc.OAuthAvailable(provider) {
		h.oauthFail(c, service.ErrOAuthDisabled.Error())
		return
	}

	want, _ := c.Cookie(oauthStateCookie(provider))
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthStateCookie(provider), "", -1, "/api/auth/oauth", "", oauthSecure(c), true)

	if e := strings.TrimSpace(c.Query("error")); e != "" {
		h.oauthFail(c, "第三方登录被取消或拒绝")
		return
	}
	got := strings.TrimSpace(c.Query("state"))
	if want == "" || got == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		h.oauthFail(c, "登录请求已过期或来源不可信，请重新发起")
		return
	}

	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		h.oauthFail(c, "第三方平台没有返回授权码，请重试")
		return
	}

	profile, err := h.svc.OAuthFetchProfile(c.Request.Context(), provider, code)
	if err != nil {
		h.oauthFail(c, err.Error())
		return
	}

	u, err := h.svc.OAuthLogin(profile)
	if err != nil {
		if errors.Is(err, service.ErrAccountDisabled) {
			h.record(c, model.LoginKindUser, profile.Email, model.LoginResultDisabled, "第三方登录：账号已禁用")
		} else {
			h.record(c, model.LoginKindUser, profile.Email, model.LoginResultBadCred, "第三方登录失败："+err.Error())
		}
		h.oauthFail(c, err.Error())
		return
	}

	token, _, err := auth.Issue(
		h.svc.Cfg.UserJWTSecret, auth.DomainUser,
		u.ID, u.Username, "", u.TokenVersion, h.svc.Cfg.UserJWTExpire,
	)
	if err != nil {
		h.oauthFail(c, "签发登录凭证失败，请重试")
		return
	}
	h.record(c, model.LoginKindUser, u.Username, model.LoginResultSuccess, "第三方登录："+provider)

	h.oauthRedirect(c, "oauth_token="+url.QueryEscape(token))
}
