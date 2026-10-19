package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
)

const (
	updateCheckTTL        = 20 * time.Minute
	defaultUpdateRepo     = "xiaoxin-zk/litetunnel"
	clientAssetName       = "LiteTunnel-windows-amd64.zip"
	clientChecksumSuffix  = ".sha256"
	updateResponseMaxRead = 1 << 20
)

var ErrUpdateCheckFailed = errors.New("检查更新失败，请稍后重试")

type ReleaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}

// UpdateStatus 是面板与客户端共用的版本信息。
// 本项目通过容器镜像发布：面板随镜像一起更新，所以这里只负责「告诉你有新版本」，
// 不提供在容器内替换二进制的在线自更新（重启后会回到旧镜像）。
type UpdateStatus struct {
	Current     string         `json:"current"`
	Latest      string         `json:"latest"`
	HasUpdate   bool           `json:"has_update"`
	ReleaseURL  string         `json:"release_url"`
	Notes       string         `json:"notes"`
	PublishedAt time.Time      `json:"published_at"`
	Assets      []ReleaseAsset `json:"assets"`
	CheckedAt   time.Time      `json:"checked_at"`
	Source      string         `json:"source"`
	Warning     string         `json:"warning,omitempty"`
	DeployHint  string         `json:"deploy_hint"`
	// CanSelfUpdate 仅二进制 + systemd 部署为 true；容器部署恒为 false。
	CanSelfUpdate bool   `json:"can_self_update"`
	InstallMode   string `json:"install_mode"`
}

type githubRelease struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func updateRepo() string {
	if r := strings.TrimSpace(os.Getenv("LT_UPDATE_REPO")); r != "" {
		return r
	}
	return defaultUpdateRepo
}

// parseVersionTuple 只认 v1.2.3 / 1.2.3 这类发行版本；
// dev、ci-xxxx、main-xxxx 等构建返回 false，不参与比较，避免误报有新版本。
func parseVersionTuple(v string) ([3]int, bool) {
	var out [3]int
	s := strings.TrimPrefix(strings.TrimSpace(v), "v")
	if s == "" {
		return out, false
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func versionLess(current, latest string) (bool, bool) {
	c, okc := parseVersionTuple(current)
	l, okl := parseVersionTuple(latest)
	if !okc || !okl {
		return false, false
	}
	for i := 0; i < 3; i++ {
		if l[i] > c[i] {
			return true, true
		}
		if l[i] < c[i] {
			return false, true
		}
	}
	return false, true
}

func clientDeployHint() string {
	return "docker compose --env-file .env -f deploy/docker-compose.yml pull && " +
		"docker compose --env-file .env -f deploy/docker-compose.yml up -d"
}

// CheckUpdate 查询最新 Release。结果缓存 20 分钟；失败时若有旧缓存则回退并附 warning，
// 避免 GitHub 限流或网络抖动把面板顶成一片红。
func (s *Services) CheckUpdate(ctx context.Context, force bool) (*UpdateStatus, error) {
	s.updateMu.Lock()
	cached := s.updateCache
	s.updateMu.Unlock()

	if !force && cached != nil && time.Since(cached.CheckedAt) < updateCheckTTL {
		return s.decorateUpdate(cached), nil
	}

	status, err := s.fetchLatestRelease(ctx)
	if err != nil {
		if cached != nil {
			fallback := *cached
			fallback.Warning = "本次检查失败，展示的是上次结果：" + err.Error()
			return s.decorateUpdate(&fallback), nil
		}
		return nil, err
	}

	// 缓存里只保留成功结果，Warning 不落缓存，避免失败标记被反复展示。
	s.updateMu.Lock()
	keep := *status
	s.updateCache = &keep
	s.updateMu.Unlock()
	return s.decorateUpdate(status), nil
}

func (s *Services) decorateUpdate(st *UpdateStatus) *UpdateStatus {
	st.CanSelfUpdate, st.InstallMode = s.SelfUpdateState()
	return st
}

func (s *Services) fetchLatestRelease(ctx context.Context) (*UpdateStatus, error) {
	repo := updateRepo()
	endpoint := "https://api.github.com/repos/" + repo + "/releases/latest"

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "LiteTunnel-Panel")
	if token := strings.TrimSpace(os.Getenv("LT_UPDATE_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := oauthHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpdateCheckFailed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GitHub 返回 %d", ErrUpdateCheckFailed, resp.StatusCode)
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, updateResponseMaxRead)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpdateCheckFailed, err)
	}
	if rel.TagName == "" || rel.Draft {
		return nil, ErrUpdateCheckFailed
	}

	latest := strings.TrimPrefix(rel.TagName, "v")
	current := config.Version
	hasUpdate, comparable := versionLess(current, latest)

	status := &UpdateStatus{
		Current:     current,
		Latest:      latest,
		HasUpdate:   hasUpdate,
		ReleaseURL:  rel.HTMLURL,
		Notes:       strings.TrimSpace(rel.Body),
		PublishedAt: rel.PublishedAt,
		CheckedAt:   time.Now(),
		Source:      "github:" + repo,
		DeployHint:  clientDeployHint(),
	}
	for _, a := range rel.Assets {
		status.Assets = append(status.Assets, ReleaseAsset{Name: a.Name, URL: a.URL, Size: a.Size})
	}
	if !comparable {
		status.Warning = "当前是开发/CI 构建（" + current + "），只展示最新版本，不做版本比较"
	}
	return status, nil
}

// LatestClientPackage 返回 Windows 客户端在最新 Release 里的下载信息。
func (s *Services) LatestClientPackage(ctx context.Context, clientVersion string) (map[string]any, error) {
	status, err := s.CheckUpdate(ctx, false)
	if err != nil {
		return nil, err
	}
	var pkg, sum string
	for _, a := range status.Assets {
		switch a.Name {
		case clientAssetName:
			pkg = a.URL
		case clientAssetName + clientChecksumSuffix:
			sum = a.URL
		}
	}
	hasUpdate, comparable := versionLess(clientVersion, status.Latest)
	return map[string]any{
		"current":        clientVersion,
		"latest":         status.Latest,
		"has_update":     hasUpdate,
		"comparable":     comparable,
		"download_url":   pkg,
		"checksum_url":   sum,
		"release_url":    status.ReleaseURL,
		"notes":          status.Notes,
		"published_at":   status.PublishedAt,
		"server_version": status.Current,
	}, nil
}
