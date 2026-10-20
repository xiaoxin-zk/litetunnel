package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrDockerUpdateUnavailable 没有可用的 docker.sock 时的统一报错。
// 报错文案本身就是修复步骤：管理员照着挂载即可开启一键更新。
var ErrDockerUpdateUnavailable = errors.New("容器一键更新需要挂载 Docker 套接字：" +
	"在 deploy/docker-compose.yml 的 panel 服务 volumes 里加入" +
	"「- /var/run/docker.sock:/var/run/docker.sock」后重新 up -d，" +
	"不想挂载时也可以继续使用更新面板里的命令行升级方式")

const (
	// dockerUpdateTimeout 覆盖「拉镜像 + 重建容器」全过程。
	// 镜像层较大或网络慢时拉取可能要几分钟，给足余量。
	dockerUpdateTimeout = 15 * time.Minute
	dockerPullTimeout   = 12 * time.Minute
	dockerCallTimeout   = 30 * time.Second
	// 旧容器在响应写回后再停：给浏览器留出收到「已提交」的时间窗。
	dockerOldStopDelay = 3 * time.Second
)

func dockerSocketPath() string {
	if p := strings.TrimSpace(os.Getenv("LT_DOCKER_SOCK")); p != "" {
		return p
	}
	return "/var/run/docker.sock"
}

func dockerSocketReachable() bool {
	conn, err := net.DialTimeout("unix", dockerSocketPath(), 2*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func dockerHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", dockerSocketPath())
			},
		},
	}
}

// dockerAPI 调用 Docker Engine HTTP API（unix socket）。body 非 nil 时按 JSON 发送；
// out 非 nil 时解析响应 JSON，否则排空响应体。
func dockerAPI(ctx context.Context, method, path string, body any, out any, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(cctx, method, "http://docker"+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := dockerHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("无法连接 Docker（检查 docker.sock 是否挂载）: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("Docker API %s %s 返回 %d: %s",
			method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// dockerContainer 只取重建容器所需字段的 inspect 结果。
type dockerContainer struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Image        string              `json:"Image"`
		User         string              `json:"User"`
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Env          []string            `json:"Env"`
		Labels       map[string]string   `json:"Labels"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
		WorkingDir   string              `json:"WorkingDir"`
	} `json:"Config"`
	HostConfig struct {
		Binds          []string `json:"Binds"`
		NetworkMode    string   `json:"NetworkMode"`
		ExtraHosts     []string `json:"ExtraHosts"`
		Privileged     bool     `json:"Privileged"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		UsernsMode     string   `json:"UsernsMode"`
		Tmpfs          map[string]string
		PortBindings   map[string][]dockerPortBinding `json:"PortBindings"`
		RestartPolicy  struct {
			Name              string `json:"Name"`
			MaximumRetryCount int    `json:"MaximumRetryCount"`
		} `json:"RestartPolicy"`
		LogConfig struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]struct {
			Aliases []string `json:"Aliases"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// inspectSelfContainer 找到面板自己的容器。默认 hostname 就是容器短 ID；
// 若部署时显式设置了 hostname（compose 标准 lt-panel 部署不会），回退到容器名。
func inspectSelfContainer(ctx context.Context) (*dockerContainer, error) {
	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	candidates := make([]string, 0, 2)
	if hostname != "" {
		candidates = append(candidates, hostname)
	}
	if name := strings.TrimSpace(os.Getenv("LT_CONTAINER_NAME")); name != "" {
		candidates = append(candidates, name)
	} else if hostname != "lt-panel" {
		candidates = append(candidates, "lt-panel")
	}
	var lastErr error
	for _, id := range candidates {
		var c dockerContainer
		if err := dockerAPI(ctx, http.MethodGet,
			"/containers/"+id+"/json", nil, &c, dockerCallTimeout); err != nil {
			lastErr = err
			continue
		}
		return &c, nil
	}
	if lastErr == nil {
		lastErr = errors.New("无法定位面板容器")
	}
	return nil, fmt.Errorf("定位面板容器失败（尝试了 %v）: %w", candidates, lastErr)
}

// nextPanelImage 根据当前镜像引用算出目标镜像：
//   - 当前用版本 tag（:v0.1.123）→ 换成新版本 tag；
//   - 当前用 :latest → 引用不变，pull 自然取到新 latest。
func nextPanelImage(currentImage, latestVersion string) (string, error) {
	repo, tag := splitImageRef(currentImage)
	if repo == "" {
		return "", fmt.Errorf("无法解析当前镜像引用: %q", currentImage)
	}
	if tag == "" || tag == "latest" {
		return repo + ":latest", nil
	}
	return repo + ":v" + latestVersion, nil
}

// splitImageRef 把 repo:tag 拆开；只在最后一个「/」之后找「:」，
// 避免把 registry 端口（ghcr.io:443/repo）当成 tag。
func splitImageRef(ref string) (repo, tag string) {
	ref = strings.TrimSpace(ref)
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// ApplyDockerUpdate 容器一键更新：pull 新镜像 → 重建当前容器 → 启动新容器 →
// 清理旧容器。数据落在挂载卷里，不受重建影响。
//
// 全程不依赖请求上下文：一旦开始 rename/create 就不能用「客户端断开」这种
// 理由中断，否则面板会停在一个没有名字的中间状态。
func (s *Services) ApplyDockerUpdate(ctx context.Context) (string, error) {
	if !runningInContainer() {
		return "", ErrDockerUpdateUnavailable
	}
	if !dockerSocketReachable() {
		return "", ErrDockerUpdateUnavailable
	}

	status, err := s.CheckUpdate(ctx, true)
	if err != nil {
		return "", err
	}
	if !status.HasUpdate {
		return "", errors.New("当前已是最新版本")
	}

	// 检查更新用请求上下文（客户端取消只影响查询），destructive 部分用独立上下文。
	bg, cancel := context.WithTimeout(context.Background(), dockerUpdateTimeout)
	defer cancel()

	self, err := inspectSelfContainer(ctx)
	if err != nil {
		return "", err
	}
	target, err := nextPanelImage(self.Config.Image, status.Latest)
	if err != nil {
		return "", err
	}

	oldName := strings.TrimPrefix(self.Name, "/")
	if oldName == "" {
		return "", errors.New("面板容器没有名字，无法重建")
	}
	tmpName := oldName + "-updating"

	// 清理上次更新残留的中间容器（正常流程会在末尾删除，异常中断会留下）。
	_ = dockerAPI(bg, http.MethodDelete, "/containers/"+tmpName+"?force=true&v=true", nil, nil, dockerCallTimeout)

	log.Printf("[dockerupdate] 拉取镜像 %s", target)
	repo, tag := splitImageRef(target)
	if err := dockerAPI(bg, http.MethodPost,
		"/images/create?fromImage="+repo+"&tag="+tag,
		nil, nil, dockerPullTimeout); err != nil {
		return "", fmt.Errorf("拉取新镜像失败: %w", err)
	}

	// 先给当前容器改名腾出原名，再创建同名新容器；任一步失败都改回来，
	// 面板服务不中断。
	if err := dockerAPI(bg, http.MethodPost,
		"/containers/"+self.ID+"/rename?name="+tmpName, nil, nil, dockerCallTimeout); err != nil {
		return "", fmt.Errorf("重命名当前容器失败: %w", err)
	}
	createReq := buildCreateRequest(self, target)
	if err := dockerAPI(bg, http.MethodPost,
		"/containers/create?name="+oldName, createReq, nil, dockerCallTimeout); err != nil {
		_ = dockerAPI(bg, http.MethodPost, "/containers/"+self.ID+"/rename?name="+oldName, nil, nil, dockerCallTimeout)
		return "", fmt.Errorf("创建新容器失败（已回滚）: %w", err)
	}
	if err := dockerAPI(bg, http.MethodPost, "/containers/"+oldName+"/start", nil, nil, dockerCallTimeout); err != nil {
		_ = dockerAPI(bg, http.MethodDelete, "/containers/"+oldName+"?force=true&v=true", nil, nil, dockerCallTimeout)
		_ = dockerAPI(bg, http.MethodPost, "/containers/"+self.ID+"/rename?name="+oldName, nil, nil, dockerCallTimeout)
		return "", fmt.Errorf("启动新容器失败（旧容器已改回原名继续服务）: %w", err)
	}

	// 新容器已接管（host 网络下同端口）：稍候停掉并删除旧容器。
	// 当前进程就跑在旧容器里，所以这段必须放在响应之后由 goroutine 收尾。
	go func() {
		time.Sleep(dockerOldStopDelay)
		if err := dockerAPI(context.Background(), http.MethodPost,
			"/containers/"+tmpName+"/stop?t=5", nil, nil, dockerCallTimeout); err != nil {
			log.Printf("[dockerupdate] 停止旧容器失败（不影响新容器服务）: %v", err)
		}
		if err := dockerAPI(context.Background(), http.MethodDelete,
			"/containers/"+tmpName+"?force=true&v=true", nil, nil, dockerCallTimeout); err != nil {
			log.Printf("[dockerupdate] 删除旧容器失败（可手工 docker rm %s）: %v", tmpName, err)
		} else {
			log.Printf("[dockerupdate] 更新完成：%s -> %s", status.Current, status.Latest)
		}
	}()

	log.Printf("[dockerupdate] 新容器已启动（镜像 %s），旧容器 %s 将在几秒后清理", target, tmpName)
	return status.Latest, nil
}

// buildCreateRequest 从 inspect 结果复制容器的运行配置，仅替换镜像。
// compose 的 env_file、network_mode、read_only、tmpfs、cap_drop 等都已
// 物化在 HostConfig/Config 里，原样带过去即可。
// 容器名通过 create 接口的 ?name= query 传入，不在请求体里。
func buildCreateRequest(c *dockerContainer, image string) map[string]any {
	host := map[string]any{
		"Binds":          c.HostConfig.Binds,
		"NetworkMode":    c.HostConfig.NetworkMode,
		"ExtraHosts":     c.HostConfig.ExtraHosts,
		"Privileged":     c.HostConfig.Privileged,
		"CapAdd":         c.HostConfig.CapAdd,
		"CapDrop":        c.HostConfig.CapDrop,
		"SecurityOpt":    c.HostConfig.SecurityOpt,
		"ReadonlyRootfs": c.HostConfig.ReadonlyRootfs,
		"UsernsMode":     c.HostConfig.UsernsMode,
		"Tmpfs":          c.HostConfig.Tmpfs,
		"PortBindings":   c.HostConfig.PortBindings,
		"AutoRemove":     false,
	}
	if c.HostConfig.RestartPolicy.Name != "" {
		host["RestartPolicy"] = map[string]any{
			"Name":              c.HostConfig.RestartPolicy.Name,
			"MaximumRetryCount": c.HostConfig.RestartPolicy.MaximumRetryCount,
		}
	}
	if c.HostConfig.LogConfig.Type != "" {
		host["LogConfig"] = map[string]any{
			"Type":   c.HostConfig.LogConfig.Type,
			"Config": c.HostConfig.LogConfig.Config,
		}
	}

	// 自定义网络下把 inspect 到的 EndpointsConfig 带过去（去掉 IP/Gateway，
	// 只保留别名）；host/bridge/none 模式下 Networks 为空，不传 NetworkingConfig。
	networking := map[string]any{}
	for netName, ep := range c.NetworkSettings.Networks {
		aliases := ep.Aliases
		if len(aliases) > 0 {
			networking[netName] = map[string]any{"Aliases": aliases}
		} else {
			networking[netName] = map[string]any{}
		}
	}

	req := map[string]any{
		"Image": image,
		"HostConfig": host,
	}
	if len(c.Config.Cmd) > 0 {
		req["Cmd"] = c.Config.Cmd
	}
	if len(c.Config.Entrypoint) > 0 {
		req["Entrypoint"] = c.Config.Entrypoint
	}
	if len(c.Config.Env) > 0 {
		req["Env"] = c.Config.Env
	}
	if len(c.Config.Labels) > 0 {
		req["Labels"] = c.Config.Labels
	}
	if len(c.Config.ExposedPorts) > 0 {
		req["ExposedPorts"] = c.Config.ExposedPorts
	}
	if c.Config.User != "" {
		req["User"] = c.Config.User
	}
	if c.Config.WorkingDir != "" {
		req["WorkingDir"] = c.Config.WorkingDir
	}
	if len(networking) > 0 {
		req["NetworkingConfig"] = map[string]any{"EndpointsConfig": networking}
	}
	return req
}
