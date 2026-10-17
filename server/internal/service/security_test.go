package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/config"
	"github.com/xiaoxin-zk/litetunnel/server/internal/model"
	"github.com/xiaoxin-zk/litetunnel/server/internal/store"
)

// 这个文件守的都是同一类缺陷：**一处改了、另一处没跟上**。
//
// 单看任何一处代码都是对的，只有把数据库、运行态内存与采集循环串起来
// 才会暴露。所以这些用例都起真实的 sqlite 库与真实服务集合，
// 而不是把函数拆出来单独喂参数。

// markTrafficBaselineReady 声明「采样基线已经建立」。
//
// collectTraffic 每次取得采集租约都会重读一次基线；没有这个标记时，
// loadTrafficBaseline 会把它当成**首次迁移**（只记基线、不计增量），
// 于是首轮采集不记账——这些用例要测的是记账，所以先落下标记。
func markTrafficBaselineReady(t *testing.T, svc *Services) {
	t.Helper()
	// 两个迁移标记都要落：基线就绪与「清零代次标记已初始化」是独立状态，
	// 缺任一个首轮都只记基线、不计增量。
	if err := svc.Settings.SetInternal(map[SettingKey]string{
		KeyTrafficBaselineReady:  "1",
		KeyTrafficResetMarkReady: "1",
	}); err != nil {
		t.Fatalf("写迁移标记失败: %v", err)
	}
}

func newTestServices(t *testing.T, cfg *config.Config) *Services {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cfg.Env = "test"
	cfg.LogLevel = "warn"
	cfg.DBDriver = "sqlite"
	if cfg.DBDSN == "" {
		cfg.DBDSN = filepath.Join(t.TempDir(), "test.db")
	}
	if cfg.APIKeyEncKey == "" {
		cfg.APIKeyEncKey = "test-api-key-enc"
	}

	db, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取数据库连接失败: %v", err)
	}
	// 先关连接再让 t.TempDir 清理：否则临时目录里的 sqlite 文件仍被占用，
	// 清理会失败（Windows 上尤其明显）。Cleanup 是后进先出，
	// 这里注册的比 TempDir 的晚，所以会先执行。
	t.Cleanup(func() { _ = sqlDB.Close() })
	return New(db, cfg)
}

func mustAdmin(t *testing.T, svc *Services, username, role string) *model.Admin {
	t.Helper()
	a, err := svc.CreateAdmin(AdminCreateInput{
		Username: username,
		Password: "AdminPass12345",
		Role:     role,
	})
	if err != nil {
		t.Fatalf("建管理员 %s 失败: %v", username, err)
	}
	return a
}

func loadAdmin(t *testing.T, svc *Services, id uint) model.Admin {
	t.Helper()
	var a model.Admin
	if err := svc.DB.First(&a, id).Error; err != nil {
		t.Fatalf("读管理员失败: %v", err)
	}
	return a
}

// newSuperAdmin 造一个启用的超级管理员。
func newSuperAdmin(t *testing.T, svc *Services, name string) *model.Admin {
	t.Helper()
	a := &model.Admin{
		Username: name, Password: "not-used", Nickname: name,
		Role: "super", Status: "active", TokenVersion: 1,
	}
	if err := svc.DB.Create(a).Error; err != nil {
		t.Fatalf("建管理员 %s 失败: %v", name, err)
	}
	return a
}

// countActiveSupers 数一下还剩几个可用的超级管理员。
func countActiveSupers(t *testing.T, svc *Services) int64 {
	t.Helper()
	var n int64
	if err := svc.DB.Model(&model.Admin{}).
		Where("role = ? AND status = ?", "super", "active").
		Count(&n).Error; err != nil {
		t.Fatalf("统计超级管理员失败: %v", err)
	}
	return n
}

// enableTestMail 打开测试用的邮件配置，并确认 MailEnabled 成立。
func enableTestMail(t *testing.T, svc *Services) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeySMTPEnabled:  "true",
		KeySMTPHost:     "smtp.example.com",
		KeySMTPPort:     "587",
		KeySMTPUser:     "noreply@example.com",
		KeySMTPPassword: "secret",
		KeySMTPFrom:     "noreply@example.com",
	}); err != nil {
		t.Fatalf("设置邮件配置失败: %v", err)
	}
	if !svc.MailEnabled() {
		t.Fatal("前置条件：邮件应已启用")
	}
}

// fakeMailer 是可控的发信替身：用它把「投递成功」与「投递失败」变成确定性的。
type fakeMailer struct {
	mu   sync.Mutex
	fail bool
	sent []string
}

func (f *fakeMailer) Send(ctx context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("smtp 不可用")
	}
	f.sent = append(f.sent, to)
	return nil
}

func (f *fakeMailer) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *fakeMailer) sentCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// newMailTestServices 构造一个邮件已启用、发信器可替换的服务集合。
func newMailTestServices(t *testing.T) (*Services, *fakeMailer) {
	t.Helper()
	svc := newTestServices(t, nil)
	enableTestMail(t, svc)
	fm := &fakeMailer{}
	svc.mailerOverride = fm
	return svc, fm
}

// deliverAll 驱动一次发件箱处理（正常路径由后台协程做，这里直接调用以便断言）。
func deliverAll(svc *Services) {
	svc.processMailOutbox(context.Background())
}

// enableTestFirewall 打开测试用的防火墙配置并指向假 helper。
func enableTestFirewall(t *testing.T, svc *Services, helper *fakeFirewallHelper) {
	t.Helper()
	if err := svc.Settings.SetMany(map[SettingKey]string{
		KeyFirewallEnabled:     "true",
		KeyFirewallAutoOpen:    "true",
		KeyFirewallHelperAddr:  helper.URL,
		KeyFirewallHelperToken: "test-token",
	}); err != nil {
		t.Fatalf("设置防火墙配置失败: %v", err)
	}
}

// fakeFirewallHelper 冒充宿主机上的 lt-fw helper，记录收到的关端口请求。
//
// 面板自身没有任何防火墙写能力（全部转发给 helper），所以这里假的是 helper，
// 而不是「防火墙」——这样测到的就是真实那条转发链路。
type fakeFirewallHelper struct {
	*httptest.Server

	// failCloses / failOpens 为 true 时对应操作一律失败，用于模拟 helper 暂时不可用。
	failCloses atomic.Bool
	failOpens  atomic.Bool

	// closeEntered / closeGate 用于把「关端口」这一步卡住：
	// 进入处理时向 closeEntered 发信号，然后等 closeGate 才返回。
	// 用来在「重试执行到一半」时插入别的操作，验证临界区。
	closeEntered chan struct{}
	closeGate    chan struct{}

	mu     sync.Mutex
	opened []string
	closed []string
}

func newFakeFirewallHelper(t *testing.T) *fakeFirewallHelper {
	t.Helper()
	f := &fakeFirewallHelper{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			_, _ = w.Write([]byte(`{"backend":"nft","available":true,"enabled":true}`))
		case "/ports/close":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.closeEntered != nil {
				select {
				case f.closeEntered <- struct{}{}:
				default:
				}
			}
			if f.closeGate != nil {
				<-f.closeGate
			}
			if f.failCloses.Load() {
				// 模拟 helper 暂时不可用：面板必须把这次失败记下来重试，
				// 而不是只写一行日志就当成关掉了。
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.closed = append(f.closed, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/ports/open":
			var body struct {
				Port  int    `json:"port"`
				Proto string `json:"proto"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if f.failOpens.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			f.mu.Lock()
			f.opened = append(f.opened, fmt.Sprintf("%d/%s", body.Port, body.Proto))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeFirewallHelper) closedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.closed))
	copy(out, f.closed)
	return out
}

func (f *fakeFirewallHelper) openedPorts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.opened))
	copy(out, f.opened)
	return out
}

// backdateSession 把某条会话的活跃时间往前拨，用于确定性地制造「久未活动」。
//
// 不用「GC(0)」这种把截止时刻设成现在的写法：它依赖两次 time.Now()
// 之间有可分辨的间隔，时钟粒度不足时会随机失败。
func backdateSession(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[runID]
	if !ok {
		t.Fatalf("前置条件不成立：会话 %s 不存在", runID)
	}
	s.LastSeen = s.LastSeen.Add(-by)
	r.sessions[runID] = s
}

// backdateTouchAt 把某条心跳节流记录的时间往前拨。
func backdateTouchAt(t *testing.T, r *Runtime, runID string, by time.Duration) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.touchAt[runID]
	if !ok {
		t.Fatalf("前置条件不成立：节流记录 %s 不存在", runID)
	}
	r.touchAt[runID] = at.Add(-by)
}

// fakeFrpsTraffic 是只上报一条代理的假 frps，累计流量可改。
type fakeFrpsTraffic struct {
	*httptest.Server
	total atomic.Int64
	// absent 为真时这一轮列表里没有该代理：模拟客户端重连、或分页期间
	// 一删一增造成的短暂缺席。
	absent atomic.Bool
}

func newFakeFrpsTraffic(proxy string) *fakeFrpsTraffic {
	f := &fakeFrpsTraffic{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if f.absent.Load() {
			_, _ = w.Write([]byte(
				`{"code":200,"msg":"success","data":{"total":0,"page":1,"pageSize":200,"items":[]}}`))
			return
		}
		fmt.Fprintf(w,
			`{"code":200,"msg":"success","data":{"total":1,"page":1,"pageSize":200,"items":[{"name":%q,"status":{"phase":"online","todayTrafficIn":%d,"todayTrafficOut":0,"curConns":0}}]}}`,
			proxy, f.total.Load())
	}))
	return f
}

func tunnelTrafficUsed(t *testing.T, svc *Services, id uint) int64 {
	t.Helper()
	var tun model.Tunnel
	if err := svc.DB.First(&tun, id).Error; err != nil {
		t.Fatalf("读隧道失败: %v", err)
	}
	return tun.TrafficUsed
}
