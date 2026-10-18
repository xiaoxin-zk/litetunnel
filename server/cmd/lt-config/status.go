package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xiaoxin-zk/litetunnel/server/internal/tlscfg"
)

// dnsTimeout 是单条记录解析的超时。
//
// 给得短是有意的：DNS 检查出现在设置页上，一条查不通的记录
// 不该让整个页面转圈一分钟。
const dnsTimeout = 5 * time.Second

// maxCheckNames 限制一次检查解析多少条记录，避免被当成 DNS 放大工具。
const maxCheckNames = 20

func (s *service) handleDNSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 POST"))
		return
	}
	var req tlscfg.DNSCheckRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		failJSON(w, http.StatusBadRequest, errors.New("请求体格式不正确"))
		return
	}
	if len(req.Names) == 0 {
		failJSON(w, http.StatusBadRequest, errors.New("请至少提供一个域名"))
		return
	}
	if len(req.Names) > maxCheckNames {
		failJSON(w, http.StatusBadRequest, fmt.Errorf("一次最多检查 %d 个域名", maxCheckNames))
		return
	}

	records := make([]tlscfg.DNSRecord, 0, len(req.Names))
	for _, name := range req.Names {
		// 客户端断开就停手：每条记录最多查 5 秒，20 条串起来近两分钟。
		// 没有这个检查，管理员关掉页面后这些查询仍会一条条跑完，
		// 反复点「检查」就叠出一堆后台任务。
		if err := r.Context().Err(); err != nil {
			break
		}
		name = strings.TrimSpace(name)
		if name == "" || len(name) > 253 {
			continue
		}
		records = append(records, s.lookup(r.Context(), name, strings.TrimSpace(req.ExpectedIP)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": records})
}

// lookup 解析一条记录并给出可操作的提示。
//
// 提示不是客套话：DNS 是这套部署里**唯一**没法用代码兜底的环节
// （证书签不下来、网站打不开，根因十有八九在这里），
// 把「下一步该看什么」直接写进结果，能省掉一轮来回问。
func (s *service) lookup(parent context.Context, name, expected string) tlscfg.DNSRecord {
	rec := tlscfg.DNSRecord{Name: name}
	// 单条仍受 dnsTimeout 限制，但父上下文（请求）被取消时立即结束：
	// 客户端已经走了，没有人在等这份结果。
	ctx, cancel := context.WithTimeout(parent, dnsTimeout)
	defer cancel()

	ips, err := s.resolver().LookupHost(ctx, name)
	if err != nil {
		rec.Error = err.Error()
		switch {
		case strings.Contains(err.Error(), "no such host"):
			rec.Hint = "没有解析记录：请在 DNS 服务商处为该域名添加 A 记录（或 CNAME 到已有记录）"
		case strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline"):
			rec.Hint = "解析超时：检查本机 DNS 配置，或换个解析服务器再试"
		default:
			rec.Hint = "解析失败，请确认域名拼写与服务商侧的记录状态"
		}
		return rec
	}
	for _, ip := range ips {
		rec.IPs = append(rec.IPs, ip)
	}
	sort.Strings(rec.IPs)

	// CNAME 链单独查一次：解析出的地址与预期不符时，别名往往是原因
	// （CNAME 指向 CDN 或旧服务器，改 A 记录当然不生效）。
	if cname, err := s.resolver().LookupCNAME(ctx, name); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(cname, name) {
			rec.CNAME = cname
		}
	}

	switch {
	case expected == "":
		rec.Hint = ""
	case hasIP(rec, expected):
		rec.Matched = true
		rec.Hint = "解析结果与期望地址一致"
	case rec.CNAME != "":
		rec.Hint = fmt.Sprintf("解析结果不含 %s，且存在别名 %s：记录很可能指向了 CDN 或另一台服务器", expected, rec.CNAME)
	default:
		rec.Hint = fmt.Sprintf("解析结果不含期望地址 %s：请修改 DNS 记录，或确认填写的期望地址是否正确", expected)
	}
	return rec
}

func hasIP(r tlscfg.DNSRecord, want string) bool {
	wantIP := net.ParseIP(want)
	if wantIP == nil {
		return false
	}
	for _, got := range r.IPs {
		if ip := net.ParseIP(got); ip != nil && ip.Equal(wantIP) {
			return true
		}
	}
	return false
}

// resolver 返回用于检查的解析器。
//
// 默认用系统的；LT_CFG_DNS_SERVER 可以指定（例如 223.5.5.5）——
// 服务器自身的解析器被改坏时，检查结果会误导管理员去改本来就正确的记录。
func (s *service) resolver() *net.Resolver {
	server := strings.TrimSpace(os.Getenv("LT_CFG_DNS_SERVER"))
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dnsTimeout}
			return d.DialContext(ctx, network, server)
		},
	}
}

func (s *service) handleCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		failJSON(w, http.StatusMethodNotAllowed, errors.New("仅支持 GET"))
		return
	}
	status := s.certStatus()
	writeJSON(w, http.StatusOK, status)
}

// certStatus 扫描 Caddy 的证书存储目录。
//
// 为什么不问 Caddy：它的 admin API 是关闭的（这是刻意的，见包注释），
// 而证书本来就落在磁盘上。直接读文件既不需要开任何接口，
// 也能读出**实际**在用的那份证书——包括它到底覆盖了哪些域名。
func (s *service) certStatus() tlscfg.CertStatus {
	root := filepath.Join(s.paths.caddyData, "certificates")
	st := tlscfg.CertStatus{}
	// 三态（见 statcheck.go）：目录不存在与读不了是两件事。把「权限不足」
	// 报成「尚未发现证书」，会把管理员引去查 Caddy 的签发日志，而真正该
	// 看的是这个目录的权限与挂载。
	switch state, err := statFileState(root); state {
	case fileMissing:
		st.Reason = fmt.Sprintf("尚未发现证书：%s 不存在（Caddy 还没为任何域名签发过证书）", root)
		return st
	case fileUnknown:
		st.Reason = fmt.Sprintf("无法读取证书目录 %s（%v）：请检查权限与挂载", root, err)
		return st
	}
	st.Available = true

	// 回调吞掉单条错误是为了「一棵子树读不了不要拖垮整份列表」，
	// 但吞掉之后 WalkDir 的返回值和「一切正常」就分不出来了，
	// 所以这里自己记住第一个失败，供下面的诊断文案使用。
	var walkErr error
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if walkErr == nil {
				walkErr = err
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".pem" {
			return nil
		}
		cert, ok := parseLeafCert(path)
		if !ok {
			return nil
		}
		st.Certs = append(st.Certs, toCertificate(cert, path))
		return nil
	})

	// 遍历失败（权限不足、IO 错误）与「目录里确实没有证书」是两种完全不同的状况：
	// 前者报成「还没签发成功」会把管理员引向错误的方向去查 Caddy 日志。
	switch {
	case walkErr != nil && len(st.Certs) == 0:
		st.Reason = fmt.Sprintf("读取证书目录失败：%v", walkErr)
	case walkErr != nil:
		st.Reason = fmt.Sprintf("证书列表可能不完整（遍历中断：%v）", walkErr)
	case len(st.Certs) == 0:
		st.Reason = "Caddy 数据目录里没有可解析的证书文件（可能还没签发成功，请查看 caddy 容器日志）"
	}
	// 最快到期的排最前：这才是管理员需要动手的那一张。
	sort.Slice(st.Certs, func(i, j int) bool {
		return st.Certs[i].NotAfter < st.Certs[j].NotAfter
	})
	return st
}

func parseLeafCert(path string) (*x509.Certificate, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return nil, false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		return cert, true
	}
}

func toCertificate(cert *x509.Certificate, path string) tlscfg.Certificate {
	domain := cert.Subject.CommonName
	if domain == "" && len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}
	kind := "unknown"
	// Caddy 的目录结构：<data>/certificates/<acme|local>/<issuer>/<域名>/<域名>.crt
	switch {
	case strings.Contains(filepath.ToSlash(path), "/acme/"):
		kind = "acme"
	case strings.Contains(filepath.ToSlash(path), "/local/"):
		kind = "local"
	}
	return tlscfg.Certificate{
		Domain:    domain,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
		Kind:      kind,
		Names:     cert.DNSNames,
	}
}
