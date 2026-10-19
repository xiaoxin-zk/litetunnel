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

const dnsTimeout = 5 * time.Second

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

func (s *service) lookup(parent context.Context, name, expected string) tlscfg.DNSRecord {
	rec := tlscfg.DNSRecord{Name: name}
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

const (
	certScanMaxFiles      = 2000
	certScanMaxDepth      = 6
	certScanMaxFileBytes  = 1 << 20
	certScanBudget        = 2 * time.Second
	certScanMaxTotalBytes = 32 << 20
	certScanMaxCerts      = 500
	certScanMaxSANs       = 100
)

func (s *service) certStatus() tlscfg.CertStatus {
	root := filepath.Join(s.paths.caddyData, "certificates")
	st := tlscfg.CertStatus{}
	switch state, err := statFileState(root); state {
	case fileMissing:
		st.Reason = fmt.Sprintf("尚未发现证书：%s 不存在（Caddy 还没为任何域名签发过证书）", root)
		return st
	case fileUnknown:
		st.Reason = fmt.Sprintf("无法读取证书目录 %s（%v）：请检查权限与挂载", root, err)
		return st
	}
	st.Available = true

	var (
		walkErr       error
		scanned       int
		readByte      int64
		truncate      string
		sansTruncated bool
		started       = time.Now()
	)
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if time.Since(started) > certScanBudget {
			truncate = "遍历超时"
			return filepath.SkipAll
		}
		if err != nil {
			if walkErr == nil {
				walkErr = err
			}
			return nil
		}
		if d.IsDir() {
			if rel, rerr := filepath.Rel(root, path); rerr == nil &&
				strings.Count(rel, string(os.PathSeparator)) > certScanMaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".pem" {
			return nil
		}
		scanned++
		if scanned > certScanMaxFiles {
			truncate = fmt.Sprintf("文件数超过 %d", certScanMaxFiles)
			return filepath.SkipAll
		}
		if info, ierr := d.Info(); ierr == nil {
			if info.Size() > certScanMaxFileBytes {
				return nil
			}
			if readByte+info.Size() > certScanMaxTotalBytes {
				truncate = fmt.Sprintf("累计读取超过 %d 字节", int64(certScanMaxTotalBytes))
				return filepath.SkipAll
			}
			readByte += info.Size()
		}
		if len(st.Certs) >= certScanMaxCerts {
			truncate = fmt.Sprintf("证书数超过 %d", certScanMaxCerts)
			return filepath.SkipAll
		}
		cert, ok := parseLeafCert(path)
		if !ok {
			return nil
		}
		item, cut := toCertificate(cert, path)
		if cut {
			sansTruncated = true
		}
		st.Certs = append(st.Certs, item)
		return nil
	})
	switch {
	case walkErr != nil && len(st.Certs) == 0:
		st.Reason = fmt.Sprintf("读取证书目录失败：%v", walkErr)
	case walkErr != nil:
		st.Reason = fmt.Sprintf("证书列表可能不完整（遍历中断：%v）", walkErr)
	case len(st.Certs) == 0:
		st.Reason = "Caddy 数据目录里没有可解析的证书文件（可能还没签发成功，请查看 caddy 容器日志）"
	}
	if sansTruncated {
		note := fmt.Sprintf("部分证书的域名列表已截断（每张最多列出 %d 个）", certScanMaxSANs)
		if st.Reason != "" {
			st.Reason += "；" + note
		} else {
			st.Reason = note
		}
	}
	if truncate != "" {
		note := fmt.Sprintf("证书列表已截断（%s），仅扫描前 %d 个文件", truncate, scanned)
		if st.Reason != "" {
			st.Reason += "；" + note
		} else {
			st.Reason = note
		}
	}
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

func toCertificate(cert *x509.Certificate, path string) (tlscfg.Certificate, bool) {
	domain := cert.Subject.CommonName
	if domain == "" && len(cert.DNSNames) > 0 {
		domain = cert.DNSNames[0]
	}
	kind := "unknown"
	switch {
	case strings.Contains(filepath.ToSlash(path), "/acme/"):
		kind = "acme"
	case strings.Contains(filepath.ToSlash(path), "/local/"):
		kind = "local"
	}
	names := cert.DNSNames
	cut := false
	if len(names) > certScanMaxSANs {
		names = names[:certScanMaxSANs]
		cut = true
	}
	return tlscfg.Certificate{
		Domain:    domain,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
		Kind:      kind,
		Names:     names,
	}, cut
}
