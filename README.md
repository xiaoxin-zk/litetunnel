# LiteTunnel

[![CI](https://github.com/xiaoxin-zk/litetunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/xiaoxin-zk/litetunnel/actions/workflows/ci.yml)

轻量内网穿透平台。以 [frp](https://github.com/fatedier/frp) 为数据面内核，自研轻量控制面，
面向游戏联机、内网网站与 NAS 映射场景。单台公网服务器即可承载，全程 Docker 部署。

---

## 一、能力概览

| 模块 | 说明 |
|---|---|
| 用户控制台 | 隧道管理、流量曲线、API Key、兑换码、客户端下载、账号资料自助修改、邮箱找回密码、账号注销 |
| 管理后台 | 用户与分组管理、流量限制、兑换码、审计与登录日志、管理员与双因素、域名与证书 |
| 隧道类型 | TCP / UDP（游戏、NAS）、HTTP / HTTPS（内网网站） |
| Windows 客户端 | Wails + Vue 单文件 exe，粘贴 API Key 即可接入，内置 frpc 托管与自动同步 |
| 流量治理 | 按分组配额、按隧道限速、超额实时断流 |

## 二、架构

```
                   公网用户 / 游戏玩家
                           │
      ┌────────────────────┴───────────────────┐
  Caddy (80/443)                        frps 隧道端口池
  ├─ /            用户控制台              20000-30000 (TCP+UDP)
  └─ /lt-console  管理后台                        │
           │ 127.0.0.1:7848                       │ 7001/TCP 7002/UDP
           ▼                                      │
  ┌────────────────────────────────────────┐      │
  │ panel：控制面 API + 静态资源 + 插件回调 │◄─────┘
  └────────────────────────────────────────┘
           │
      SQLite（WAL）
```

面板只监听回环地址，公网流量统一由 Caddy 进入；隧道端口由 frps 直接承接。

## 三、目录结构

```
server/            Go 控制面（cmd/panel 入口，cmd/lt-fw、cmd/lt-config 为宿主机 helper）
web/user/          用户控制台（Vue）
web/admin/         管理后台（Vue）
client/windows/    Windows 客户端（Wails）
deploy/            compose、frps / Caddy 模板与渲染脚本
```

---

## 四、快速开始

### 本地开发

```bash
cp .env.example .env
cd server && go mod tidy && go run ./cmd/panel

cd web/user  && npm install && npm run dev   # http://localhost:5173
cd web/admin && npm install && npm run dev   # http://localhost:5175
```

默认管理员账号取自 `.env` 的 `LT_BOOTSTRAP_ADMIN_USER` / `LT_BOOTSTRAP_ADMIN_PASSWORD`。

### 生产部署

镜像由 GitHub Actions 构建并推送到 GHCR，服务器只负责拉取运行，见下方部署手册。

---

## 五、部署手册

### 步骤 0：服务器准备

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

国内服务器建议配置 Docker Hub 镜像加速（`/etc/docker/daemon.json` 的 `registry-mirrors`）。

### 步骤 1：拉取代码

```bash
git clone https://github.com/xiaoxin-zk/litetunnel.git
cd litetunnel
```

### 步骤 2：生成配置

```bash
cp .env.example .env

# 一键生成密钥，把输出粘贴进 .env
for k in LT_USER_JWT_SECRET LT_ADMIN_JWT_SECRET LT_APIKEY_ENC_KEY LT_FRPS_TOKEN LT_FRPS_API_PASSWORD; do
  echo "$k=$(openssl rand -hex 32)"
done
echo "LT_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 15 | tr -d '/+=')"
```

必填项：

| 变量 | 说明 |
|---|---|
| `LT_ENV` | 填 `production` |
| `LT_USER_PUBLIC_URL` | 控制台对外地址。`https://panel.example.com` 自动申请证书；`http://1.2.3.4` 为无域名时的明文模式 |
| `LT_GATEWAY_HOST` | 客户端接入地址，填域名或公网 IP |
| `LT_ACME_EMAIL` | 证书通知邮箱（HTTP 模式下不使用） |
| 上面生成的 6 个密钥 | 直接粘贴 |

可选：`LT_TUNNEL_DOMAIN`（启用 HTTP/HTTPS 隧道时填裸域名，如 `tunnel.example.com`）、
`LT_CADDY_DNS_PROVIDER`（泛域名证书的 DNS 服务商，如 `cloudflare`）、
`LT_HTTPS_TUNNEL_MODE`（`edge` 默认 / `e2e`）。

### 步骤 3：渲染配置

```bash
bash deploy/scripts/render.sh
# Windows: powershell -ExecutionPolicy Bypass -File deploy/scripts/render.ps1
```

生成 `deploy/frps/frps.toml` 与 `deploy/caddy/Caddyfile`（均已被 gitignore）。
脚本会校验必填项并拒绝 `CHANGE_ME` 占位符。

> 启用 HTTP/HTTPS 隧道时，泛域名证书需要 DNS Challenge，官方 `caddy:2-alpine` 不带插件，
> 需按 `deploy/caddy/Dockerfile` 自行构建镜像，并在 `.env` 里把 `LT_CADDY_IMAGE`
> 指向构建结果。具体步骤见 `deploy/docker-compose.yml` 中 caddy 段的注释。

### 步骤 3.5：后台改域名（可选）

不改也能用。若希望在管理后台修改域名 / DNS 凭据，需要额外安装宿主机 helper：

```bash
cd server && go build -o /usr/local/bin/lt-config ./cmd/lt-config
mkdir -p /etc/litetunnel
cp deploy/systemd/lt-config.env.example /etc/litetunnel/lt-config.env
vi /etc/litetunnel/lt-config.env          # 填 LT_CFG_TOKEN 与 LT_CFG_DEPLOY_DIR
cp deploy/systemd/lt-config.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now lt-config
```

然后在 **管理后台 → 域名与证书** 里填写面板域名、隧道根域名、DNS 服务商与凭据。
「保存并校验」只校验不落盘，「保存并应用」才会写盘并重建 `caddy` 与 `frps`。

### 步骤 4：启动

```bash
docker compose --env-file .env -f deploy/docker-compose.yml pull
docker compose --env-file .env -f deploy/docker-compose.yml up -d
docker compose --env-file .env -f deploy/docker-compose.yml ps
```

> `--env-file .env` 不能省：`.env` 在仓库根目录，Compose 默认只找 compose 文件所在目录。

### 步骤 5：验证

```bash
curl -fsS http://127.0.0.1:7848/healthz && echo
docker compose --env-file .env -f deploy/docker-compose.yml logs panel | head -30
```

首次启动会打印初始管理员账号。

### 步骤 6：放行端口与解析域名

| 端口 | 协议 | 用途 |
|---|---|---|
| 80 | TCP | 证书校验与 HTTP 访问 |
| 443 | TCP | HTTPS 控制台与网站隧道 |
| 7001 | TCP | 客户端接入 |
| 7002 | UDP | KCP 加速（游戏联机建议开） |
| 20000-30000 | TCP+UDP | 隧道端口池 |
| 8444 | TCP | 端到端 HTTPS 隧道（仅 `e2e` 模式） |
| 8081 | TCP | 网站隧道的 HTTP 入口（`LT_VHOST_HTTP_PORT`），Caddy 与外部都可直接访问 |

`7848` 与 `7500` 是内部端口，**不要对公网放行**。

> 网站隧道入口同时被 Caddy（走 `127.0.0.1`）和外部请求使用：外部可以用
> `Host: <子域>.隧道域名` 直接访问，此时不经过 Caddy，也就没有 TLS。
> 这是该入口的设计行为，默认对公网开放。
>
> 若不需要 `IP:8081` 直连、只想让 Caddy 使用，可只封非回环来源：
>
> ```bash
> iptables -I INPUT ! -i lo -p tcp --dport 8081 -j DROP
> # 或 nft：
> nft add rule inet filter input iifname != "lo" tcp dport 8081 drop
> ```
>
> 必须带 `! -i lo`，否则 Caddy 的本机转发也会被挡住。
>
> 无法在 frp 配置里把它绑到回环：frp 的 `proxyBindAddr` 同时用于绑定隧道端口池，
> 设成 `127.0.0.1` 会让所有 TCP/UDP 隧道失去公网入口。
>
> 没有域名时 HTTP 隧道不可用（vhost 需要 `Host`），请把本地网站映射成 **TCP 隧道**，
> 用 `http://服务器IP:<分配的远程端口>` 访问；那条路径不经过 8081。

DNS：控制台域名 A 记录指向服务器；启用隧道域名时，`*.隧道域名` 按需解析。

### 步骤 7：登录

| 入口 | 地址 |
|---|---|
| 用户控制台 | `协议://你的域名/`（协议取自 `LT_USER_PUBLIC_URL`） |
| 管理后台 | `协议://你的域名/lt-console/` |

> **没有域名或无法备案时**：把 `LT_USER_PUBLIC_URL` 写成 `http://服务器公网IP` 重新渲染即可。
> 该模式不申请证书、不发送 HSTS，登录令牌与 API Key 明文传输，建议仅在可信网络使用。

管理员与普通用户是两套独立账号，用户控制台的账号**无法**登录管理后台。

登录后请立刻修改管理员密码，并启用双因素认证（TOTP）。
可选用 `LT_ADMIN_ALLOW_CIDR` 把管理后台限制到指定网段。

### 步骤 8：分发客户端

从 Releases 下载 `LiteTunnel-windows-amd64.zip`，或把 CI 产物放进服务器的
`deploy/data/panel/clients` 目录，用户控制台「客户端」页会自动列出。

客户端只需粘贴 API Key。服务地址在发版时通过仓库 Secret `LT_CLIENT_SERVER` 注入；
未注入的调试构建会显示地址输入框作为兜底。

---

## 六、配置项

完整列表见 `.env.example`。几处约束：

- `LT_USER_JWT_SECRET` 与 `LT_ADMIN_JWT_SECRET` 必须不同，长度不少于 24；
- `LT_APIKEY_ENC_KEY` 需为 32 或 64 个字符；
- `LT_ADMIN_ALLOW_CIDR` 留空表示管理后台对公网开放，建议配合双因素使用；
- `LT_GATEWAY_HOST` 是下发给客户端的连接地址，只写进 `.env`。

---

## 七、常见问题

**Q：客户端提示「客户端凭据无效」？**
在管理后台对该用户执行「重置客户端凭据」，然后重新登录客户端。

**Q：隧道在线但访问不通？**
检查安全组是否放行了对应隧道端口，TCP 与 UDP 都要放行。

**Q：游戏联机延迟高？**
优先使用 KCP 端口（`LT_KCP_PORT`），确保该 UDP 端口已放行，并选择离玩家更近的节点。

**Q：HTTP 隧道访问 404？**
确认 `*.你的隧道域名` 已解析到本机，且 `LT_CADDY_DNS_PROVIDER` 已配置、
Caddy 使用的是带对应插件的镜像。出现 `unrecognized directive: dns` 说明镜像还是官方的。

**Q：HTTPS 隧道提示证书不匹配？**
`e2e` 模式必须用 `<子域>.隧道域名:8444` 访问；443 由 Caddy 接管，返回平台自己的证书。
`edge` 模式下请使用 HTTP 隧道，本地网站继续用 HTTP。

**Q：忘记管理员密码？**
`lt_admins` 表为空时才会重新播种。清空该表后重启 panel：

```bash
docker compose -f deploy/docker-compose.yml stop panel
# 用 SQLite 客户端打开 deploy/data/panel/litetunnel.db 执行：
#   DELETE FROM lt_admins;
docker compose -f deploy/docker-compose.yml start panel
```

**Q：认证器丢了，登不进管理后台？**
若还有另一个超级管理员，在后台「管理员」页重置 2FA 即可；否则清空该管理员的
`totp_enabled` / `totp_secret` / `totp_pending_secret` 字段后重启。

**Q：怎么配置 QQ 邮箱发信（找回密码）？**

```ini
LT_SMTP_HOST=smtp.qq.com
LT_SMTP_PORT=465
LT_SMTP_TLS=ssl
LT_SMTP_USER=你的QQ号@qq.com
LT_SMTP_PASS=授权码
LT_SMTP_FROM=LiteTunnel <你的QQ号@qq.com>
```

未配置时找回密码功能自动禁用，并提示联系管理员。国内服务器建议用 465(SSL) 或 587(STARTTLS)。

**Q：从旧版本升级要注意什么？**
`LT_USER_PUBLIC_URL` 在 `production` 下为必填；凭据轮换或重置密码后，已下发的客户端需要
重新获取配置；改动双因素会作废该管理员的既有登录会话。数据库表结构启动时自动迁移。

---

## 八、许可

数据面内核 [fatedier/frp](https://github.com/fatedier/frp) 采用 Apache-2.0。
