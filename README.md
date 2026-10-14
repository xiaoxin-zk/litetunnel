# LiteTunnel

[![CI](https://github.com/xiaoxin-zk/litetunnel/actions/workflows/ci.yml/badge.svg)](https://github.com/xiaoxin-zk/litetunnel/actions/workflows/ci.yml)

轻量内网穿透平台。以 **frp v0.71** 为数据面内核，自研轻量控制面，面向游戏联机、内网网站与 NAS 映射场景。

单台公网服务器即可承载，全程 Docker 部署，管理后台与用户控制台**物理隔离**。
所有构建产物均由 GitHub Actions 产出，服务器只负责拉取运行。

---

## 一、能力概览

| 模块 | 说明 |
|---|---|
| 用户控制台 | 隧道管理、流量曲线、API Key、兑换码、客户端下载 |
| 管理后台 | 用户禁用/删除、流量限制、分组权限、兑换码生成、审计日志 |
| 隧道类型 | TCP / UDP（游戏、NAS）、HTTP / HTTPS（内网网站） |
| Windows 客户端 | Wails + Vue 单文件 exe，一键登录、自动同步配置、内置 frpc 托管 |
| 多用户 | 每用户独立接入凭据，可单独吊销 |
| 流量治理 | 按分组配额、按隧道限速、超额实时断流 |
| 审计 | 全部管理操作落库，含来源 IP |

## 二、架构

```
                    公网用户 / 游戏玩家
                            │
        ┌───────────────────┴────────────────────┐
   Caddy (80/443 自动证书)              frps 隧道端口池
   用户控制台 / 网站 vhost               20000-30000 (TCP+UDP)
        │                                        │
        │  127.0.0.1:7848                        │ 7001/TCP  7002/UDP
        ▼                                        │
   ┌─────────────────────────────────────────┐   │
   │  panel（控制面，单二进制）               │   │
   │   · 用户 API（对公网）                   │   │
   │   · 管理 API（仅回环 127.0.0.1:8443）    │   │
   │   · frps 插件回调（仅回环）              │◄──┘ 鉴权 / 审批 / 断流
   │   · 流量采集器（轮询 frps admin API）    │
   └─────────────────────────────────────────┘
        │
   SQLite（WAL）
```

### 隔离设计（三重）

1. **网络层**：用户侧与控制面同进程但不同端口；管理端口默认只监听 `127.0.0.1`，公网不可达。
2. **令牌层**：用户域与管理域使用**不同 JWT 密钥**且 `aud` 不同，用户令牌在管理接口上必然校验失败。
3. **路由层**：管理路由只注册在管理监听地址上，公网端口根本不存在这些路径。

### 为什么用 frps 服务端插件

frp 的服务端插件回调是整个平台的信任边界，所有关键校验都在这里完成：

| 回调 | 作用 |
|---|---|
| `Login` | 校验 `metadatas.token`（每用户独立凭据），拒绝伪造身份 |
| `NewProxy` | 校验隧道归属、协议、远程端口，并**由服务端强制下发限速** |
| `NewUserConn` | 超额时实时拒绝新建连接，实现按配额断流 |
| `Ping` | 刷新会话心跳 |
| `CloseProxy` / `NewWorkConn` | 生命周期记录 |

> 限速通过覆盖 `bandwidth_limit` + 固定 `bandwidth_limit_mode = "server"` 实现，
> 客户端即使自行修改 frpc.toml 也无法绕过。

---

## 三、目录结构

```
.
├── server/                     Go 控制面
│   ├── cmd/panel/              入口（同时监听用户侧与管理侧）
│   ├── internal/
│   │   ├── config/             环境变量配置与生产环境强校验
│   │   ├── model/              持久化实体
│   │   ├── store/              连接、迁移、播种
│   │   ├── auth/               口令哈希、双域 JWT、API Key 加解密
│   │   ├── middleware/         安全头、限流、双域鉴权
│   │   ├── service/            业务逻辑 + frps 插件运行时 + 流量采集
│   │   ├── handler/
│   │   │   ├── userapi/        用户控制台 API
│   │   │   ├── adminapi/       管理后台 API
│   │   │   └── frpsplugin/     frps 服务端插件回调
│   │   └── router/             两套路由装配
│   └── Dockerfile
├── web/
│   ├── user/                   用户控制台（Vue3 + Element Plus）
│   └── admin/                  管理后台（Vue3 + Element Plus）
├── client/windows/             Windows 客户端（Wails + Vue）
├── deploy/
│   ├── docker-compose.yml
│   ├── frps/frps.toml.template
│   ├── caddy/Caddyfile.template
│   └── scripts/render.{ps1,sh}
├── scripts/
│   ├── build.ps1               可选：本地调试构建（正式产物由 CI 产出）
│   └── check-secrets.ps1       提交前检查硬编码地址
├── .github/workflows/
│   ├── ci.yml                  推送即校验：Go 检查、前端构建、客户端构建、镜像构建
│   └── release.yml             打 tag 即发布：推送 GHCR 镜像 + 打包 Release 产物
└── .env.example                全部配置项模板
```

---

## 四、快速开始

### 1. 本地开发

```bash
# 控制面（开发模式会自动放宽密钥校验）
cp .env.example .env
cd server && go mod tidy && go run ./cmd/panel
```

前端分别启动：

```bash
cd web/user  && npm install && npm run dev   # http://localhost:5173
cd web/admin && npm install && npm run dev   # http://localhost:5175
```

默认管理员账号为 `.env` 中的 `LT_BOOTSTRAP_ADMIN_USER` / `LT_BOOTSTRAP_ADMIN_PASSWORD`，
**首次登录后请立即修改**。

### 2. 生产部署（Docker）

镜像由 GitHub Actions 构建并推送到 GHCR，服务器只负责拉取运行。
完整流程见下方「部署手册」。

> 若需要在本机从源码构建，取消 `deploy/docker-compose.yml` 中 `build:` 段落的注释，
> 然后执行 `docker compose -f deploy/docker-compose.yml up -d --build`。

---

## 五、部署手册

### 步骤 0：服务器准备

```bash
# 安装 Docker（官方脚本）
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

# 国内服务器必须配置 Docker Hub 镜像加速，否则拉不动 frps 与 caddy
sudo tee /etc/docker/daemon.json >/dev/null <<'EOF'
{
  "registry-mirrors": [
    "https://<你的ID>.mirror.aliyuncs.com",
    "https://docker.m.daocloud.io"
  ]
}
EOF
sudo systemctl restart docker
```

阿里云的专属加速地址在「容器镜像服务 → 镜像工具 → 镜像加速器」中获取。

### 步骤 1：拉取代码

```bash
git clone https://github.com/xiaoxin-zk/litetunnel.git
cd litetunnel
```

### 步骤 2：生成配置

```bash
cp .env.example .env

# 一键生成全部密钥，把输出粘贴进 .env
for k in LT_USER_JWT_SECRET LT_ADMIN_JWT_SECRET LT_APIKEY_ENC_KEY LT_FRPS_TOKEN LT_FRPS_API_PASSWORD; do
  echo "$k=$(openssl rand -hex 32)"
done
echo "LT_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -base64 15 | tr -d '/+=')"
```

必填项：

| 变量 | 说明 |
|---|---|
| `LT_ENV` | **必须是 `production`**，否则启动时会放宽安全校验并告警 |
| `LT_USER_PUBLIC_URL` | 控制台域名，如 `https://panel.example.com`（Caddy 靠它签证书） |
| `LT_GATEWAY_HOST` | 客户端接入地址，填域名或公网 IP |
| `LT_ACME_EMAIL` | Let's Encrypt 通知邮箱 |
| 上面生成的 6 个密钥 | 直接粘贴 |
| `LT_TUNNEL_DOMAIN` | 可选，启用 HTTP/HTTPS 隧道时填泛域名 |

### 步骤 3：渲染 frps.toml 与 Caddyfile

```bash
bash deploy/scripts/render.sh
# Windows: powershell -ExecutionPolicy Bypass -File deploy/scripts/render.ps1
```

脚本会校验 `.env` 完整性、拒绝 `CHANGE_ME` 占位符，并生成 `deploy/frps/frps.toml` 与 `deploy/caddy/Caddyfile`（两者均已被 gitignore）。

### 步骤 4：启动

```bash
# 仓库公开后镜像通常也是公开的，可跳过 login；若拉取报 401 则执行：
# echo "<PAT>" | docker login ghcr.io -u xiaoxin-zk --password-stdin

docker compose -f deploy/docker-compose.yml pull
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml ps
```

### 步骤 5：验证

```bash
# 三个容器都应为 running
docker compose -f deploy/docker-compose.yml ps

# 控制面健康检查
curl -fsS http://127.0.0.1:7848/healthz && echo

# 查看启动日志（首次会打印初始管理员账号）
docker compose -f deploy/docker-compose.yml logs panel | head -30
```

首次启动会打印一行 `【注意】初始管理员账号 ... 密码 ...`，把它记下来。

### 步骤 6：放行端口与解析域名

防火墙 / 安全组只放行：

| 端口 | 协议 | 用途 |
|---|---|---|
| 80 | TCP | ACME 证书校验与跳转 |
| 443 | TCP | 控制台 + 网站隧道 |
| 7001 | TCP | 客户端 frpc 接入 |
| 7002 | UDP | KCP 加速（游戏联机建议开） |
| 20000-30000 | TCP+UDP | 隧道端口池 |

DNS：把控制台域名 A 记录指向服务器，泛域名（如 `*.tunnel.example.com`）按需解析。

### 步骤 7：登录与创建隧道

```bash
# 管理后台默认只监听回环，用 SSH 隧道访问
ssh -L 8443:127.0.0.1:8443 user@你的服务器
# 浏览器打开 http://127.0.0.1:8443，用上面的初始账号登录，立即改密码
```

用户控制台走 `https://你的域名`，注册账号后即可创建隧道。
游戏联机场景记得选 **UDP** 类型（如基岩版 19132、帕鲁 8211）。

### 步骤 8：分发客户端

到仓库 Actions 页面下载最近一次 CI 的 `LiteTunnel-windows-amd64` artifact（或用打 tag 后的 Release 包，已内置 `frpc.exe`），
把安装包放进服务器的 `deploy/data/panel/clients` 目录，用户控制台的「客户端」页会自动列出。

### 3. 安全组 / 防火墙

| 端口 | 协议 | 用途 | 是否必须 |
|---|---|---|---|
| 80 | TCP | ACME 证书校验与跳转 | 是 |
| 443 | TCP | 用户控制台、网站隧道 | 是 |
| 7001 | TCP | frpc 接入（强制 TLS） | 是 |
| 7002 | UDP | KCP 加速、NAT 打洞 | 游戏联机建议开 |
| 20000-30000 | TCP+UDP | 隧道端口池 | 是 |
| 7848 / 8443 / 7500 | TCP | 内部端口 | **禁止放行** |

管理后台访问方式（任选其一）：

```bash
# SSH 隧道（推荐）
ssh -L 8443:127.0.0.1:8443 user@your-server
# 然后浏览器打开 http://127.0.0.1:8443
```

### 4. Windows 客户端

客户端同样由 CI 产出，**已内置官方 `frpc.exe`，解压即用**：

- 打开仓库的 **Releases** 页面下载 `LiteTunnel-windows-amd64.zip`
- 或到 **Actions** 页面下载最近一次 CI 的 `LiteTunnel-windows-amd64` artifact

把安装包放进服务器的 `LT_CLIENT_DIST_DIR` 目录，用户控制台会自动列出供下载。

> 本地调试可执行 `powershell -ExecutionPolicy Bypass -File scripts/build.ps1`，
> 产物在 `client/windows/build/bin/LiteTunnel.exe`（需自行放置 `frpc.exe`）。

---

## 六、构建与发布（GitHub Actions）

**不在本地构建**，全部交给 CI。

### `ci.yml` — 推送即校验

| Job | 内容 |
|---|---|
| Server (Go) | `go mod tidy` → `go vet` → 交叉编译 Linux 二进制 |
| Web (user/admin) | 分别构建两个前端，产物上传为 artifact |
| Client (Windows) | 安装 Wails CLI → 构建 `LiteTunnel.exe`，上传为 artifact |
| Docker image | 构建镜像验证 Dockerfile 可用（不推送） |

### `release.yml` — 打 tag 即发布

```bash
git tag v1.0.0
git push origin v1.0.0
```

触发后自动完成：

1. 构建并推送镜像到 `ghcr.io/xiaoxin-zk/litetunnel-panel:v1.0.0`（同时更新 `latest`）
2. 构建 Windows 客户端，并下载对应版本的官方 `frpc.exe` 一起打包
3. 生成服务端部署包（compose + 模板 + `.env.example` + README）
4. 创建 Release（草稿态，确认后发布）并挂载以上产物

也可以到 Actions 页面手动触发 `Release` workflow 并指定版本号。

> **关于 `go.sum`**：当前仓库尚未提交 `go.sum`，CI 每次会执行 `go mod tidy` 解析依赖。
> 首次 CI 成功后，建议把生成的 `go.sum` 提交入库，并把两个 workflow 中的
> `cache: false` 改为 `cache: true` 以获得依赖缓存加速与可复现构建。

---

## 七、安全清单

| 项 | 实现 |
|---|---|
| 传输加密 | frp 强制 TLS；用户侧统一 HTTPS |
| 客户端鉴权 | 每用户独立 `client_secret`，写入 frpc 的 `metadatas`，登录时校验 |
| **插件身份判定** | 以 `run_id` 为唯一依据，且该 `run_id` 必须来自「已通过凭据校验」的会话记录；客户端自报的 user 字段仅用于交叉核对 |
| 口令存储 | bcrypt（cost 10） |
| 令牌隔离 | 用户域 / 管理域不同密钥、不同 aud |
| **令牌实时失效** | 每次请求复查账号状态，禁用/删除后最长 10 秒令牌即失效（带 TTL 缓存，避免每请求查库） |
| **暴力破解防护** | IP 令牌桶 + **账号级指数退避锁定**（用户域 5 次/15 分钟起，管理域 3 次/30 分钟起，上限 24 小时），覆盖网页登录与客户端登录两个入口 |
| API Key | 仅存 SHA-256 摘要；明文经 AES-256-GCM 加密后存储，用于控制台回显 |
| 限速防篡改 | 服务端插件覆盖客户端声明，并固定 `bandwidthLimitMode = server` |
| 端口约束 | `allowPorts` 锁定端口池；禁止特权端口；数据库部分唯一索引兜底 |
| 配额断流 | `NewUserConn` 回调实时拒绝 + 内存态标记，不查库 |
| 来源校验 | 插件回调仅接受白名单网段（默认回环），并拒绝 `0.0.0.0/0` 这类全信任配置 |
| 反代信任 | 仅信任 `LT_TRUSTED_PROXIES` 的转发头，配置成全网段会被启动校验直接拒绝 |
| 管理面隔离 | 默认只监听 `127.0.0.1`；生产环境用 `SplitHostPort` 解析后强制校验，`[::]:8443` 这类 IPv6 通配写法无法绕过 |
| **无硬编码密钥** | 源码中不存在任何可用密钥；非生产环境缺失时**随机生成**并告警，杜绝「源码公开 + 默认环境变量 = 可伪造管理员令牌」 |
| **令牌不进 URL** | 只从 `Authorization` 头读取，不支持 `?token=`，避免凭据写入访问日志与 Referer |
| **请求体上限** | 1 MiB，防止超大 JSON 耗尽内存 |
| 容器加固 | 非 root、`read_only`、`cap_drop: ALL`、`no-new-privileges` |
| 审计 | 全部写操作落库，含管理员、动作、目标、来源 IP；管理员登录失败与锁定同样留痕 |
| 自检 | `scripts/check-secrets.ps1` 扫描硬编码地址；CI 冒烟测试校验管理路由未出现在公网端口 |

### 威胁模型与已知取舍

| 场景 | 现状 |
|---|---|
| 全局 `frps token` 泄露 | 仅能完成 frp 协议层握手，仍过不了每用户凭据校验（`Login` 回调） |
| 数据库文件被读取 | 用户口令为 bcrypt；API Key 为摘要 + 密文；`client_secret` 为明文（需下发给客户端，属已知取舍） |
| 控制面重启 | 内存会话清空，回落到数据库会话表（10 分钟信任窗口），已连接客户端不会中断 |
| 配额超限 | 最多 30 秒（采集周期）的流量超出窗口 |
| 管理后台暴露 | 生产环境启动即拒绝监听非回环地址，无法误配 |

> **部署前必读**：`LT_ENV` 必须显式设为 `production`。非生产环境会放宽校验并自动生成随机密钥，
> 虽然随机密钥本身安全，但该环境不校验管理地址、不强制配置插件白名单，**不可用于公网**。

---

## 八、配置项

完整列表见 `.env.example`。几处关键约束：

- `LT_USER_JWT_SECRET` 与 `LT_ADMIN_JWT_SECRET` **必须不同**，且长度不少于 24；
- `LT_APIKEY_ENC_KEY` 需为 32 或 64 个字符；
- 生产环境禁止把 `LT_ADMIN_ADDR` 配成 `0.0.0.0`，启动时会直接报错退出；
- `LT_GATEWAY_HOST` 是**下发给客户端的连接地址**，填域名或公网 IP（只写进 `.env`，不进源码）。

---

## 九、常见问题

**Q：客户端连不上，日志提示「客户端凭据无效」？**
在管理后台对该用户执行「重置客户端凭据」，然后重新登录客户端。

**Q：隧道在线但访问不通？**
检查安全组是否放行了对应的隧道端口（TCP 与 UDP 都要放行），UDP 类型容易被忽略。

**Q：游戏联机延迟高？**
优先使用 KCP 端口（`LT_KCP_PORT`），并确保该 UDP 端口已放行；中转节点应选择离玩家更近的地域。

**Q：HTTP 隧道访问 404？**
需要在 DNS 把泛域名 `*.你的隧道域名` 解析到本机，并在 `Caddyfile` 中配置 DNS Challenge 申请泛域名证书。

**Q：忘记管理员密码？**
停掉 panel 容器，用 SQLite 客户端清空 `lt_admins` 表中对应记录后重启，会重新按 `.env` 播种初始管理员。

---

## 十、许可

数据面内核 [fatedier/frp](https://github.com/fatedier/frp) 采用 Apache-2.0。
本项目自身代码可用于商业用途，请自行保留 frp 的版权与许可声明。
