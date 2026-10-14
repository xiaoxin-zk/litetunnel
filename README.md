# LiteTunnel

轻量内网穿透平台。以 **frp v0.71** 为数据面内核，自研轻量控制面，面向游戏联机、内网网站与 NAS 映射场景。

单台公网服务器即可承载，全程 Docker 部署，管理后台与用户控制台**物理隔离**。

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
        │  127.0.0.1:8080                        │ 7000/TCP  7001/UDP
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
│   ├── build.ps1               一键构建全部产物
│   └── check-secrets.ps1       提交前检查硬编码地址
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

```bash
# 1) 准备配置
cp .env.example .env
# 编辑 .env：填写域名、网关地址、各项密钥（openssl rand -hex 32）

# 2) 渲染 frps.toml 与 Caddyfile
bash deploy/scripts/render.sh          # Windows: powershell -File deploy/scripts/render.ps1

# 3) 启动
docker compose -f deploy/docker-compose.yml up -d --build
```

### 3. 安全组 / 防火墙

| 端口 | 协议 | 用途 | 是否必须 |
|---|---|---|---|
| 80 | TCP | ACME 证书校验与跳转 | 是 |
| 443 | TCP | 用户控制台、网站隧道 | 是 |
| 7000 | TCP | frpc 接入（强制 TLS） | 是 |
| 7001 | UDP | KCP 加速、NAT 打洞 | 游戏联机建议开 |
| 20000-30000 | TCP+UDP | 隧道端口池 | 是 |
| 8080 / 8443 / 7500 | TCP | 内部端口 | **禁止放行** |

管理后台访问方式（任选其一）：

```bash
# SSH 隧道（推荐）
ssh -L 8443:127.0.0.1:8443 user@your-server
# 然后浏览器打开 http://127.0.0.1:8443
```

### 4. Windows 客户端

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -SkipWeb
```

产物在 `client/windows/build/bin/LiteTunnel.exe`。把官方 `frpc.exe` 放到同目录即可。
也可以把客户端安装包放进 `LT_CLIENT_DIST_DIR` 目录，用户控制台会自动列出供下载。

---

## 五、安全清单

| 项 | 实现 |
|---|---|
| 传输加密 | frp 强制 TLS；用户侧统一 HTTPS |
| 客户端鉴权 | 每用户独立 `client_secret`，写入 frpc 的 `metadatas`，登录时校验 |
| 口令存储 | bcrypt |
| 令牌隔离 | 用户域 / 管理域不同密钥、不同 aud |
| API Key | 仅存 SHA-256 摘要；明文经 AES-256-GCM 加密后存储，用于控制台回显 |
| 限速防篡改 | 服务端插件覆盖客户端声明，并固定 `bandwidthLimitMode = server` |
| 端口约束 | `allowPorts` 锁定端口池；禁止特权端口 |
| 配额断流 | `NewUserConn` 回调实时拒绝 + 内存态标记，不查库 |
| 来源校验 | 插件回调仅接受白名单网段（默认回环） |
| 反代信任 | 仅信任 `LT_TRUSTED_PROXIES` 的转发头，防止伪造 IP 绕过限流 |
| 管理面隔离 | 默认只监听 `127.0.0.1`，生产环境启动时强制校验 |
| 容器加固 | 非 root、`read_only`、`cap_drop: ALL`、`no-new-privileges` |
| 审计 | 全部写操作落库，含管理员、动作、目标、来源 IP |
| 无硬编码 | 所有地址与密钥均来自环境变量；`scripts/check-secrets.ps1` 可自检 |

---

## 六、配置项

完整列表见 `.env.example`。几处关键约束：

- `LT_USER_JWT_SECRET` 与 `LT_ADMIN_JWT_SECRET` **必须不同**，且长度不少于 24；
- `LT_APIKEY_ENC_KEY` 需为 32 或 64 个字符；
- 生产环境禁止把 `LT_ADMIN_ADDR` 配成 `0.0.0.0`，启动时会直接报错退出；
- `LT_GATEWAY_HOST` 是**下发给客户端的连接地址**，填域名或公网 IP（只写进 `.env`，不进源码）。

---

## 七、常见问题

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

## 八、许可

数据面内核 [fatedier/frp](https://github.com/fatedier/frp) 采用 Apache-2.0。
本项目自身代码可用于商业用途，请自行保留 frp 的版权与许可声明。
