# 构建上下文为仓库根目录：docker build -f server/Dockerfile .
# ---------- 前端：用户控制台 ----------
FROM node:22-alpine AS web-user
WORKDIR /src
COPY web/user/package.json web/user/package-lock.json web/user/
# 用户端使用 vitest 4 + jsdom；npm 10 的 peer 解析需要与 lockfile 生成时保持一致。
# Alpine 的 Rollup musl 原生包已锁入 package-lock.json。
RUN cd web/user && npm ci --no-audit --no-fund --legacy-peer-deps
COPY web/user web/user
RUN cd web/user && npm run build

# ---------- 前端：管理后台 ----------
FROM node:22-alpine AS web-admin
WORKDIR /src
COPY web/admin/package.json web/admin/package-lock.json web/admin/
# Alpine 需要 Rollup 的 linux-x64-musl 原生包；它已锁入 package-lock.json。
RUN cd web/admin && npm ci --no-audit --no-fund
COPY web/admin web/admin
RUN cd web/admin && npm run build

# ---------- 后端 ----------
FROM golang:1.26-alpine AS builder

# 构建时注入版本号，便于确认线上运行的具体版本
ARG VERSION=dev
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux
COPY server/go.mod server/go.sum* ./
RUN go mod download
COPY server .
RUN go build -trimpath \
      -ldflags="-s -w -X github.com/xiaoxin-zk/litetunnel/server/internal/config.Version=${VERSION}" \
      -o /out/panel ./cmd/panel

# ---------- 运行镜像 ----------
FROM alpine:3.21
# 刻意**不装** iptables / nftables：
# 面板不执行任何防火墙写操作，它把写请求转发给宿主机上的 lt-fw helper。
# 镜像里没有这些工具，也就杜绝了「哪天有人顺手加了 NET_ADMIN 就能改主机
# 防火墙」的可能——能力不存在，就没法被误用。
RUN apk add --no-cache ca-certificates tzdata wget \
    && adduser -D -u 10001 -h /app lt

WORKDIR /app
COPY --from=builder /out/panel /app/panel
COPY --from=web-user /src/web/user/dist /app/web/user
COPY --from=web-admin /src/web/admin/dist /app/web/admin

# 数据目录由挂载卷提供
RUN mkdir -p /data/clients && chown -R lt:lt /app /data

USER lt
# 单一公网入口：用户控制台与管理后台共用该端口
# （管理后台挂载路径由 LT_ADMIN_PATH 决定，默认 /lt-console）
EXPOSE 7848

# 端口跟随 LT_USER_ADDR（默认 0.0.0.0:7848），改端口后健康检查不会误报。
# 注意：Dockerfile 里是 CMD（shell 形式），CMD-SHELL 是 compose 的写法。
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD port="${LT_USER_ADDR##*:}"; wget -qO- "http://127.0.0.1:${port:-7848}/healthz" || exit 1

ENTRYPOINT ["/app/panel"]
