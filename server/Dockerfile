# 构建上下文为仓库根目录：docker build -f server/Dockerfile .
# ---------- 前端：用户控制台 ----------
FROM node:22-alpine AS web-user
WORKDIR /src
COPY web/user/package.json web/user/
RUN cd web/user && npm install --no-audit --no-fund
COPY web/user web/user
RUN cd web/user && npm run build

# ---------- 前端：管理后台 ----------
FROM node:22-alpine AS web-admin
WORKDIR /src
COPY web/admin/package.json web/admin/
RUN cd web/admin && npm install --no-audit --no-fund
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
RUN apk add --no-cache ca-certificates tzdata wget \
    && adduser -D -u 10001 -h /app lt

WORKDIR /app
COPY --from=builder /out/panel /app/panel
COPY --from=web-user /src/web/user/dist /app/web/user
COPY --from=web-admin /src/web/admin/dist /app/web/admin

# 数据目录由挂载卷提供
RUN mkdir -p /data/clients && chown -R lt:lt /app /data

USER lt
# 单一公网入口：用户控制台与管理后台共用该端口（管理后台在 /admin 下）
EXPOSE 7848

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:7848/healthz || exit 1

ENTRYPOINT ["/app/panel"]
