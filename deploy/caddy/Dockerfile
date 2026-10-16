# ============================================================
#  自定义 Caddy 镜像：编入 DNS 服务商插件
#
#  为什么要自己构建：
#
#    泛域名证书无法用 HTTP-01/TLS-ALPN-01 验证，只能走 DNS Challenge，
#    而 DNS Challenge 的 dns 指令来自插件——官方 caddy:2-alpine 一个插件
#    都不带，Caddyfile 里写了 dns 会直接以
#    "unrecognized directive: dns" 拒绝启动。
#
#    所以「用 LT_TUNNEL_DOMAIN 走泛域名」与「用官方镜像」二者不可兼得：
#    要把镜象换成这里构建出来的那个（.env 里的 LT_CADDY_IMAGE）。
#
#  构建参数（由 docker compose build args 注入，见 deploy/docker-compose.yml）：
#
#    CADDY_VERSION       基础镜像标签，默认 2
#    CADDY_DNS_MODULES   空格分隔的插件名，例如 "cloudflare" 或 "cloudflare dnspod"
#
#  插件名与 Caddyfile 里 dns 指令的第一个参数同名，模块统一取自
#  github.com/caddy-dns/<名字>（cloudflare / alidns / dnspod / route53 ...）。
#
#  用法（在仓库根目录）：
#
#    docker compose --env-file .env -f deploy/docker-compose.yml build caddy
#
#  该命令会按 .env 里的 LT_CADDY_DNS_MODULES 构建，并把 docker-compose.yml
#  中 caddy.build 那段取消注释后生效；构建完把 LT_CADDY_IMAGE 指到镜像名，
#  再 up -d 即可。
# ============================================================
ARG CADDY_VERSION=2

FROM caddy:${CADDY_VERSION}-builder AS builder

# 在 stage 内重新声明，否则取不到全局 ARG
ARG CADDY_DNS_MODULES=""

# 显式循环而不是拼字符串：模块为空时 xcaddy 会构建一个与原版等价的 caddy，
# 这也是一种合法用法（例如只用裸域名证书，只是不再需要这个镜像）。
RUN set -eux; \
    args=""; \
    for m in ${CADDY_DNS_MODULES}; do args="${args} --with=github.com/caddy-dns/${m}"; done; \
    xcaddy build ${args}

FROM caddy:${CADDY_VERSION}-alpine

# 只替换二进制：入口脚本、caddy 用户、/data 与 /config 的目录权限全部沿用官方镜像
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
