ARG GO_IMAGE=docker.m.daocloud.io/library/golang:1.26.5-bookworm
ARG TAILSCALE_IMAGE=docker.m.daocloud.io/tailscale/tailscale:v1.98.9
ARG NODE_IMAGE=docker.m.daocloud.io/library/node:22.18.0-bookworm-slim
ARG ALPINE_IMAGE=docker.m.daocloud.io/library/alpine:3.23

FROM ${GO_IMAGE} AS builder

ARG GOPROXY=https://goproxy.cn,direct
ENV CGO_ENABLED=0 \
    GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/snw-agent-link ./cmd/snw-agent-link && \
    go build -trimpath -ldflags="-s -w" -o /out/snw-agent-linkd ./cmd/snw-agent-linkd

FROM ${TAILSCALE_IMAGE} AS tailscale

FROM ${GO_IMAGE} AS derper-builder

ARG GOPROXY=https://goproxy.cn,direct
ARG TAILSCALE_VERSION=v1.98.9
ENV CGO_ENABLED=0 \
    GOPROXY=${GOPROXY}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install "tailscale.com/cmd/derper@${TAILSCALE_VERSION}"

FROM ${NODE_IMAGE} AS node-runtime

ARG CODEX_VERSION=0.142.5
ARG NPM_REGISTRY=https://registry.npmmirror.com

RUN sed -i \
      -e 's#deb.debian.org#mirrors.aliyun.com#g' \
      -e 's#security.debian.org#mirrors.aliyun.com#g' \
      /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl iproute2 jq netcat-openbsd openssl procps python3 tini && \
    rm -rf /var/lib/apt/lists/* && \
    npm config set registry "${NPM_REGISTRY}" && \
    npm install --global "@openai/codex@${CODEX_VERSION}" && \
    codex --version

COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY --from=tailscale /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY --from=builder /out/snw-agent-link /usr/local/bin/snw-agent-link
COPY --from=builder /out/snw-agent-linkd /usr/local/bin/snw-agent-linkd
COPY adapters/snw-agent-link-codex /opt/snw-agent-link/adapters/snw-agent-link-codex
COPY docker/e2e/entrypoint.sh /usr/local/bin/e2e-entrypoint

RUN chmod 0755 /usr/local/bin/e2e-entrypoint && \
    mkdir -p \
      /run/e2e \
      /run/tailscale \
      /var/lib/codex \
      /var/lib/snw-agent-link \
      /var/lib/snw-agent-link-adapter \
      /var/lib/tailscale \
      /var/log/e2e

ENV CODEX_HOME=/var/lib/codex \
    OPENAI_API_KEY=PROXY_MANAGED \
    PYTHONPATH=/opt/snw-agent-link/adapters/snw-agent-link-codex \
    SNW_AGENT_LINK_ADAPTER_DATA_DIR=/var/lib/snw-agent-link-adapter \
    SNW_AGENT_LINK_DATA_DIR=/var/lib/snw-agent-link

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/e2e-entrypoint"]
CMD ["run"]

FROM ${ALPINE_IMAGE} AS derper-runtime

COPY --from=derper-builder /out/derper /usr/local/bin/derper

EXPOSE 3340/tcp 3478/udp
ENTRYPOINT ["/usr/local/bin/derper"]
CMD ["-a", ":3340", "--http-port=-1", "--certmode=manual", "--certdir=/run/derper-certs", "--hostname=derper", "-c", "/var/lib/derper/derper.key"]
