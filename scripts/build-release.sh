#!/usr/bin/env sh
set -eu

mkdir -p dist
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = "windows" ]; then suffix=".exe"; fi
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "dist/snw-agent-link-${os}-${arch}${suffix}" ./cmd/snw-agent-link
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "dist/snw-agent-linkd-${os}-${arch}${suffix}" ./cmd/snw-agent-linkd
done
