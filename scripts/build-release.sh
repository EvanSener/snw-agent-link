#!/usr/bin/env sh
set -eu

DIST_DIR=${DIST_DIR:-dist}
STAGE_DIR="$DIST_DIR/.stage"
rm -rf "$DIST_DIR"
mkdir -p "$STAGE_DIR"

for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  package="snw-agent-link-${os}-${arch}"
  package_dir="$STAGE_DIR/$package"
  mkdir -p "$package_dir"
  cp LICENSE "$package_dir/LICENSE"
  cp README.md "$package_dir/PROJECT.md"

  if [ "$os" = "windows" ]; then
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$package_dir/snw-agent-link.exe" ./cmd/snw-agent-link
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$package_dir/snw-agent-linkd.exe" ./cmd/snw-agent-linkd
    cp packaging/windows/README.md "$package_dir/README.md"
    cp packaging/windows/install.ps1 "$package_dir/install.ps1"
    (
      cd "$STAGE_DIR"
      zip -qr "../$package.zip" "$package"
    )
  else
    packaging_os=$os
    if [ "$os" = "darwin" ]; then
      packaging_os=macos
    fi
    mkdir -p "$package_dir/bin"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$package_dir/bin/snw-agent-link" ./cmd/snw-agent-link
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$package_dir/bin/snw-agent-linkd" ./cmd/snw-agent-linkd
    cp "packaging/$packaging_os/README.md" "$package_dir/README.md"
    cp "packaging/$packaging_os/install.sh" "$package_dir/install.sh"
    if [ "$os" = "darwin" ]; then
      cp packaging/macos/com.snw.agent-linkd.plist.template "$package_dir/com.snw.agent-linkd.plist.template"
    else
      cp packaging/linux/snw-agent-linkd-wrapper "$package_dir/snw-agent-linkd-wrapper"
      cp packaging/linux/snw-agent-linkd.service "$package_dir/snw-agent-linkd.service"
    fi
    tar -czf "$DIST_DIR/$package.tar.gz" -C "$STAGE_DIR" "$package"
  fi
done

rm -rf "$STAGE_DIR"
(
  cd "$DIST_DIR"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum ./*.tar.gz ./*.zip >checksums.sha256
  else
    shasum -a 256 ./*.tar.gz ./*.zip >checksums.sha256
  fi
)
