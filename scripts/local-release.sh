#!/bin/bash
# 本地发布脚本：绕过 GitHub Actions，直接在构建机上构建并发布到 GitHub Releases。
#
# 前置依赖（构建机需具备）：
#   - docker（已 docker login，或设置环境变量 DOCKERHUB_TOKEN）
#   - gh CLI（设置 GH_TOKEN，需对 wsczx/RemLink 与 wsczx/RemLink-private 有写权限）
#
# 用法：
#   GH_TOKEN=xxx DOCKERHUB_TOKEN=xxx ./scripts/local-release.sh [-l]
#   ARCH="linux/amd64" ./scripts/local-release.sh          # 仅 amd64
#   ./scripts/local-release.sh -l                          # 同时打 latest 镜像标签
set -euo pipefail

REPO_PRIVATE=wsczx/RemLink-private
REPO_PUBLIC=wsczx/RemLink
VER=$(cat version)
COMMIT=$(git rev-parse HEAD)
# Docker 构建架构，逗号分隔
ARCH="${ARCH:-linux/amd64,linux/arm64}"

# 是否额外打 latest 镜像标签：-l / --latest / latest 均可
LATEST_TAG=0
for _arg in "$@"; do
  case "$_arg" in
    -l|--latest|latest) LATEST_TAG=1 ;;
  esac
done

echo "==> 构建版本 v${VER} commit ${COMMIT}"
echo "==> Docker 架构: ${ARCH}"

# 环境检测
command -v gh >/dev/null 2>&1 || { echo "错误：未安装 gh，请先 'apt install gh' 并 'gh auth login'"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "错误：gh 未登录，请先 'gh auth login'"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "错误：未安装 docker"; exit 1; }
if [ -n "${DOCKERHUB_TOKEN:-}" ]; then
  echo "$DOCKERHUB_TOKEN" | docker login -u wsczx --password-stdin
fi

# 前端构建
bash scripts/build_web.sh

# 打包私有仓库源码
rm -rf artifact-src && mkdir -p artifact-src
tar --exclude='.git' \
    --exclude='.env*' \
    --exclude='server/.env*' \
    --exclude='web/node_modules' \
    --exclude='server/ui' \
    --exclude='server/conf' \
    --exclude='artifact-dist' \
    --exclude='artifact-src' \
    -czf "artifact-src/RemLink-src-v${VER}.tar.gz" .

# 提取当前版本 changelog 作为 Release 正文
ver="${VER#v}"
body=$(awk -v ver="v$ver" '
  BEGIN { f=0 }
  /^## / { f=0 }
  $0 == "## " ver { f=1; next }
  /^## / && f { exit }
  f { print }
' CHANGELOG.md)
if [ -z "$body" ]; then
  body=$(awk -v ver="$ver" '
    BEGIN { f=0 }
    /^## / { f=0 }
    $0 == "## " ver { f=1; next }
    /^## / && f { exit }
    f { print }
  ' CHANGELOG.md)
fi
body=$(printf "%s\n" "$body" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' | sed '/./,$!d')
[ -z "$body" ] && body="RemLink v${ver} 发布"

# 多架构 Docker 镜像构建并推送
docker buildx build --push \
  --platform "$ARCH" \
  --build-arg "appVer=${VER}" \
  --build-arg "commitId=${COMMIT}" \
  -f docker/Dockerfile \
  -t "wsczx/remlink:${VER}" .
if [ "$LATEST_TAG" = "1" ]; then
  docker buildx build --push \
    --platform "$ARCH" \
    --build-arg "appVer=${VER}" \
    --build-arg "commitId=${COMMIT}" \
    -f docker/Dockerfile \
    -t "wsczx/remlink:latest" .
fi

# 提取二进制
RELEASE_ARCHES=$(echo "$ARCH" | tr ',' ' ') bash scripts/release.sh

# 发布到私有仓库（源码）
gh release delete "v${VER}" -R "$REPO_PRIVATE" 2>/dev/null || true
gh release create "v${VER}" -R "$REPO_PRIVATE" \
  -t "RemLink-src v${VER}" -n "$body" artifact-src/*

# 发布到公共仓库（二进制）
gh release delete "v${VER}" -R "$REPO_PUBLIC" 2>/dev/null || true
gh release create "v${VER}" -R "$REPO_PUBLIC" \
  -t "RemLink v${VER}" -n "$body" artifact-dist/*

echo "==> 发布完成："
echo "    私有: https://github.com/${REPO_PRIVATE}/releases/tag/v${VER}"
echo "    公共: https://github.com/${REPO_PUBLIC}/releases/tag/v${VER}"
