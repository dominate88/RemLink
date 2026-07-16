#!/bin/bash
# 构建 Docker 镜像并推送
# 用法:
#   bash scripts/build_docker.sh          构建并打版本 tag
#   bash scripts/build_docker.sh cn       构建并推送到阿里云镜像仓库
#   bash scripts/build_docker.sh cntest   构建并推送到阿里云测试 tag

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

action=$1
ver=$(cat version)
echo "版本: $ver"

# 构建镜像
docker buildx build -t wsczx/remlink:latest --platform linux/amd64 \
  --progress=plain \
  --build-arg CN="yes" --build-arg appVer=$ver --build-arg commitId=$(git rev-parse HEAD) \
  -f docker/Dockerfile .

echo "docker tag latest $ver"
docker tag wsczx/remlink:latest wsczx/remlink:$ver
docker run --rm wsczx/remlink:$ver -v

# 推送阿里云镜像仓库
if [[ $action == "cn" ]]; then
  echo "推送阿里云镜像仓库..."
  for arch in amd64 arm64; do
    docker pull --platform=linux/$arch wsczx/remlink:$ver

    if [[ $arch == "amd64" ]]; then
      docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:latest
      docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:latest
      docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:$ver
      docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:$ver
    else
      docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-latest
      docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-latest
      docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-$ver
      docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-$ver
    fi
    docker rmi wsczx/remlink:$ver
  done
  echo "阿里云推送完成"

elif [[ $action == "cntest" ]]; then
  docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
  docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
  echo registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
fi
