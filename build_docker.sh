#!/bin/bash

action=$1

ver=$(cat version)
echo $ver

# docker login -u wsczx

# 生成时间 2024-01-30T21:41:27+08:00
# date -Iseconds

#bash ./build_web.sh

# 安装qemu支持 重要
#docker run --rm --privileged multiarch/qemu-user-static --reset -p yes

#docker buildx build -t wsczx/remlink:latest,wsczx/remlink:$ver \
#  --progress=plain --platform linux/amd64,linux/arm64 \
#  --build-arg CN="yes" --build-arg appVer=$ver --build-arg commitId=$(git rev-parse HEAD) \
#  -f docker/Dockerfile  --push .


# docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 本地不生成镜像
#docker build -t wsczx/remlink:latest \ --no-cache
docker buildx build -t wsczx/remlink:latest --platform linux/amd64 \
  --progress=plain \
  --build-arg CN="yes" --build-arg appVer=$ver --build-arg commitId=$(git rev-parse HEAD) \
  -f docker/Dockerfile .

echo "docker tag latest $ver"
docker tag wsczx/remlink:latest wsczx/remlink:$ver
docker run -it --rm wsczx/remlink:$ver -v

if [[ $action == "cntest" ]]; then
  docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
  docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
  echo registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:test-$ver
fi
