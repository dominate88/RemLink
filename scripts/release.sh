#!/bin/bash

set -x

ver=$(cat version)
echo "当前版本 $ver"

rm -rf artifact-dist
mkdir artifact-dist

function archive() {
  arch=$1
  arch_name=${arch////-}
  echo "打包 $arch_name"

  container="remlink-$ver-$arch_name"
  docker container rm $container 2>/dev/null
  docker container create --platform $arch --name $container wsczx/remlink:$ver

  # 只提取二进制文件（在线升级直接下载裸二进制）
  docker cp $container:/app/remlink artifact-dist/remlink-$arch_name
  docker container rm $container 2>/dev/null
}

archive "linux/amd64"
archive "linux/arm64"

test -d artifact-dist || { echo "ERROR: artifact-dist not found"; exit 1; }
test "$(ls artifact-dist)" || { echo "ERROR: artifact-dist is empty"; exit 1; }

ls -lh artifact-dist
