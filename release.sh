#!/bin/bash

#github action release.sh

set -x
function RETVAL() {
  rt=$1
  if [ $rt != 0 ]; then
    echo $rt
    exit 1
  fi
}

#当前目录
cpath=$(pwd)

ver=$(cat version)
echo "当前版本 $ver"


rm -rf artifact-dist
mkdir artifact-dist

function archive() {
  arch=$1
  #echo "整理部署文件 $arch"
  arch_name=${arch//\//-}
  echo $arch_name

  deploy="remlink-$ver-$arch_name"
  docker container rm $deploy
  docker container create --platform $arch --name $deploy wsczx/remlink:$ver
  rm -rf remlink-deploy
  docker cp -a $deploy:/app ./remlink-deploy

  ls -lh remlink-deploy

  tar zcf ${deploy}.tar.gz remlink-deploy
  mv ${deploy}.tar.gz artifact-dist/

  # 生成 SHA256 校验文件
  sha256sum artifact-dist/${deploy}.tar.gz > artifact-dist/${deploy}.tar.gz.sha256
}

echo "copy二进制文件"

archive "linux/amd64"
archive "linux/arm64"

ls -lh artifact-dist

#注意使用root权限运行
#cd remlink-deploy
#sudo ./remlink
