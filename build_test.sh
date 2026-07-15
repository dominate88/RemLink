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
echo $ver

#前端编译 仅需要执行一次
#bash ./build_web.sh

echo "copy二进制文件"

# -tags osusergo,netgo,sqlite_omit_load_extension
flags="-trimpath"
ldflags="-s -w -extldflags '-static' -X main.appVer=$ver -X main.commitId=$(git rev-parse HEAD) -X main.buildDate=$(date --iso-8601=seconds)"
#github action
gopath=/go

dockercmd=$(
  cat <<EOF
sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
apk add gcc g++ musl musl-dev tzdata
export GOPROXY=https://goproxy.cn
go mod tidy
echo "build:"
rm remlink
export CGO_ENABLED=1
go build -v -o remlink $flags -ldflags "$ldflags"
./remlink -v
EOF
)

# golang:1.22-alpine3.19
#使用 musl-dev 编译
docker run -q --rm -v $PWD/server:/app -v $gopath:/go -w /app --platform=linux/amd64 \
  golang:1.24-alpine3.22 sh -c "$dockercmd"

#arm64编译
#docker run -q --rm -v $PWD/server:/app -v $gopath:/go -w /app --platform=linux/arm64 \
#  golang:1.20-alpine3.19 go build -o remlink_arm64 $flags -ldflags "$ldflags"
#exit 0

#cd $cpath

echo "整理部署文件"
rm -rf remlink-deploy remlink-deploy.tar.gz
mkdir remlink-deploy
mkdir remlink-deploy/log

cp -r server/remlink remlink-deploy

cp -r index_template remlink-deploy
cp -r deploy remlink-deploy
cp -r LICENSE remlink-deploy

tar zcvf remlink-deploy.tar.gz remlink-deploy

#注意使用root权限运行
#cd remlink-deploy
#sudo ./remlink
