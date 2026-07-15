#!/bin/bash
# Docker 编译脚本（生成 remlink-deploy 发布包）
# 要求: docker 已安装
# 前置: 先执行 build_web.sh 编译前端（仅首次或前端变更后）
#
# 产物: remlink-deploy-{ver}.tar.gz

#当前目录
cpath=$(pwd)

ver=$(cat version)
echo $ver

#前端编译 仅需要执行一次
#bash ./build_web.sh

bash build_docker.sh

deploy="remlink-deploy-$ver"
docker container rm $deploy
docker container create --name $deploy wsczx/remlink:$ver
rm -rf remlink-deploy remlink-deploy.tar.gz
docker cp -a $deploy:/app ./remlink-deploy
tar zcf ${deploy}.tar.gz remlink-deploy


./remlink-deploy/remlink -v


echo "remlink 编译完成，目录: remlink-deploy"
ls -lh remlink-deploy


# 如需本地编译（不依赖 Docker），使用:
# bash build_local.sh
# 产物在 server/remlink