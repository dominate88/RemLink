#!/bin/bash

ver=$(cat version)
echo $ver

echo "docker tag latest $ver"

docker pull --platform=linux/amd64 wsczx/remlink:$ver

docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:latest
docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:latest

docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:$ver
docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:$ver

docker rmi wsczx/remlink:$ver

#arm64
docker pull --platform=linux/arm64 wsczx/remlink:$ver

docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-latest
docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-latest

docker tag wsczx/remlink:$ver registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-$ver
docker push registry.cn-hangzhou.aliyuncs.com/wsczx/remlink:arm64v8-$ver

docker rmi wsczx/remlink:$ver
