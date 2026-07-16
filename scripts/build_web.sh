#!/bin/bash
# 前端编译脚本（使用 Docker 容器编译）
# 需要: docker 已安装
# 产物: web/ui → server/ui（供后端 embed 使用）

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

rm -rf web/ui server/ui

docker run --rm -v $PWD/web:/app -v /data/remlink_node_modules:/app/node_modules -w /app node:16-alpine \
  sh -c "yarn install --registry=https://registry.npmmirror.com && yarn run build"

cp -r web/ui/. server/ui/
