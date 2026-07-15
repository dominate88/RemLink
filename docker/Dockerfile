#node:16-bullseye
#golang:1.20-bullseye
#debian:bullseye-slim
#bullseye
# sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list
#bookworm
# sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources

# sed -i 's/dl-cdn.alpinelinux.org/mirrors.tuna.tsinghua.edu.cn/g' /etc/apk/repositories


# 配合 github action 使用
# 需要先编译出ui文件后 再执行docker编译

# server
# golang:1.22-alpine3.19
FROM golang:1.24-alpine3.22 AS builder_golang

ARG CN="no"
ARG appVer="appVer"
ARG commitId="commitId"

ENV TZ=Asia/Shanghai

WORKDIR /server
COPY docker/init_build.sh /tmp/
COPY server/ /server/
COPY web/ui  /server/ui

#RUN apk add gcc musl-dev bash
RUN --mount=type=cache,target=/go --mount=type=cache,target=/root/.cache/go-build sh /tmp/init_build.sh


# remlink
#alpine:3.19
FROM alpine:3.22
LABEL maintainer="github.com/wsczx"

ARG CN="no"

ENV TZ=Asia/Shanghai
#开关变量  on  off
ENV REMLINK_IN_CONTAINER="on"
#ENV IPTABLES_LEGACY="off"

WORKDIR /app
COPY docker/init_release.sh /tmp/

COPY --from=builder_golang /server/remlink  /app/
COPY docker/docker_entrypoint.sh server/bridge-init.sh ./README.md ./LICENSE version_info /app/
COPY ./deploy /app/deploy
COPY ./index_template  /app/index_template
# 通过 .dockerignore 处理
# COPY ./server/conf  /app/conf

#TODO 本地打包时使用镜像
RUN sh /tmp/init_release.sh


EXPOSE 443 8800 443/udp

#CMD ["/app/remlink"]
ENTRYPOINT ["/app/docker_entrypoint.sh"]

