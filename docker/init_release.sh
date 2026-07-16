#!/bin/sh
set -x

if [ "$CN" = "yes" ]; then
  sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
  export GOPROXY=https://goproxy.cn
fi

apk add --no-cache ca-certificates bash tzdata inetutils-telnet iptables

which iptables
iptables -V

chmod +x /app/docker_entrypoint.sh
mkdir -p /app/log

uname -a
date -Iseconds
