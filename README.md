# RemLink

![GitHub release](https://img.shields.io/github/v/release/wsczx/remlink)
![GitHub downloads](https://img.shields.io/github/downloads/wsczx/remlink/total)
[![Docker pulls](https://img.shields.io/docker/pulls/wsczx/remlink.svg)](https://hub.docker.com/r/wsczx/remlink)

RemLink 项目在 [AnyLink](https://github.com/bjdgyc/anylink) 基础上深度重构，是一个企业级安全远程接入网关，可以支持多人同时在线使用。感谢原作者 [bjdgyc](https://github.com/bjdgyc) 的开源贡献。

使用 RemLink，你可以随时随地安全的访问你的内部网络。

With RemLink, you can securely access your internal network anytime and anywhere.

## Repo

> github: https://github.com/wsczx/RemLink

## Introduction

RemLink 基于 [ietf-openconnect](https://tools.ietf.org/html/draft-mavrogiannopoulos-openconnect-02)
协议开发，并且借鉴了 [ocserv](http://ocserv.gitlab.io/www/index.html) 的开发思路，使其可以同时兼容 AnyConnect 客户端。

RemLink 使用 TLS/DTLS 进行数据加密，因此需要 RSA 或 ECC 证书，可以使用私有自签证书，可以通过 Let's Encrypt 和 TrustAsia
申请免费的 SSL 证书。

RemLink 服务端仅在 CentOS7、CentOS8、Ubuntu18、Ubuntu20、Ubuntu22、Ubuntu24、AnolisOS8、OpenCloudOS8、Debian10、Debian11、Debian12、Debian13 测试通过，如需要安装在其他系统，需要服务端支持
tun/tap
功能、ip 设置命令、iptables命令。

## Screenshot

![online](https://img.wsczx.com/remlink-screenshot-online.jpg)

## 支持与打赏

> 如果您觉得 RemLink 对您有帮助，欢迎打赏支持项目持续开发。请[点击这里](https://github.com/wsczx/RemLink/blob/main/.github/FUNDING.md)查看打赏二维码。

## Installation

> 没有编程基础的同学建议直接下载 release 包，从下面的地址下载 remlink-deploy.tar.gz
>
> https://github.com/wsczx/remlink/releases
>
> https://gitee.com/wsczx/remlink/releases
>
> 安装与使用问题请参考文档或提交 Issue。

### 使用问题

> 对于测试环境，可以直接进行测试，需要客户端取消勾选【阻止不受信任的服务器(Block connections to untrusted servers)】
>
> 对于线上环境，尽量申请安全的https证书(跟nginx使用的pem证书类型一致)
>
> 群共享文件有相关客户端软件下载，其他版本没有测试过，不保证使用正常
>
> 其他问题 [前往查看](https://github.com/wsczx/RemLink/blob/main/doc/question.md)
>
> 默认管理后台访问地址  https://host:8800 或 https://域名:8800
>
> 首次启动时自动生成随机管理员密码，请查看启动日志获取初始密码。忘记密码时执行重置命令（见下方 Config 章节）。
>
> 首次使用，请在浏览器访问  https://域名:443   浏览器提示安全后，在客户端输入 【域名:443】 即可

### 自行编译安装

> 需要提前安装好 docker 和 make

```shell
git clone https://github.com/wsczx/remlink.git
cd remlink

make help          # 查看所有命令
make build         # 编译前端 + Docker 镜像 + 发布包

cd remlink-deploy
sudo ./remlink

# 默认管理后台访问地址 https://host:8800
# 管理员密码在首次启动日志中查看
```

#### 本地编译（不依赖 Docker）

> 需要 Go 1.24+、Node.js 16+、yarn

```bash
make web    # 编译前端
make local  # 编译二进制（musl 静态链接 + UPX 压缩）
# 产物在 server/remlink
```

## Feature

### 网络与基础设施
- [x] IP 分配（实现 IP、MAC 映射信息的持久化）
- [x] TLS-TCP 通道
- [x] DTLS-UDP 通道
- [x] 兼容 AnyConnect / OpenConnect
- [x] 基于 tun 设备的 nat 访问模式
- [x] 基于 tun / macvtap 设备的桥接访问模式
- [x] 支持 [proxy protocol v1&v2](http://www.haproxy.org/download/2.2/doc/proxy-protocol.txt)
- [x] nftables 后端（优先使用，自动回退 iptables）
- [x] FakeDNS + FakeIP（域名规则匹配 + DNS 缓存加速）
- [x] 流量压缩功能
- [x] 出口 IP 自动放行
- [x] 空闲链接超时自动断开
- [x] 流量速率限制

### 认证体系
- [x] 本地密码认证（bcrypt）
- [x] TOTP 动态码认证
- [x] 客户端证书认证（支持绑定设备）
- [x] LDAP/AD 认证
- [x] RADIUS 认证（含 Access-Challenge 二次验证）
- [x] 企业微信 OAuth2 扫码登录
- [x] 飞书 OAuth2 扫码登录
- [x] SMS 短信验证码（腾讯云 TC3 + 阿里云）
- [x] WebAuth 浏览器端证书认证
- [x] 认证 Pipeline 可编排架构（多步骤自由组合 + 断点恢复）
- [x] Provider 统一管理第三方认证配置
- [x] 登录防爆（用户+IP 三级锁定策略）
- [x] 自动同步 LDAP / 企微 / 飞书用户

### 用户门户
- [x] 客户端下载页面
- [x] 证书自助申请与下载
- [x] 在线设备管理与踢下线
- [x] 密码自助重置
- [x] OTP 动态码绑定

### 管理与运维
- [x] Web 管理后台
- [x] 用户 / 组 / 策略管理
- [x] 访问权限管理
- [x] 用户活动审计日志
- [x] IP 访问审计（支持多端口、连续端口）
- [x] 管理员操作审计日志
- [x] 系统日志实时推送（WebSocket）
- [x] 数据库在线切换（SQLite / MySQL / PostgreSQL / MSSQL）
- [x] 数据备份与还原
- [x] 在线升级
- [x] 配置全面数据库化（无需手动编辑配置文件）
- [x] 敏感字段 AES-256-GCM 加密存储 + API 脱敏
- [x] 多服务配置区分
- [x] 自适应响应式前端界面
- [x] 支持 Docker 非特权模式

- [ ] 基于 ipvtap 设备的桥接访问模式

## Config

> 所有配置项已数据库化，首次启动后在 Web 管理后台「软件配置」页面在线修改，无需手动编辑配置文件。
>
> 查看所有配置项：`./remlink tool -d`

```shell
# 查看帮助信息
./remlink -h

# 生成后台密码
./remlink tool -p 123456

# 生成jwt密钥
./remlink tool -s

# 查看所有配置项
./remlink tool -d

# 重置管理员密码（需先停止服务）
# pkill remlink && ./remlink --reset-admin-password && ./remlink

# 强制禁用管理员两步验证（OTP 密钥丢失时使用，需先停止服务）
# pkill remlink && ./remlink --disable-admin-otp && ./remlink

# 管理员密码说明：
# - 首次启动：自动生成随机 16 位密码，在启动日志中打印
# - 登录后：进入后台「系统设置 > 安全设置」修改密码
# - 忘记密码：先停止服务，执行 remlink --reset-admin-password 重置，再启动服务
```

> 数据库配置示例
>
> 数据库表结构自动生成，无需手动导入(请赋予 DDL 权限)

| db_type  | db_source                                                                                                            |
|----------|----------------------------------------------------------------------------------------------------------------------|
| sqlite3  | ./conf/remlink.db                                                                                                    |
| mysql    | user:password@tcp(127.0.0.1:3306)/remlink?charset=utf8<br/>user:password@tcp(127.0.0.1:3306)/remlink?charset=utf8mb4 |
| postgres | postgres://user:password@localhost/remlink?sslmode=verify-full                                                       |
| mssql    | sqlserver://user:password@localhost?database=remlink&connection+timeout=30                                           |

### 首次安装使用非 SQLite 数据库

默认使用 SQLite，无需额外配置。如需使用 MySQL / PostgreSQL / MSSQL，请选择以下方式之一：

- **方式一（推荐）：手动创建 `conf/db.json`**\
  在 `conf/` 目录下创建 `db.json` 文件，写入数据库连接信息后启动服务：

  ```json
  {
    "db_type": "mysql",
    "db_source": "user:password@tcp(127.0.0.1:3306)/remlink?charset=utf8mb4"
  }
  ```

- **方式二：启动后通过 Web 管理界面切换**\
  首次启动使用默认 SQLite → 登录管理后台 → 在「软件配置」页面点击数据库的「切换」按钮 → 按照向导完成切换。

- **方式三：通过命令行参数启动**\
  首次启动时指定 `--db_type` 和 `--db_source` 参数，服务会自动生成 `conf/db.json` 持久化配置，后续启动无需再次指定：

  ```bash
  ./remlink --db_type mysql --db_source "user:password@tcp(127.0.0.1:3306)/remlink?charset=utf8mb4"
  ```

### 第三方认证（企业微信 / 飞书 / LDAP / RADIUS）

第三方认证的服务端配置（AppID、Secret、服务器地址等）通过 **Provider** 机制统一管理，在管理后台「认证提供方」页面新建即可，无需修改配置文件。

认证组（用户组）通过 **Pipeline 编排** 自由组合认证步骤，例如：
- `[local, otp]` — 本地密码 + TOTP 动态码
- `[wxwork, otp]` — 企业微信扫码 + TOTP
- `[cert, ldap]` — 客户端证书 + LDAP 密码
- `[radius]` — RADIUS 认证（含 Access-Challenge 二次验证）

详细文档参见 [server/auth/README.md](server/auth/README.md)。

### 敏感字段加密

数据库中的敏感字段（管理员密码、JWT 密钥、证书密钥、Provider 配置、SMTP/SMS 密码等）使用 AES-256-GCM 加密存储，API 返回时自动脱敏。

密钥文件 `.encryption_key` 默认保存在工作目录，首次在管理后台「安全设置」页面启用加密时自动生成。可通过以下环境变量自定义密钥位置：

- `REMLINK_ENCRYPTION_KEY` — 指定密钥文件的**完整路径**
- `REMLINK_ENCRYPTION_KEY_DIR` — 指定密钥文件的**存放目录**（文件名固定为 `.encryption_key`）

> **注意**：环境变量仅在密钥文件尚未生成时生效（防止遗忘迁移密钥）。如需迁移密钥路径，请先在管理后台关闭加密，再移动密钥文件并设置环境变量。

## Upgrade

> 升级前请备份 `conf` 目录和数据库，并停止服务，使用新版 `remlink` 二进制文件替换旧版后重启即可。

### 数据库切换

如需切换数据库（如从 SQLite 迁移到 PostgreSQL），请通过 Web 管理界面的「软件配置」→ 数据库「切换」按钮操作。
切换操作会自动生成 `conf/db.json`，**不要**手动修改该文件。

**向导流程：**

1. 填写新数据库类型和连接串
2. 测试新库连通性
3. 选择数据迁移方式：
   - **自动迁移数据**（推荐）：将当前数据库数据完整迁移到新库
   - **仅备份不迁移**：创建备份文件，重启后页面会提示手动还原
   - **跳过备份**：直接切换到新库，原有数据不保留
4. 确认后系统完成切换并自动重启

## Setting

### 依赖设置

> 新版本已使用 netlink 替代 iproute2 命令，优先使用 nftables（自动回退 iptables）。
>
> 最小依赖：
>
> centos: `yum install iptables`
>
> ubuntu: `apt-get install iptables`

### link_mode 设置

> 以下参数必须设置其中之一

网络模式选择，需要配置 `link_mode` 参数，如 `link_mode="tun"`,`link_mode="macvtap"` 等参数。
不同的参数需要对服务器做相应的设置。

建议优先选择 tun 模式，其次选择 macvtap 模式，因客户端传输的是 IP 层数据，无须进行数据转换。 tap 模式是在用户态做的链路层到
IP 层的数据互相转换，性能会有所下降。 如果需要在虚拟机内开启 tap
模式，请确认虚拟机的网卡开启混杂模式。

#### tun 设置

1. 开启服务器转发

```shell
# 新版本支持自动设置ip转发

# file: /etc/sysctl.conf
net.ipv4.ip_forward = 1

#执行如下命令
sysctl -w net.ipv4.ip_forward=1

# 查看设置是否生效
cat /proc/sys/net/ipv4/ip_forward
```

2.1 设置 nat 转发规则(二选一)

```shell
systemctl stop firewalld.service
systemctl disable firewalld.service

# 新版本支持自动设置nat转发，如有其他需求可以参考下面的命令配置

# 请根据服务器内网网卡替换 eth0
# iptables -t nat -A POSTROUTING -s 192.168.90.0/24 -o eth0 -j MASQUERADE
# 如果执行第一个命令不生效，可以继续执行下面的命令
# iptables -A FORWARD -i eth0 -s 192.168.90.0/24 -j ACCEPT
# 查看设置是否生效
# iptables -nL -t nat
```

2.2 使用全局路由转发(二选一)

```shell
# 假设remlink所在服务器的内网ip: 10.1.2.10

# 首先关闭nat转发功能
iptables_nat = false

# 传统网络架构，在华三交换机添加以下静态路由规则
ip route-static 192.168.90.0 255.255.255.0 10.1.2.10
# 其他品牌的交换机命令，请参考以下地址
https://cloud.tencent.com/document/product/216/62007

# 公有云环境下，需设置vpc下的路由表，添加以下路由策略
目的端: 192.168.90.0/24
下一跳类型: 云服务器
下一跳: 10.1.2.10

```

3. 使用 AnyConnect 客户端连接即可

#### 桥接设置

1. 设置配置文件

> arp_proxy 性能较高，设置相对比较简单，只需要配置相应的参数即可。
>
> 网络要求：需要网络支持 ARP 传输，可通过 ARP 宣告普通内网 IP。
>
> 网络限制：云环境下不能使用，网卡mac加白环境不能使用，802.1x认证网络不能使用
>
> 以下参数可以通过执行 `ip a` 查看


1.1 arp_proxy

```

# file: /etc/sysctl.conf
net.ipv4.conf.all.proxy_arp = 1

#执行如下命令
sysctl -w net.ipv4.conf.all.proxy_arp=1


配置文件修改:

# 首先关闭nat转发功能
iptables_nat = false


link_mode = "tun"
#内网主网卡名称
ipv4_master = "eth0"
#以下网段需要跟ipv4_master网卡设置成一样
ipv4_cidr = "10.1.2.0/24"
ipv4_gateway = "10.1.2.99"
ipv4_start = "10.1.2.100"
ipv4_end = "10.1.2.200"

```

1.2 macvtap

```

# 命令行执行 master网卡需要打开混杂模式
ip link set dev eth0 promisc on

#=====================#

# 配置文件修改
# 首先关闭nat转发功能
iptables_nat = false

link_mode = "macvtap"
#内网主网卡名称
ipv4_master = "eth0"
#以下网段需要跟ipv4_master网卡设置成一样
ipv4_cidr = "10.1.2.0/24"
ipv4_gateway = "10.1.2.1"
ipv4_start = "10.1.2.100"
ipv4_end = "10.1.2.200"
```

## Deploy

> 部署配置文件放在 `deploy` 目录下，请根据实际情况修改配置文件

### Systemd

1. 添加 remlink 程序
   - 首先把 `remlink-deploy` 文件夹放入 `/usr/local/remlink-deploy`
   - 添加执行权限 `chmod +x /usr/local/remlink-deploy/remlink`
2. 把 `remlink.service` 脚本放入：
   - centos: `/usr/lib/systemd/system/`
   - ubuntu: `/lib/systemd/system/`
3. 操作命令:
   - 加载配置: `systemctl daemon-reload`
   - 启动: `systemctl start remlink`
   - 停止: `systemctl stop remlink`
   - 开机自启: `systemctl enable remlink`

### Docker Compose

1. 进入 `deploy` 目录
2. 执行脚本 `docker-compose up`

### k8s

1. 进入 `deploy` 目录
2. 执行脚本 `kubectl apply -f deployment.yaml`

## Docker

### remlink 镜像地址

镜像发布在 DockerHub（具体版本号可以查看 `version` 文件）：

|    支持设备/平台    |       DockerHub       |
|:-------------:|:---------------------:|
| x86_64/amd64  | wsczx/remlink:latest |
| x86_64/amd64  | wsczx/remlink:0.15.1 |
| armv8/aarch64 | wsczx/remlink:latest |
| armv8/aarch64 | wsczx/remlink:0.15.1 |

### docker 镜像源地址

> docker.1ms.run/wsczx/remlink:latest
>
> dockerhub.yydy.link:2023/wsczx/remlink:latest


### 操作步骤

1. 获取镜像
   ```bash
   # 具体tag可以从docker hub获取
   # https://hub.docker.com/r/wsczx/remlink/tags
   docker pull wsczx/remlink:latest
   ```

2. 查看命令信息
   ```bash
   docker run -it --rm wsczx/remlink -h
   ```

3. 生成密码
   ```bash
   docker run -it --rm wsczx/remlink tool -p 123456
   #Passwd:$2a$10$lCWTCcGmQdE/4Kb1wabbLelu4vY/cUwBwN64xIzvXcihFgRzUvH2a
   ```

4. 生成 jwt secret
   ```bash
   docker run -it --rm wsczx/remlink tool -s
   #Secret:9qXoIhY01jqhWIeIluGliOS4O_rhcXGGGu422uRZ1JjZxIZmh17WwzW36woEbA
   ```

5. 查看所有配置项
   ```bash
   docker run -it --rm wsczx/remlink tool -d
   ```

6. 启动容器
   ```bash
   # 默认启动（首次启动会在日志中打印随机管理员密码）
   docker run -itd --name remlink --privileged \
       -p 443:443 -p 8800:8800 -p 443:443/udp \
       --restart=always \
       wsczx/remlink
   
   # 自定义配置目录（持久化数据库和密钥）
   docker run -itd --name remlink --privileged \
       -p 443:443 -p 8800:8800 -p 443:443/udp \
       -v /home/myconf:/app/conf \
       --restart=always \
       wsczx/remlink
   
   docker restart remlink
   ```

7. 使用自定义参数启动容器
   ```bash
   # 参数可以参考 ./remlink tool -d
   # 可以使用命令行参数 或者 环境变量 配置
   docker run -itd --name remlink --privileged \
       -e LINK_LOG_LEVEL=info \
       -p 443:443 -p 8800:8800 -p 443:443/udp \
       -v /home/myconf:/app/conf \
       --restart=always \
       wsczx/remlink \
       --ip_lease=1209600 # IP地址租约时长
   ```

8. 使用非特权模式启动容器
   ```bash
   # 参数可以参考 ./remlink tool -d
   # 可以使用命令行参数 或者 环境变量 配置
   docker run -itd --name remlink \
       -p 443:443 -p 8800:8800 -p 443:443/udp \
       -v /dev/net/tun:/dev/net/tun --cap-add=NET_ADMIN \
       --restart=always \
       wsczx/remlink
   ```

9. 构建镜像 (非必需)
   ```bash
   git clone https://github.com/wsczx/remlink.git
   cd remlink
   make docker   # 或 docker build -t remlink -f docker/Dockerfile .
   ```

## 常见问题

请前往 [常见问题文档](https://github.com/wsczx/RemLink/blob/main/doc/question.md) 查看具体信息

## Support Document

- [三方文档-男孩的天职](https://note.youdao.com/s/X4AxyWfL)
- [三方文档-issues](https://github.com/wsczx/remlink/issues)
- [openwrt 安装 openconnect 配置客户端教程](https://gitee.com/wsczx/remlink/wikis/pages?sort_id=16384148&doc_id=6261997)
- [三方文档-思有云](https://www.ioiox.com/archives/128.html)
- [三方文档-杨杨得亿](https://yangpin.link/archives/1897.html)  [Windows电脑连接步骤-杨杨得亿](https://yangpin.link/archives/1697.html)

## Support Client

- [AnyConnect Secure Client](https://www.cisco.com/) (Windows/macOS/Linux/Android/iOS)
- [OpenConnect](https://gitlab.com/openconnect/openconnect) (Windows/macOS/Linux)
- [三方 RemLink Secure Client](https://github.com/tlslink/remlink-client) (Windows/macOS/Linux)
- [【推荐】三方客户端下载地址](https://cisco.yydy.link/) (
  Windows/macOS/Linux/Android/iOS)
- [客户端下载面板搭建](https://blog.yydy.link/archives/2018.html) (支持Docker、Linux二进制、Windwos系统直接运行)

## Contribution

欢迎提交 PR、Issues，感谢为 RemLink 做出贡献。

注意新建 PR，需要提交到 dev 分支，其他分支暂不会合并。

## Other Screenshot

<details>
<summary>展开查看</summary>

![system](https://img.wsczx.com/remlink-screenshot-system.jpg)
![setting](https://img.wsczx.com/remlink-screenshot-setting.jpg)
![users](https://img.wsczx.com/remlink-screenshot-users.jpg)

</details>

## License

RemLink 为闭源商业软件，采用专属最终用户许可协议（EULA），完整条款见 [LICENSE](LICENSE)。未经授权，不得复制、修改、反向工程或再分发本软件及其任何部分。

