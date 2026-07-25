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
- [x] 基于 tun / tap / macvtap 设备的桥接访问模式
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

网络模式选择，需要配置 `link_mode` 参数，如 `link_mode="tun"`、`link_mode="tap"`、`link_mode="macvtap"` 等参数。
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
global_nat = false

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

#### tap / macvtap 桥接设置

桥接模式下客户端可获得与内网同段的真实 IP。RemLink 支持三种桥接方式：

- **arp_proxy（tun + 内核 proxy_arp）**：利用 Linux 内核 ARP 代理，无需混杂模式、无需网桥，手动开启 `proxy_arp` 即可。
- **tap（用户态 ARP 代答）**：服务端用户态代答 ARP，需主网卡混杂模式并配置网桥。
- **macvtap（内核态）**：基于内核 `macvtap` 模块，需主网卡混杂模式。

> 网络限制：云环境下通常不能使用（无混杂模式，网卡 MAC 加白、802.1x 认证网络受限），请使用 tun 模式。
>
> 内网网段参数可通过 `ip a` 查看。

1.1 arp_proxy（tun + 内核 proxy_arp）

利用 Linux 内核 `proxy_arp`：客户端 IP 配在 tun 接口，当 `ipv4_cidr` 与主网卡同网段、且主网卡开启 `proxy_arp` 时，内网机器对客户端 IP 的 ARP 请求会由内核代答（内核知道该 IP 路由走 tun），从而实现二层互通。无需混杂模式、无需网桥。

```shell
# 开启内核 ARP 代理（写入 /etc/sysctl.conf 持久化）
sysctl -w net.ipv4.conf.all.proxy_arp=1

# 配置文件修改
# 首先关闭 nat 转发功能
global_nat = false

link_mode = "tun"
#内网主网卡名称
ipv4_master = "eth0"
#以下网段需要跟 ipv4_master 网卡设置成一样
ipv4_cidr = "10.1.2.0/24"
#网关填主网卡自身 IP
ipv4_gateway = "10.1.2.99"
ipv4_start = "10.1.2.100"
ipv4_end = "10.1.2.200"
```

1.2 tap（用户态 ARP 代答）

服务端在用户态对客户端做 ARP 代答，需主网卡开启混杂模式并配置网桥（标准 Linux 网桥 `remlink0`）。不依赖 `macvtap` 内核模块，兼容性最好，适合需要二层广播 / 多播 / 非 IP 协议穿透、或环境不支持 `macvtap` 的场景。

```shell
# 主网卡开启混杂模式
ip link set dev eth0 promisc on

# 配置文件修改
# 首先关闭nat转发功能
global_nat = false

link_mode = "tap"
#内网主网卡名称
ipv4_master = "eth0"
#以下网段需要跟ipv4_master网卡设置成一样
ipv4_cidr = "10.1.2.0/24"
ipv4_gateway = "10.1.2.1"
ipv4_start = "10.1.2.100"
ipv4_end = "10.1.2.200"
```

1.3 macvtap（内核态）

基于内核 `macvtap`（`macvlan`）模块，由内核直接桥接，性能优于 tap。注意：macvlan 的 vepa / private 模式会限制接口间或与宿主机互访，且部分容器 / 受限环境无法加载该模块；此类情况改用 tap。

```shell
# 主网卡开启混杂模式
ip link set dev eth0 promisc on

# 配置文件修改
# 首先关闭nat转发功能
global_nat = false

link_mode = "macvtap"
#内网主网卡名称
ipv4_master = "eth0"
#以下网段需要跟ipv4_master网卡设置成一样
ipv4_cidr = "10.1.2.0/24"
ipv4_gateway = "10.1.2.1"
ipv4_start = "10.1.2.100"
ipv4_end = "10.1.2.200"
```

### IPv6 双栈（IPv6 Dual-Stack）

RemLink 支持 IPv4 / IPv6 双栈，叠加在任意 `link_mode`（tun / tap / macvtap）之上，无需改动既有 v4 配置。

> **总开关**：后台「虚拟网络」填写 `ipv6_cidr` 即启用 IPv6；**留空则纯 v4**（字节级不变，向后兼容）。该字段为空时，下面所有 IPv6 行为均不生效。

#### 客户端地址分配

- 每个客户端分配一个 **`/128`** 地址（不是整段）。
- 网关地址 = `ipv6_cidr` 网段地址 **+1**（例如 `2001:db8:1::/64` → 网关 `2001:db8:1::1`，客户端从 `::2` 起分配）。
- 服务器侧据此建立 v6 隧道端点，客户端据此设置默认（或下发）v6 路由。

#### 两种出网模式（由 `global_nat` 决定）

`global_nat` 是 **v4 / v6 共用的同一个开关**，对称管理两侧出网：

| 模式 | `global_nat` | 行为 | 前置要求 |
|------|-------------|------|----------|
| **NAT66（默认）** | `true` | 客户端 v6 源地址被 masquerade 成**服务器 egress 网卡自身的 GUA** 出网 | 服务器 egress 网卡有公网 GUA 即可，**最简单** |
| **纯路由** | `false` | 客户端使用池内**真实 GUA** 直接路由出网，不经 NAT | 运营商 / 上游交换机 / VPC 路由表须把 `ipv6_cidr` 段**回指**到 RemLink 服务器，否则外部无法回包 |

> 你当前验证通过的即是 **NAT66 模式**（`global_nat` 保持默认 `true`）：客户端 `2409:8a62:856:3011::2` 经服务器 GUA 出网，公网 `ping6` 正常。

> ⚠️ **模式由 `global_nat` 决定，不由你填什么地址决定**。填了一个可路由的 GUA 段**不会**自动进入纯路由模式、也**不会**让 `global_nat` 失效——`global_nat=true` 时 NAT66 照常对该段生效（只是浪费了段的可路由性）。只有 `global_nat=false` 才是纯路由。不确定用哪种时，**保持 `global_nat=true`（NAT66）最稳**，任意合法 v6 段都能出网。

#### 前置条件（两种模式都需满足）

1. **服务器 egress 网卡必须有 GUA（全球单播地址）**：`ip -6 addr show <网卡>` 应能看到 `2409:8a62:...` / `2001:...` 开头的 `global` 地址，而**不只是 `fe80::` 链路本地**。没有 GUA，NAT66 无可 masquerade 的源、纯路由也无回包目标。
2. **`ipv6_cidr` 填什么，取决于你的前缀是「路由型」还是「on-link 型」**——这是选模式的关键：

   **A. 路由型前缀（DHCPv6-PD 委派，可走纯路由）**
   - 家庭 / 企业宽带通常从运营商拿到 **IPv6-PD**（如 `2409:8a62:856:3010::/60`），上游明确把整段**路由**到你这台设备。前提是 **RemLink 服务器本身就是拿 PD 的那台**（光猫桥接后本机拨号、软路由自己 PD）。
   - PD 内含 16 个 `/64`，**取其中一个未被 LAN 占用的 `/64`** 作为池，例如 `2409:8a62:856:3011::/64`（避开路由器已用在 LAN 的 `3010::/64`）。**不要把整个 `/60` 当池**——会与 LAN 段重叠，导致 NDP / 出网混乱。
   - 此类前缀可 `global_nat=false` 走纯路由（客户端拿真 GUA）；不确定也可 `global_nat=true` 走 NAT66。
   - 判断方法：服务器上 `ip -6 route show` 应能看到一条指向本机的 `2409:8a62:856:3011::/64 dev ...`。

   **B. on-link 型前缀（SLAAC 单 /64，只能 NAT）**
   - 典型是**境外 VPS**：`ip -6 addr` 只有一个 SLAAC 动态 `/64`（如 `2605:52c0:2:975:.../64 scope global dynamic`），这个 /64 是**和同网段其它 VPS 共享的 on-link 段**，上游网关只对每个具体地址做 NDP，**没有整段路由给你**。
   - ❌ **绝不能**从这个 /64 切一段做池 + `global_nat=false`：上游会对池地址发 NDP 请求，服务端无出口侧 NDP 代答，**回程直接死**。
   - ✅ 正确做法：`ipv6_cidr` 填一个 **ULA 段**（如 `fd00:c0de::/64`，任意 `fd` 开头 /64 均可，避开 FakeDNS 占用的 `2001:db8::/32`），`global_nat=true` 走 **NAT66** —— 客户端 ULA 池地址出网时 masquerade 成 VPS 自身的 SLAAC GUA，无需 NDP、无需上游配合。
   - 想让境外 VPS 客户端拿真 GUA（纯路由），只能向服务商申请一个**额外的 routed /64 或 /48**（工单/面板），拿到后按 A 类处理。
3. **服务器 IPv6 转发由 RemLink 自动开启**：当 `ipv6_cidr` 非空时，新版本二进制启动时会自动设置 `net.ipv6.conf.all.forwarding=1` 并将 egress 接口 `accept_ra` 设为 `2`（防止打开转发后内核停 RA、丢失默认路由），**无需手动 sysctl**。老版本或想持久化可写入 `/etc/sysctl.d/99-ipv6.conf`：
   ```ini
   net.ipv6.conf.all.forwarding = 1
   net.ipv6.conf.<egress网卡名>.accept_ra = 2
   ```

#### ULA 与公网可达性

- `fd00::/8`（ULA，站点本地地址）本身**公网不可路由**，但这**不代表** ULA 池上不了公网——区别在于是否经 NAT66：
  - **ULA 池 + `global_nat=true`（NAT66）**：客户端 ULA 源地址被 masquerade 成服务器 egress 的 **GUA** 出网，**可以正常访问公网 v6**。这正是**境外 VPS（on-link /64）的推荐方案**。
  - **ULA 池 + `global_nat=false`（纯路由）**：ULA 不可公网路由，**出不了公网**（仅内部互通 / 验证数据面），这是 RFC 4193 的预期行为，不是 bug。
- 只有当你想让客户端拿到**真实可路由的 GUA**（纯路由、无 NAT）时，才必须用可路由的 GUA 段（PD 委派或 routed 前缀）。

#### 配置与验证示例

**场景一：本地服务器 + 运营商 IPv6-PD（如 `2409:8a62:856:3010::/60`）**

1. 后台「虚拟网络」：
   - `ipv6_cidr` = `2409:8a62:856:3011::/64`（PD 内未被 LAN 占用的一个 /64）
   - `global_nat` 保持默认 `true`（NAT66，最稳）；确认该 /64 已路由到本机也可设 `false` 走纯路由
2. 保存后**重启 RemLink** 服务，客户端重连。

**场景二：境外 VPS（`ip -6 addr` 只有单个 SLAAC on-link /64）**

1. 后台「虚拟网络」：
   - `ipv6_cidr` = `fd00:c0de::/64`（ULA，勿用 `2001:db8::/32`）
   - `global_nat` = `true`（**必须 NAT66**；切 VPS 自带 /64 做纯路由会因 NDP 回程死）
2. 保存后**重启 RemLink** 服务，客户端重连。

**客户端验证（Windows 示例，两场景通用）**：
```powershell
# 通网关（证明隧道头 + 接口 v6 + 服务器侧 v6 端点 OK）
ping <ipv6_cidr 网段地址+1，如 2409:8a62:856:3011::1 或 fd00:c0de::1>
# 通公网（证明 NAT66 / 路由 OK）
ping 2001:4860:4860::8888
```
> 若公网某特定站点（如 google）不通，先在**服务器上**直接 ping 该站点真实 v6 地址；服务器自己都不通 = 出口链路问题（换服务器），与 RemLink 无关。

#### 故障排查

| 现象 | 原因 / 处理 |
|------|------------|
| 网关不通 | 服务器侧 v6 端点未建立，查看系统日志是否有 `permission denied` 等 |
| 网关通、公网不通（NAT66） | 服务器 egress 无 GUA，或 IPv6 转发未开（`net.ipv6.conf.all.forwarding=1`），或 `global_nat` 被误关 |
| 网关通、公网不通（纯路由） | 上游未把 `ipv6_cidr` 段回指到服务器；若前缀是 on-link（如境外 VPS SLAAC /64）切段做纯路由必然回程死，改用 ULA + NAT66 |
| 用 ULA 池 + 纯路由公网不通 | 预期行为（ULA 不可公网路由）；开 `global_nat=true` 走 NAT66 即可公网可达，或换可路由 GUA 段 |
| 目标特定站点（如 google）v6 超时、但国内 v6 站点正常 | **非 RemLink 问题**：服务器自身 v6 出口到该目标不可达（如境内出口被墙 google v6）。在服务器上 `ping6 <目标真实地址>` 若同样不通即证实，换 v6 出口可达的服务器 |

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

