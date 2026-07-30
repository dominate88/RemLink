# RemLink WebVPN（免客户端接入）设计方案

> 状态：设计稿 v2（2026-07-30，评审修订：认证改用 portal JWT、证书多张并存、server 级超时豁免、审计定为新表；v2 二次修订含范围/边界/缺口盘点与全局安全头硬伤约束）
> 范围：Web 应用反向代理（核心）+ 通用 TCP 端口转发（第二阶段）。
> 定性：**本方案本质是让 RemLink 内置一个「身份感知的七层反向代理」**。与「Nginx 放前面」的差别在于：认证/授权/审计与 RemLink 账号体系原生打通、按会话动态授权、统一管理面——这是外挂 Nginx 做不到或做起来更别扭的部分。

## 总体架构

```
                    ┌────────────────────────────── RemLink 服务端 ──────────────────────────────┐
浏览器 ──TLS──▶ 443 SNI/Host 分流 ─┬─ vpn.example.com        → 现有 CSTP/portal/admin（不动）
                                   ├─ *.wv.example.com       → WebVPN L7 反向代理（新增）
                                   │     认证(webvpn_session JWT) → 授权(App×用户/组) → ReverseProxy → 内网 HTTP(S)
                                   └─ wv.example.com/agent   → TCP 转发 WebSocket 隧道（阶段二）
```

关键选型（已定，理由见附录A）：
- **子域名映射**（`oa.wv.example.com → 10.0.1.10:80`），**不做** Cisco 式 `/+webvpn+/` 路径改写
- 网关自持证书终止 TLS，**无 MITM/自建 CA**
- 转发核心用标准库 `httputil.ReverseProxy`（含 WebSocket 升级原生支持）

## 阶段一：Web 应用代理（~3 周）

### 1. 数据模型（dbdata）

```go
type WebVpnApp struct {
    Id          int       `xorm:"pk autoincr not null"`
    Name        string    `xorm:"varchar(64) not null"`        // 显示名：OA系统
    Subdomain   string    `xorm:"varchar(64) not null unique"` // oa → oa.wv.example.com
    Backend     string    `xorm:"varchar(255) not null"`       // http://10.0.1.10:80 或 https://...
    SkipVerify  bool      `xorm:"Bool"`                        // 后端自签证书时跳过校验
    HostRewrite string    `xorm:"varchar(128)"`                // 可选：改写转发的 Host 头（虚拟主机后端需要）
    Groups      []string  `xorm:"Text"`                        // 允许的用户组，空=全部
    Note        string    `xorm:"varchar(255)"`
    Status      int8      `xorm:"Int default 1"`
    CreatedAt   time.Time `xorm:"DateTime created"`
    UpdatedAt   time.Time `xorm:"DateTime updated"`
}
```

ServerConfig 新增：`WebVpnDomain`（如 `wv.example.com`，空 = 功能关闭）。

### 2. 会话与认证（v2 修订：复用 portal JWT，否决 WebOnly 会话）

> v1 曾设计「复用 CSTP stoken + Session 加 WebOnly 字段」，评审否决，两个理由：
> ① cookie 名 `webvpn` 与现有 CSTP 隧道冲突——`LinkTunnel` 就是读 `r.Cookie("webvpn")` 取 stoken（link_tunnel.go:42）；
> ② `checkSession` 会把 `!IsActive` 且 SessionTimeout 内无活动的会话当超时清掉（session.go:115-118），WebOnly 会话永远没有 ConnSession、永远不 IsActive，用户浏览中会被误杀，除非每个代理请求都去刷 LastLogin——等于给热路径加锁写共享 map。

**v2 方案：复用 portal 已有的 JWT 无状态鉴权**（`portalIssueToken`/`portalCurrentUser`，portal.go:1118-1167）。它不碰内存 session map、不占 IP 池、JWT 里自带 Groups（正好做 App 授权）、不受 checkSession 回收影响，登录链路可整体复用 `portalStartAuth`（密码+OTP+lockManager 防爆破）。

- Cookie：**独立命名 `webvpn_session`**（不用 `webvpn`，也不复用 host-scoped 的 `portal_session`），值为 JWT，Domain=`.wv.example.com`（一次登录所有子域通行），`Secure; HttpOnly; SameSite=Lax`
- 校验：Host 分流后、进代理前，`GetJwtData` 验签 → 取用户/组；无效 → 302 到 `wv.example.com/login`
- 登录页：复用 portalStartAuth 全链路，成功后签 JWT 写 `webvpn_session`
- **滑动续期**（portal JWT 固定 3h 无续期，浏览器场景不可接受）：校验时若剩余有效期 < 1h，重签并 Set-Cookie；无操作满 3h 自然过期
- **热路径用户缓存**：`portalCurrentUser` 每次调用查一次 DB（`dbdata.One`），代理路径上每个静态资源请求都会打库；WebVPN 分支加 30~60s TTL 的用户状态缓存（username → 状态/组），缓存命中时不查库
- **吊销（踢会话立即生效）**：分两层，复用现有代码而非另造：
  - 单会话吊销（登出/改密/踢指定会话）：`SetJwtData` 已写入 `jti` claim（admin/common.go:61），`GetJwtData` 已支持 `jwtRevoked` 按 jti 黑名单拒绝（admin/common.go:92-99，含 `RevokeJwt`/`RevokeJwtToken`）——**这层已经免费存在，直接复用**；v2 原稿「无需 jti 黑名单」的判断需更正。
  - 整用户吊销（禁用账号/踢某用户全部会话）：jti 黑名单不知道该用户还有哪些活跃 jti，需轻量「失效水位」：内存 map `username → revokeBefore 时间戳`，禁用/踢人时写入，校验时比较 `iat < revokeBefore` 即拒绝。
  - **前置修正（评审 A 点）**：水位靠比较 `iat`，但 `SetJwtData` 当前只写 `exp`+`jti`、无 `iat`（common.go:58-68）。靠 `exp - 3h` 反推签发时间在滑动续期下失效（续期后 exp 前移）。**必须给 webvpn_session token 显式加 `iat` claim**（复用 `portalIssueToken` 已写入的 `portal_user` 作水位 lookup key）。O(1) 校验。
- 在线展示：WebVPN 活跃用户不进 session map，在线列表如需展示，从用户缓存/审计侧另做，不伪造 Session 对象

### 3. 代理核心（handler/webvpn.go 新增）

- 入口（**必须作为外层 wrapper 挂载，避免被全局安全头污染**，评审第四点硬伤）：在 `initRoute()` 返回的 mux **之外**再包一层 Host 判断中间件——`Host` 后缀匹配 `*.wv.example.com` 则**由 WebVPN 分支直接处理并短路，绝不 delegate 进 mux**；否则走现有路由。原因：`initRoute` 里 `r.Use(SetSecureHeader)` 给所有 mux 路由统一套了严格策略（`secure_header.go:21` 的 `default-src 'self'`、`X-Frame-Options`、`:24` `Cross-Origin-Embedder-Policy: require-corp`、`:26` `Cross-Origin-Resource-Policy: same-origin` 等，见 server.go:109-114）。若把 WebVPN 实现成 mux 子路由（`r.Host(...).Handler(...)`），SetSecureHeader 会**重新套到被代理响应上**，把后端外部资源/内联脚本/iframe 全拦掉——M2 上线即大面积白屏。故 WebVPN 必须是**外层短路**，被代理响应**不继承任何全局安全头**；需要的头由代理层按需显式设置（MVP 至少不要带 COEP/CORP require-corp，否则跨域子资源全挂），后端自带 CSP 则保留不动。
- **超时豁免（M2 必做，v2 新增；机制经评审 B 点修正）**：VPN 的 `http.Server` 写死 `ReadTimeout/WriteTimeout = 100s`（handler/server.go:80-81），这是**连接级**超时，影响分两类：
  - **不 hijack 的转发响应（确定性失败，必须豁免）**：普通 HTTP 响应、>100s 的大文件下载/流式响应、SSE——WriteTimeout 在请求开始 100s 后掐断仍在写的连接；>100s 的大文件**上传**受 ReadTimeout 影响。这是 M5 验收要打的场景。
  - **WebSocket（通常不受影响，仍建议套豁免）**：Go 1.20+ 的 `ReverseProxy` 处理 Upgrade 时内部 `hijack`，脱离 server 逐请求生命周期、数据阶段不再被逐次重置 deadline；但握手阶段已设到 conn 上的 OS 级 deadline 仍挂着——典型 WS（ping/pong < 100s）写入落在 deadline 内、一般能活过 100s，若静默超 100s 再 I/O 仍可能撞上。故 WS 端点也对**本连接套一次豁免**（清遗留 deadline，保长闲 WS 不断），但它**不适合作豁免是否生效的验收用例**（即便不做豁免多数也能过 100s）。
  - 修法：WebVPN 分支入口用 `http.ResponseController` 的 `SetReadDeadline/SetWriteDeadline(time.Time{})` 清除本连接 deadline（Go 1.20+，本项目 Go 1.26 满足）。空闲控制交给 transport 层 `IdleConnTimeout` + 应用层心跳。**不改全局 100s**（保护现有 CSTP/portal），不单起 listener（443 只有一个）
- 查表：subdomain → WebVpnApp（内存缓存 + 变更失效）
- 授权：JWT 内用户组 ∈ App.Groups
- 转发：每 App 一个 `httputil.ReverseProxy` 实例（连接池复用），`Rewrite` 钩子处理：
  - `X-Forwarded-For/Proto/Host` 注入
  - HostRewrite
  - 剥离 `webvpn_session` cookie（不泄漏给后端）
  - **入站头清洗（评审第五点）**：转发前先剥掉客户端伪造的 `X-Forwarded-*`/`X-Real-IP`，再按真实来源重写，避免后端拿到伪造来源（现有代码仅在 portal 读取 `X-Forwarded-Proto`，无统一反代清洗逻辑，需新写）
  - **登出/禁用联动（评审第五点）**：登出或禁用用户须清除 `webvpn_session` cookie（Domain=`.wv.example.com`）；多 App 子域间靠此共享登录态
  - 响应 `Location` 头若指向后端地址 → 改写回子域名（302 跳转场景，低成本必做；HTML 正文**不改写**——子域名方案下相对链接天然正确）
  - **向后端注入身份（评审第三点，本期未实现）**：`webvpn_session` JWT 仅作网关侧访问闸门（App×用户/组授权），代理转发时**不替用户认证后端**（portal.go:1118-1125 只签发 JWT，无表单重放/请求头/Kerberos/SAML 注入）。用户通过授权后仍可能需在 OA 自身再登录一次；SSO 透传列入后续阶段，不在 MVP 范围
- WebSocket：Go 1.20+ ReverseProxy 原生透传 Upgrade（内部 hijack）；在分支入口已对本连接套豁免的前提下稳定可用，无需额外处理
- 错误页：后端不可达时返回带 App 名的友好错误页

### 4. 证书（v2 修订：真实成本在多证书并存，不在 SNI 通配）

事实核对后修正 v1 的两处误判：

- **「现有证书管理已支持多证书」不成立**。`buildNameToCertificate` 每次加载先清空整个 `nameToCertificate` map 再写入这一张证书的 CN/SAN（dbdata/cert.go:414-444），`LoadCertificate` 是**替换**语义——全局同一时刻只有一张 server 证书。SNI 通配匹配（`*.` 前缀查表）倒是现成的（GetCertificateBySNI，cert.go:393-400），不是工作量所在。
- **LE 泛域名 v1 就能签，不必降级**。现有 LE 集成只走 DNS-01（`SetDNS01Provider`，支持 aliyun/txcloud/cloudflare，cert.go:217-233），DNS-01 天然支持泛域名。改动只是 `GetCert` 目前 `Obtain` 单域名（cert.go:246-262），需支持传入泛域名。

两条落地路径：

| 路径 | 内容 | 改动量 |
|---|---|---|
| A. 单证书多 SAN | `vpn.example.com` + `*.wv.example.com` 合进一张证书（自传或 LE `Obtain(Domains: [...])` 均可） | 极小，现有替换语义直接兼容 |
| B. 多证书并存 | 改造 `buildNameToCertificate` 为按「来源槽位」累加（server 槽 / webvpn 槽各自清理重建，互不覆盖）；`SettingTLSCert` 存储也要加第二槽位 | M4 的真实工作量 |

**v1 以路径 A 为默认交付**（文档指引用户合并 SAN），**路径 B 做进 M4**——因为自传用户的既有证书大概率不含 wv 域，强迫重新签发是不合理的使用门槛。B 完成后 A 自动成为其特例。

### 5. 门户页

`wv.example.com/` 登录后展示该用户可访问的 App 卡片列表（图标+名称+描述），点击跳对应子域。复用 portal 的 Vue 工程追加页面。

### 6. 审计

**定为新表 `WebVpnAudit`**（v2 定稿：AccessAudit 是 IP 包五元组模型 Protocol/Src/Dst/DstPort，与 L7 的 AppName/URL/Method/Status 语义不匹配，不扩展）：记录用户、App、方法、路径（不含 query，防敏感信息入库）、状态码、字节数。异步批量写入，照 `logAudit` 的批处理模式。

### 7. 管理面

- admin API：`/webvpn/app/list|detail|set|del`、`/webvpn/audit/list`
- 前端：「WebVPN 应用」管理页 + 审计查询页

### 8. 里程碑（~3 周）

| 里程碑 | 内容 | 估时 |
|---|---|---|
| M1 | WebVpnApp 表 + admin API + 管理页 | 3d |
| M2 | Host 分流中间件 + **超时豁免（ResponseController）** + ReverseProxy 核心 + 授权 | 4d |
| M3 | 登录页/门户页 + **portal JWT 接入（webvpn_session cookie/滑动续期/用户缓存/吊销水位）** | 3d |
| M4 | **多证书并存改造（buildNameToCertificate 槽位化 + 存储第二槽位）** + LE 泛域名 Obtain | 3-4d |
| M5 | 审计 + 联调（含 >100s **流式下载/大文件上传**、302 场景） | 3d |

> M4 由 2d 调为 3-4d（多证书并存是真实成本）；M5 验收改用「>100s 流式下载 + 大文件上传」——这是确定受 100s server 超时影响的非 hijack 长响应，直接验证 M2 的 ResponseController 豁免是否生效（WebSocket 因 ReverseProxy 内部 hijack 通常不受影响，不适合作此项验收，见 §3）。

## 阶段二：通用 TCP 端口转发（~2-3 周，独立排期）

> 你要求覆盖通用 TCP。先明确：**浏览器无法直接发起任意 TCP 连接**，所以「免客户端」和「任意 TCP」不可兼得，只能取以下形态之一。

### 形态对比

| 形态 | 用户体验 | 实现成本 | 判断 |
|---|---|---|---|
| a. 轻量转发器（推荐） | 下载单文件小工具 `remlink-fwd`，本地 `127.0.0.1:3389 → 内网:3389` | 中 | **推荐**：一个 ~200 行的 Go 单二进制，不是「第二个 VPN 客户端」 |
| b. Web 化终端（SSH/RDP） | 纯浏览器 | SSH 中 / RDP 极高 | SSH 可做（xterm.js + WS）；RDP 需 Guacamole 级投入，不自研 |
| c. 浏览器内 TCP over WS + 页面代理 | 纯浏览器但仅限特定应用 | 高 | 放弃 |

### 形态a 设计

- 服务端：`wss://wv.example.com/tcp-tunnel?app=<id>` WebSocket 端点，认证复用 `webvpn_session` JWT / 一次性码；每条 WS 对应一条到后端的 TCP 连接（`io.Copy` 双向）；同样依赖 M2 的超时豁免（WS 端点套一次 deadline 清除，保证长闲连接不断）
- 数据模型：WebVpnApp 增 `Type`（http/tcp）与 `TcpPort`；tcp 类型 App 表示「允许转发到 Backend:TcpPort」
- 客户端 `remlink-fwd`：Go 编写，交叉编译三平台单文件；参数 `remlink-fwd -server wv.example.com -app rdp-fin -listen 127.0.0.1:3389 -token <一次性码>`；门户页 App 卡片直接生成完整命令行供复制
- 一次性码：门户页签发短时效 token，避免用户在命令行暴露长期凭据
- 审计：连接建立/断开/字节数入 WebVpnAudit

### 形态b（SSH Web 终端，可选加分项）

xterm.js（前端）+ `golang.org/x/crypto/ssh`（服务端起 SSH 连接）+ WS 桥接，约 1 周。RDP/VNC 明确不自研，如有需求引导用户走形态a + 本地 mstsc。

## 范围、边界与已知缺口（评审盘点，2026-07-30）

本方案完整实现的是「身份感知反向代理」这一**被有意收窄**的目标，不是「完整的 webvpn / 通用七层代理」。逐类说明：

**一、主动放弃（写入定性，非缺陷）**
- 缓存 / 压缩 / 限流 / WAF：明确不做，留给用户前置设施。
- Cisco 式 `/+webvpn+/` 路径改写：附录 A 否决，只做子域名映射。代价见下「硬编码绝对 URL」。

**二、范围性不完整（设计已画定的边界）**
- 非 Web 流量（TCP/RDP/数据库）仍依赖阶段二自研 `remlink-fwd` 客户端 + WS 隧道——只有 Web(HTTP/S) 真正免客户端；「免客户端」对 TCP 是「换更轻客户端」而非零客户端。
- 硬编码绝对 URL 的后端应用：子域名方案救不了（风险 #2 自承），引导走隧道。公允讲，这是 webvpn 品类的固有难题（Cisco 投入十余年仍未彻底解决），非本方案独有缺陷。

**三、功能性缺口（完整 webvpn 的核心缺失，方案未实现）**
- **向后端注入身份 / SSO 透传**：`webvpn_session` JWT 仅作网关侧访问闸门，代理转发时不替用户认证后端（§3 已标注）。列后续阶段。

**四、动工前必须先解决的硬伤（集成隐患）**
- **全局安全头污染被代理内容**：`r.Use(SetSecureHeader)` 给所有 mux 路由套严格 CSP/X-Frame-Options/COEP require-corp/CORP same-origin（server.go:109-114，secure_header.go:18-28）。若 WebVPN 实现成 mux 子路由会重新套用，被代理应用白屏。**已在 §3 入口约束为「外层 wrapper 短路、不 delegate 进 mux」，被代理响应不继承全局安全头**——这是 M2 落地的前置硬条件。

**五、需补齐的常规反代要点**
- 入站头清洗：`X-Forwarded-*`/`X-Real-IP` 转发前剥离再重写（§3 已补）。
- 跨子域 Cookie 作用域 + 登出联动：`webvpn_session` Domain=`.wv.example.com` 共享登录态，登出/禁用须清除（§3 已补）。
- 吊销水位加 `iat`：见 §2 评审 A 点（M3 前置）。

**定位结论**

| 维度 | 状态 |
|---|---|
| 配合良好的 Web 应用反代（子域名） | 完整可用（MVP） |
| 网关侧身份感知授权 + 审计 | 完整 |
| 任意内网 Web 应用（含硬编码绝对 URL） | 不覆盖（子域名方案固有局限） |
| 向后端 SSO/凭据注入 | 未实现（完整 webvpn 核心缺口） |
| 非 Web(TCP/RDP) 免客户端 | 仍需 remlink-fwd 客户端 |
| 缓存/压缩/限流/WAF | 明确不做 |
| 全局安全头/CSP 对被代理内容的影响 | 未处理 → 已在 §3 约束为动工前硬伤 |

> 一句话：本方案完整实现「身份感知反向代理」这一窄目标，对「配合良好的内网 Web 系统免客户端访问」够用且自洽；若期望「任意应用免客户端 + 后端免二次登录 + 全协议零客户端」的完整 webvpn，还差第三（SSO）、第二（非 Web 客户端）、第四（CSP 污染）这几块，其中第四点是动工前必须先解决的硬伤。

## 与「前置 Nginx」方案的对比（回应你的定性质疑）

| 维度 | RemLink 内置 L7 | Nginx/Traefik 前置 + auth_request |
|---|---|---|
| 认证联动 | 原生 JWT/OTP/防爆破，与账号体系同源 | 需写 auth 子请求端点 + 两套配置 |
| 动态 App 管理 | admin 页 CRUD 即生效 | 改 conf + reload，或上 Nginx Plus/OpenResty |
| 会话踢出 | 踢会话立即生效 | cookie 有效期内难精确回收 |
| 审计 | 与用户体系打通 | access log 无用户语义，需拼接 |
| 部署形态 | 单二进制不变 | 多组件，跟 RemLink「单文件交付」定位冲突 |

结论：内置合理，**但仅限「身份感知代理」这个窄目标**——不做缓存、压缩、限流、WAF 这些通用网关能力，那些永远留给用户自己的前置设施。

## 附录A：为什么不做路径改写（方案否决记录）

Cisco 式 `/+webvpn+/http/host/path` 需改写 HTML/CSS/JS 内所有 URL。现代 SPA 的 URL 由 JS 运行时拼接（`fetch('/api/'+id)`），静态改写覆盖不了，Cisco 投入十余年仍大量兼容性问题。子域名方案下相对路径天然正确，唯一代价是泛域名 DNS+证书，成本不对称，故否决。

## 风险

1. 泛域名 DNS + 证书是硬前置条件，需在文档醒目说明（无泛域名解析能力的用户无法使用此功能）
2. 后端应用若硬编码绝对 URL（含内网 IP 的跳转/资源引用），子域名方案也救不了——门户页需提供「兼容性说明」，此类应用引导走隧道
3. 超时分两层：**server 层 100s Read/WriteTimeout 是主要拦路点**（已在 §3 用 ResponseController 豁免解决，M2 落地）；transport 层 FlushInterval/IdleConnTimeout 属常规调参
4. 安全：WebVPN 把内网 Web 暴露到公网边缘，App 级授权默认拒绝（Groups 空 = 全部**登录用户**，绝非匿名）；登录页沿用现有防爆破
5. JWT 无状态的固有代价：单会话吊销走 `jwtRevoked` jti 黑名单（admin/common.go 已存在，复用即可）；整用户吊销走「失效水位」内存态（需给 webvpn_session 加 `iat` claim，见 §2 A 点）。服务重启后两者均丢失（重启前签发的 JWT 重新有效至自然过期，最长 3h 窗口）——可接受；若不可接受再考虑水位/jti 持久化到 DB
6. 「会话踢出立即生效」在对比表里是内置方案的优势项，v2 改 JWT 后此优势弱化为「秒级水位拒绝」，对比表结论不变但幅度收窄
