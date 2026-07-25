# RemLink IPv6 双栈改造 — 连通优先版定稿设计

> 状态：定稿（v1 已实现；v2 策略补全已实现于 `ipv6-v1` 分支，见 `ipv6-dual-stack-future.md`）
> 范围：仅服务端改动；客户端走标准 AnyConnect / OpenConnect 头，无需改客户端
> 基线决策：TUN + TAP + macvtap 三模式全做；客户端 v6 地址池分配 `/128`；单 `Ipv6CIDR` 自动分配；单一 `GlobalNat` 开关对称管 v4+v6；v6 策略**连通优先**（不做 v6 版 FakeDNS / ACL / 审计）；**v6 默认 NAT66** 作为安全基线
> v2 更新（2026-07-25）：v6 策略层已全部补齐——v6 精细 ACL 匹配、v6 访问审计、v6 FakeDNS(AAAA)+v6 DNAT、v6 DNS 拦截、组级独立 v6 出网隔离（`Group.ClientCidr6` + `AddGroupNAT6` + 前端配置）；`Ipv6CIDR` 为空仍完全维持纯 v4 行为。

---

## 0. 决策基线（已锁定）

| 项 | 决策 |
|---|---|
| 客户端 | 仅 AnyConnect / OpenConnect（标准头，纯服务端） |
| 链路模式 | TUN + TAP + macvtap 全做 |
| v6 地址 | 池分配 `/128` |
| 配置粒度 | 单 `Ipv6CIDR` 自动分配（不暴露 gw/start/end） |
| 出网 | 单 `GlobalNat` 对称管 v4+v6；**默认 NAT66** |
| v6 策略深度 | 连通优先：DNS 拦截 / FakeDNS / ACL / 审计均不做 v6 版 |
| DTLS | `X-DTLS-Address-IP6` 信息性下发；DTLS 传输仍走 v4 接入，本次不动服务端 v6 监听 |
| 向后兼容 | `Ipv6CIDR` 为空 → 完全维持现行纯 v4 行为 |

**内部自动推导（单 CIDR，不暴露给用户）**：`gw = 网络地址+1`，`start = 网络地址+2`，`end = 网段末地址`；分配游标用 `big.Int`（不能用 `uint32`）。

---

## 1. 安全与正确性约束（最高优先级，v1 必须全部满足）

本轮审查发现 4 类缺陷，均为**阻断级或安全倒退级**，必须进 v1。

### 1.1 外围守卫（强制 2 处 + 1 处已安全）

`payloadIn`（`handler/payload.go:10-27`）顺序：`interceptDNS`(12) → `restoreFakeIP`(16) → `checkLinkAcl`(22)。三者都直接对 `pl.Data` 调 `waterutil.IPv4Xxx`，对 v6 包会误读头字节。

| 函数 | 位置 | v6 现状 | 处置 |
|---|---|---|---|
| `interceptDNS` | `dns_intercept.go:30-34` | 已有 `ipVersion != 4 → return false` | **无需改**（v6 DNS 透传真实 DNS） |
| `restoreFakeIP` | `dns_intercept.go:165-201` | 无版本判断；`:171` 误读 v6 头 16–20 字节当 IPv4，若落入 FakeIP 段 → 误丢包 | **强制守卫**：开头加 `if (pl.Data[0]&0xF0)>>4 != 4 { return false }` |
| `checkLinkAcl` | `payload.go:79-135` | 无版本判断；`:85` 误读。且 `:80` 当 `len(rp.LinkAcl)>0` 时 v6 包匹配不上任何规则 → `return false` → **整包丢弃（连通阻断，非仅无管控）** | **强制守卫**：开头加 `if (pl.Data[0]&0xF0)>>4 != 4 { return true }`（连通优先=放行） |
| `logAudit` | `payload_access_audit.go:125-136` | `IPv4Protocol` 读 v6 第 9 字节=Hop Limit（常值 64），非 TCP/UDP → `default: return`；外层 `recover()` 兜底 → v6 自然不审计，**safe-by-accident** | **无需改**（v6 不审计符合连通优先）；可选加显式 `if pl.Data[0]>>4 != 4 { return }` 提升可读性 |

> 结论：强制守卫 = `checkLinkAcl` + `restoreFakeIP` 两处；`interceptDNS` 已守卫；审计无需改。

### 1.2 入站暴露（安全倒退，最高危）

现状（`sessdata/firewall.go`）：
- **NFT** `SetupGlobalNAT` 的 FORWARD 是**有状态的**：先 `ct state ESTABLISHED,RELATED → ACCEPT`（`:285-306`），再 `src∈VPN CIDR → ACCEPT`（`:309-313`），其余落默认 DROP → 安全。
- **IPT** `SetupGlobalNAT` 的 FORWARD 是**无条件 `-j ACCEPT`**（`:136-141`）。v4 下靠"客户端地址是 RFC1918 私网、外部路由不到"遮丑。

**风险**：若 v6 分配 **GUA 公网地址** 且上游把前缀回指本机，IPT 那条无条件 ACCEPT 会把每个客户端 v6 暴露给公网入站（NAT66 才有 conntrack 兜底，纯路由无 MASQUERADE 即无 conntrack）。

**整改（必须）**：
- **v6 默认走 NAT66（`GlobalNat` 开）** 作为安全基线：MASQUERADE 带 conntrack，入站仅 established/related 回包能进，与 v4 一致，零新增风险。
- **纯路由（`GlobalNat` 关 v6）安全条件**（二选一）：① 分配的 `Ipv6CIDR` 为 **ULA（`fd00::/8`）** → 本就不公网可达，暴露消失；② 用 **GUA** → 必须配 **stateful FORWARD**（established/related + `src∈VPNv6CIDR` ACCEPT，其余 DROP），**绝不可复刻 IPT 无条件 ACCEPT**。
- 实现约束：`SetupGlobalNAT6` 的 **NFT 直接复用现有有状态 forward 设计即安全**；**IPT 禁止照抄 `-j ACCEPT`**，改 `-m state --state ESTABLISHED,RELATED -j ACCEPT` + `-s <v6cidr> -j ACCEPT`（顺带修掉 v4 IPT 同一隐患）。

### 1.3 split 路由格式（正确性缺陷）

`link_tunnel.go:162,166` 直接推 `v.IpMask`（`"192.168.1.0/255.255.255.0"` 点分掩码串）。但 `X-CSTP-Split-Include-IP6` / `-Exclude-IP6` 要求 **CIDR**。
**整改**：新增解析（兼容点分掩码与 CIDR）归一为 `*net.IPNet`；v4 维持原 `v.IpMask` 下发，v6 用 `ipNet.String()`（CIDR）下发到 `-IP6` 头。前端/校验链若只认 v4 格式需同步补。

### 1.4 FakeDNS AAAA 已知限制（功能性，非安全）

`dns_intercept.go:100-111`：命中 FakeDNS 规则的 AAAA 查询回空响应。DNS 本身跑在 v4 隧道上，故**只要组开了 FakeDNS，其域名的 AAAA 被清空 → 客户端退回 A(v4)**，"双栈"对这批域名是假的。影响面仅限开了 FakeDNS 的组。
**处置**：连通优先下**文档标注为已知限制**；根治 = v2 的 v6 FakeIP。

---

## 2. 配置层 — `base/config.go`

- 新增字段：`Ipv6CIDR string`（如 `2001:db8:1::/64`，要求前缀 < 128 才有分配空间）。
- 不新增 `FakeDNSv6Range`（不做 v6 FakeDNS）、不新增 `Ipv6Master`（复用 `Ipv4Master` 作 v6 出网口）。
- `GlobalNat` 不变，单开关对称管 v4+v6。
- 在 `cfgOptions` 注册（`group:"虚拟网络"`, `restart:true`），json tag + `LINK_` 环境变量读取沿用现有机制。

---

## 3. IP 池 — `sessdata/ip_pool.go`

- `ipPoolConfig` 加：`Ipv6IPNet *net.IPNet` + `ipv6Cursor`（用 `big.Int` 表示相对偏移）。
- `initIpPool()`：`Ipv6CIDR != ""` 时校验前缀、内部推导 `gw/start/end`、置 `ipv6Cursor=0`。
- 新增 `acquireIpV6()` / `loopIpV6()`：游标 `big.Int` 自增、回卷、复用 `ipActive` 去重、租期逻辑照搬 v4 版。
- `ConnSession.IpAddr6 net.IP`；分配调用点一次拿 v4+v6（仅启用 v6 时）。
- `ReleaseIp` 改为 `ReleaseIp(ip, ip6 net.IP, macAddr string)`（纯 v4 时 `ip6=nil`）；v6 与 v4 在**同一分配步**取得（见下"分配点"），故所有释放点须同步释放 v6，杜绝池泄漏。
  - **主释放点 `ConnSession.Close()`（`sessdata/session.go:292`，`closeOnce.Do` 兜底）**：以下所有断开原因都汇聚于此——`CloseSess`（`session.go:517`→`Close`，覆盖空闲超时 `link_cstp.go:72`、DPD 驱动断开、管理员踢线、banner 登出）、`CloseCSess`、数据面 EOF/错误（`link_tun.go:149` / `link_tap.go:133` / `link_cstp.go:20,135` / `session.go:186`）。在 `Close()` 内对 `cs.IpAddr6` 一并释放。
  - **早期退出路径 `NewConnSession`（`session.go:243` 策略加载失败、`session.go:250` 配额超限）**：cSess 尚未建立即释放。因 v6 与 v4 同在 `:206` 的 `AcquireIpWithRange` 一步取得（改 acquire 返回 `(ip, ip6)`），这两处早退须 `ReleaseIp(ip, ip6, macAddr)` 同时释放 v6。

---

## 4. 隧道响应头 — `handler/link_tunnel.go`

启用 v6 时追加（`X-CSTP-Address` 等现有头之后）：
- `X-CSTP-Address-IP6: <IpAddr6>`
- `X-CSTP-Netmask-IP6: <前缀长度，如 128>`
- `X-DTLS-Address-IP6: <IpAddr6>`（信息性；DTLS 仍 v4 接入）

split 路由（§1.3 修正后）：遍历 `rp.RouteInclude/RouteExclude`，按 `ipNet` 含 `:` 分流 → v4 走 `X-CSTP-Split-Include`/`-Exclude`（原 `v.IpMask`），v6 走 `X-CSTP-Split-Include-IP6`/`-Exclude-IP6`（CIDR）。
`X-CSTP-DNS`（`:149-151`）已按 `Val` 下发，v6 DNS 条目自动复用，无需改。

> ⚠️ split-tunnel 下若管理员只配 v4 路由，AnyConnect 默认**不隧道 v6**（走本地）；全量隧道（无 split）则 v6 自动全隧道。后台须提示：双栈 split 必须显式配 v6 段。

> ⚠️ **v6 MTU 下限（≥1280）**：IPv6 要求链路 MTU ≥ 1280，否则大报文会 PMTU 黑洞。MTU 在 `session.go:402-413` 由全局 `GetCfg().Mtu` 赋值、`X-CSTP-MTU`/`X-DTLS-MTU`（`link_tunnel.go:206-207`）与 `netlink.LinkSetMTU`（`link_tun.go:95`/`link_tap.go:90`/`link_vtap.go:110`）共用同一 `cSess.Mtu`。**启用 v6 时**，若 `GetCfg().Mtu < 1280` 须在赋值前**强制上调到 1280 并告警**（网关/客户端两侧同一值，无需分字段）。

---

## 5. TUN 模式 — `handler/link_tun.go`

- 删 `disable_ipv6`（约 `:136`）。
- `LinkTun`：v4 `AddrAdd` 后，启用 v6 时加 本地=`gw`/128、Peer=`IpAddr6`/128。
- `tunRead/tunWrite` 不改（L3 裸写天然兼容 v6）。

---

## 6. TAP / macvtap 数据面（连通必需，非"策略"）

- 去禁用：`link_tap.go` ~`:120`、`link_vtap.go` ~`:129` 删 `disable_ipv6`。
- 新建 `pkg/ndpdis`（类比 `pkg/arpdis`）：`Addr`/`Lookup`/`Add`/`NewNAReply`；网关 v6 的 MAC 复用 `gatewayHw`，NS(type135) 代答回 `gatewayHw`。**NDP 代答是 v6 在二层能通的前提**。
- `allTapWrite`（客户端→服务端，LTypeIPData）：去 `IsIPv6 continue`；v4 保持；v6 分支：校验源==`IpAddr6`（防伪造）→ 目的在 v6 池内用 `ndpdis.Lookup`、否则 `gatewayHw` → `frame.Prepare(..., ethernet.IPv6, ...)`。
- `allTapRead`（服务端→客户端）：`case ethernet.IPv6:` 不再 `continue`，取 IPv6 payload，校验目的==`IpAddr6` 投递；IPv6 内若 `next-header==ICMPv6(58)` 且 NS → 用 `ndpdis` 构 NA 代答（类比现有 ARP 分支）。

---

## 7. NAT / 防火墙 v6 — `sessdata/firewall.go`

- `Firewall` 接口新增（v1 仅此一个）：
  - `SetupGlobalNAT6(vpnCIDR6, masterDev string, inContainer bool, useNat66 bool) error`
  - `CleanupGlobal()` 同步清 IPv6 表。
- **语义**：`SetupGlobalNAT6` **始终**下发 stateful FORWARD（established/related + `src∈VPNv6CIDR`）；仅当 `useNat66`（即 `GlobalNat` 开）才追加 POSTROUTING MASQUERADE。纯路由（GUA）因此也受 stateful 保护（§1.2）。
- **IPT 实现**：`iptables.NewWithProtocol(iptables.ProtocolIPv6)` 建 v6 实例；FORWARD 用 `-m state --state ESTABLISHED,RELATED -j ACCEPT` + `-s <v6cidr> -j ACCEPT`（**非** `-j ACCEPT`）；MASQUERADE 仅 `useNat66` 时加。
- **NFT 实现**：新增 `TableFamilyIPv6` 表；MASQUERADE 表达式 saddr `Offset:8,Len:16`，`mask=net.CIDRMask(ones,128)`，`IP.To16()`；FORWARD 回程 family=IPv6，沿用现有有状态规则结构。`MasqueradeExprs`/`ForwardAcceptExprs` 按 family 分支或新增 v6 版。
- 调用点（`checkTun` / 服务端启动处，启用 v6 时）：`GlobalNat` 开 → `useNat66=true`；关 → `useNat66=false`（仍 stateful FORWARD）。

> **§3↔§7 闭环说明（组级 v6 配置来源）**：§0 已锁定"单 `Ipv6CIDR` 全局池、自动分配"，所有客户端 v6 地址均出自**同一段**全局 CIDR，v1 **不存在每组的 v6 地址空间划分**。因此原 §7 设想的 `AddGroupNAT6(groupCIDR6,...)` 在 v1 **无数据基础**（没有 per-group 的 v6 CIDR 来源），本次**延后到 v2**，接口不实现；`SetupGlobalNAT6` 直接以全局 `Ipv6CIDR` 网络作 source 即可覆盖全部客户端 v6 出网。若未来要组级 v6 出网隔离，再给 `Group` 结构体新增 `ClientCidr6` 字段并落实 `AddGroupNAT6`，届时 §3 池也需支持多 CIDR——故 v1 明确不做。

---

## 8. 外围守卫实现（落到函数）

### 8.1 `checkLinkAcl`（`handler/payload.go:79`）
原 `:80-83` 守卫后插入版本判断：
```go
func checkLinkAcl(rp *dbdata.Policy, pl *sessdata.Payload) bool {
    // 连通优先：v6 流量不做 ACL 匹配，直接放行（v6 精细 ACL 留 v2）
    if (pl.Data[0]&0xF0)>>4 != 4 {
        return true
    }
    if pl.LType == sessdata.LTypeIPData && pl.PType == 0x00 && len(rp.LinkAcl) > 0 {
    } else {
        return true
    }
    // ... 原有 v4 逻辑（:85-134）不变 ...
}
```

### 8.2 `restoreFakeIP`（`handler/dns_intercept.go:165`）
`FakeDNS nil/未启用` 判断后插入：
```go
func restoreFakeIP(cSess *sessdata.ConnSession, pl *sessdata.Payload) bool {
    rp := cSess.Policy
    if cSess.FakeDNS == nil || !rp.EnableFakeDNS {
        return false
    }
    // 连通优先：v6 包不做 FakeIP 还原（v6 FakeIP 留 v2），直接放行
    if (pl.Data[0]&0xF0)>>4 != 4 {
        return false
    }
    ipDst := waterutil.IPv4Destination(pl.Data)
    // ... 原有逻辑（:176-200）不变 ...
}
```

### 8.3 `interceptDNS` — 不变（已有守卫 `:30-34`）。
### 8.4 `logAudit` — 不变（safe-by-accident）；可选加显式 v6 早退。

---

## 9. 向后兼容

- `Ipv6CIDR` 为空：不初始化 v6 池、不下发 `-IP6` 头、不调 `SetupGlobalNAT6`、TUN/TAP 仍 `disable_ipv6` → 纯 v4 行为字节级不变（§8 守卫对 v4 无影响）。
- 所有 v6 路径以 `Ipv6CIDR != ""` 为总开关。

---

## 10. 测试与回滚

- **单测**：`loopIpV6` 分配/回收/回卷；`pkg/ndpdis` NA 报文构造；守卫单测（v6 包经 `checkLinkAcl`/`restoreFakeIP` 不被误丢）；`ReleaseIp` 在 `Close()` 与 `NewConnSession` 两处早退路径均释放 v6（池不泄漏）；**MTU 下限**：`Ipv6CIDR!=""` 且 `Mtu<1280` 时被强制上调到 1280。
- **集成**：TUN 双栈（openconnect 连、分配 v6、ping6 网关+外网，NAT66 / 纯路由两模式）；TAP 双栈（含 NDP 代答）；macvtap 双栈；split v6 路由下发校验。
- **回归**：`Ipv6CIDR` 空 → 纯 v4 行为不变；v4 LinkAcl / FakeDNS 既有行为不变。
- **回滚**：`Ipv6CIDR` 缺省即纯 v4，开关级可控。

---

## 11. 工作量与里程碑

合计约 **1.5–2 周（单人）**。建议顺序（最低风险优先）：
- **M1 配置层 + IP 池 v6 + 外围守卫（§8）**：低风险、可单测、且正好覆盖两处强制守卫 → **首选起步**。
- **M2 隧道头 + TUN 数据面**。
- **M3 NAT/Firewall v6（§7，含 stateful FORWARD / 默认 NAT66）**。
- **M4 TAP/VTAP 数据面 + NDP 代答（§6）**。
- **M5 split 路由 CIDR（§1.3）+ 集成测试 + 回归**。

> 成本削减杠杆：若欲进一步压缩，可退为 **TUN-only**（去掉 M4 的 TAP/VTAP），但须在文档标注"TAP/macvtap 用户无 v6"。

---

## 12. 已知限制（v2 状态追踪）

> 下列条目为 v1 设计时的「v2 待办」。截至 `ipv6-v1` 分支，1–4 与 6 均已在 v2 落地（见 `docs/ipv6-dual-stack-future.md`），仅 5 为**本轮明确不做**。

- [x] ~~v6 精细 ACL 匹配（当前放行）~~ → 已完成：`checkLinkAcl` 复用 `LinkAcl` 的 `*net.IPNet`，ICMPv6 按 ICMP 处理。
- [x] ~~v6 FakeDNS / AAAA 解析 / v6 DNAT~~ → 已完成：v6 FakeIP 段固定 `2001:db8::/32`（RFC3849），`ResolveDomainAAAA` + `interceptDNS` AAAA 回 v6 fakeIP + 防火墙 v6 DNAT 靠 map 查表。
- [x] ~~v6 审计字段细化（当前不审计）~~ → 已完成：`AccessAudit.Src/Dst varchar(60)` 记录 v6 五元组。
- [x] ~~v6 DNS 拦截（当前不拦截，透传）~~ → 已完成：去掉 v6 早退，`interceptDNS` 接管 AAAA。
- [ ] 服务端 v6 接入监听（CSTP/DTLS over v6）—— **本轮明确不做**（DTLS 传输仍 v4 接入，`DTLS-Address-IP6` 仅信息性下发）。
- [x] ~~组级 v6 出网隔离~~ → 已完成：`Group.ClientCidr6` 字段 + `AddGroupNAT6` 接口，组池优先、回退全局 `Ipv6CIDR`。

### 12.1 本轮新增修复（MTU 下限）
- IPv6 要求链路 MTU ≥ 1280。原仅 `initIpPool` 强制**全局** `base.GetCfg().Mtu ≥ 1280`，但用户级 `user.Mtu` 覆盖（非 0）会绕过 `SetMtu`、且客户端显式请求低 MTU 也会被接受，导致 v6 PMTU 黑洞。已在两处补 1280 下限保护（`session.go` 会话创建处 + `SetMtu`），仅 v6 开启时生效，纯 v4 字节级不变。
