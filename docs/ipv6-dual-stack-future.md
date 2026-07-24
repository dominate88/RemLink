# RemLink IPv6 双栈 — 后续补齐计划（v2+）

> 配套文档：`ipv6-dual-stack-design.md`（v1 连通优先版定稿设计）。
> 本文汇总 v1 **有意不做**的项，给出 v2+ 的落地顺序、依赖与工作量。
> 关键前提：v1 数据面（配置 → IP 池 → 隧道头 → TUN/TAP/VTAP → NAT66/stateful FORWARD）已为这些项预留插入点，**补回时无需返工数据面**，全部可增量插入。

---

## 0. 背景与原则

- v1 已交付"双栈能通"，但 v6 侧**无策略**：ACL 放行、审计不记、FakeDNS AAAA 回空、DNS 透传。
- 这些被砍项（原方案 Q1「完整 v6 策略」）彼此**独立**，可单独立项、按需增量，不受实现顺序约束。
- 决策的"天花板"未变：v1 传输层仍是 v4 接入，故无论补多少 v6 策略，**纯 v6 客户端仍连不上**（见 §3.1）。

### 0.1 横向技术约束（v1 代码评审补强）

以下问题在多个 v2 项中**反复出现**，集中说明以避免各节重复踩坑：

- **waterutil 无 IPv6 helper**：`songgao/water/waterutil` 只有 `IPv4*`（如 `IPv4Destination/Source/Protocol/Port`，见 `payload.go:85-87`、`payload_access_audit.go:125-146`），全仓库零 `IPv6*` 匹配。所有 v6 解析**不能复用 waterutil**，只能手写或改用 `google/gopacket`（已在依赖，arpdis/link_tap 使用，可零成本复用）。
- **v6 头解析比 v4 复杂（扩展头）**：v6 基础头固定 40 字节，但源/目的地址各 16 字节、端口在 TCP/UDP 内；若报文带扩展头（Next Header 编号 0/43/44/50/51/59/60/135 等），必须**逐跳跳过**才能定位上层端口。这是 v6 比 v4 难的核心，易错。→ **建议抽一个共享 v6 头解析 helper**（见 §1.1 注①），`checkLinkAcl`/`logAudit`/`restoreFakeIP`-v6/`allTapWrite`/`allTapRead` 共用，避免 N 份重复逻辑。
- **前端 CIDR 校验 IPv4-only（硬依赖）**：`web/src/pages/policy/List.vue:674` 的 `isValidCIDR` 正则死写 IPv4，v6 必被拒。§1.1（v6 ACL）与设计文档 §1.3（split v6 路由）落地前**必须让前端校验支持 v6**，否则后端支持、前端存不进。
- **parseIpNet 对 v6 的格式坑**：`group.go:351-361` 的 `ipMask = fmt.Sprintf("%s/%s", ip, mask)` 对 v6 产出 `2001:db8::/ffff:ffff:…` 怪格式。**匹配用 `ipNet`（`*net.IPNet`）不受影响；但凡当字符串下发（如 split 路由 `X-CSTP-Split-Include-IP6`）必须用 `ipNet.String()`（CIDR）**——这是设计文档 §1.3 的 v1 修正项，§1.1 复用 split 前须确认其已在 v1 完成。

---

## 1. v2 候选 — 策略补全（对应被砍的 Q1）

### 1.1 v6 精细 ACL 匹配
- **现状**：v1 `checkLinkAcl`（`payload.go:79`）对 v6 直接 `return true`（放行，连通优先）。
- **目标**：v6 流量过目的地址/端口级二次过滤，与 v4 `LinkAcl` 同机制。
- **改动**：
  - `checkLinkAcl` 加 v6 分支：解析 v6 头取源/目的地址 + 下一头 + （跳过扩展头后）TCP/UDP 端口。
  - **⚠️ waterutil 无 IPv6 helper**（见 §0.1）：v6 分支**不能复用 waterutil**，两种实现路径：
    - **A. 手写 v6 头解析**：固定 40 字节基础头（源/目的各 16 字节、Next Header 偏移 6、payload 偏移 40），但**扩展头必须逐跳跳过**才能定位端口——易错（§0.1）。
    - **B. 复用 `google/gopacket`**（`layers.IPv6` + `layers.TCP/UDP` 自动处理扩展头链）：正确性高、代码量小。**推荐 B**。
  - `dbdata.Policy` 需支持 v6 规则条目（新增 `LinkAcl6` 或让 `LinkAcl` 兼容 CIDR v6）；ACL 匹配走 `parseIpNet` 返回的 `ipNet`（`*net.IPNet` 原生支持 v6），**不**踩 IpMask 格式坑。
  - 前端策略配置增加 v6 条目 UI，**且必须同步修 `isValidCIDR`**（见下硬依赖）。
- **⚠️ 硬依赖 — 前端 CIDR 校验 IPv4-only**（§0.1）：`List.vue:674` 的 `isValidCIDR` 会把 v6 判非法，ACL 与 split 路由编辑都走它。→ 落地前**必须先让前端校验支持 v6**（或新增 `isValidCIDRv6` 分流），否则后端支持、前端存不进。
- **注① 解析器应抽共享 helper**：v6 扩展头跳过逻辑在 `checkLinkAcl`/`logAudit`/`restoreFakeIP`-v6/`allTapWrite`/`allTapRead` 多处都要用，建议抽成单一 `parseV6Header` helper（见 §0.1），避免重复且易错的代码。
- **注② 不踩 parseIpNet 格式坑**：ACL 匹配只用 `ipNet` 不受影响；但若 §1.1 复用任何 v6 网段**字符串下发**，须用 `ipNet.String()`（CIDR）——前提是设计文档 §1.3（split v6 CIDR）已在 v1 完成，否则会踩同一坑。
- **依赖**：无后端依赖；但**前端校验**与**设计文档 §1.3（split v6 CIDR）** 是其前置硬条件。
- **风险/工作量**：原估"低"偏乐观——v6 扩展头解析比 v4 复杂，且牵出前端校验改造。**上调为「中」**。
- **解锁**：v6 流量抵达内网前的精确管控（当前是"过路由即全放"）。

### 1.2 v6 FakeDNS（AAAA 解析 + v6 fakeIP + v6 DNAT）
- **现状**：v1 AAAA 查询被回空（`dns_intercept.go:100-111`），命中 FakeDNS 的域名只能走 v4；不做 v6 fakeIP。
- **目标**：命中 FakeDNS 规则的域名返回 v6 fakeIP，服务端做 v6 DNAT 还原。
- **改动**：
  - 配置层新增 `FakeDNSv6Range`（`fd00::/64` 段，可配；类比 v4 fakeIP 段）。
  - `restoreFakeIP`（`dns_intercept.go:165`）加 v6 分支（当前已守卫 `return false`，改为走 v6 还原）。
  - `allTapWrite` / `allTapRead`（§6 数据面）增加 v6 DNAT 路径。
  - DNS 拦截层支持 AAAA 报文解析与 fakeIP 注入。
- **依赖**：与 1.4 同批最佳；独立于 1.1/1.3。**工作量中**。
- **解锁**：开了 FakeDNS 的组，双栈对这批域名"不再假"（v1 下这批域名 AAAA 被清空）。

### 1.3 v6 审计字段细化
- **现状**：v1 `logAudit`（`payload_access_audit.go:125-155`）safe-by-accident 不审计 v6（`IPv4Protocol` 误读 v6 第 9 字节 = Hop Limit → `default: return`，外层 `recover()` 兜底）。
- **目标**：v6 包记录源/目的/协议/端口，与 v4 审计同口径。
- **改动**：
  - `logAudit` 加 v6 解析分支（`pl.Data[0]>>4 == 6`）：取源/目的地址 + 协议 + （跳过扩展头后）目的端口，填 `ipSrc.String()`/`ipDst.String()`。建议复用 §1.1 注① 的共享 v6 头解析 helper。
  - **存储侧几乎零改动（原估高估，应下调）**：`AccessAudit.Src/Dst` 是 `varchar(60)`（`tables.go:91,93`），IPv6 文本最长 45 字符，直接放得下，**无需新列或长文本改造**；去重 key 已是 `16 字节源 + 16 字节目的` 布局（`payload_access_audit.go:148-151` 的 `copy(key[:16],…)` / `copy(key[16:32],…)`），**本身 v6 就绪**。所以 §1.3 真正工作量只在"加 v6 解析分支"，存储/去重不动。
- **依赖**：与 §1.1 共享 v6 头解析 helper（建议同批）。
- **风险/工作量**：**存储侧为「极低」**；解析侧与 §1.1 同源（扩展头复杂度），但因可复用共享 helper，**整体仍为「低–中」**，比原描述更省。
- **解锁**：合规/审计对 v6 流量的可见性。

### 1.4 v6 DNS 拦截
- **现状**：v1 v6 DNS 包透传真实 DNS（`interceptDNS` 已守卫 `ipVersion != 4 → return false`）。
- **目标**：若需对 v6 DNS 做拦截/改写（如广告/域名策略）。
- **改动**：`interceptDNS` 去 v6 早退，加 v6 DNS 报文解析与拦截逻辑。
- **依赖**：通常与 1.2 同批。**低优先**。

---

## 2. v2 候选 — 配置 / 数据面扩展

### 2.1 组级 v6 出网隔离
- **现状**：v1 单全局 `Ipv6CIDR` 池，`SetupGlobalNAT6` 以全局段作 source；`AddGroupNAT6` 延后（见设计文档 §7 闭环说明）。
- **目标**：每组独立 v6 CIDR，分别 NAT/路由出网（对标 v4 的 per-group `ClientCidr` + `AddGroupNAT`）。
- **改动**：
  - `dbdata.Group` 结构体新增 `ClientCidr6` 字段（含 DB 迁移）。
  - IP 池支持多 CIDR（每池一个 v6 段，或全局池按组切片）。
  - `Firewall` 接口加 `AddGroupNAT6(groupCIDR6, masterDev, inContainer, useNat66)`（`SetupGlobalNAT6` 的按组版）。
  - 前端组配置增加 v6 段输入与校验。
- **依赖**：无（独立于 1.x）。**工作量中**。
- **解锁**：多租户/多组 v6 出网隔离，避免所有组共用一段 v6 出网。

---

## 3. v3 前瞻 — 本轮明确不做

### 3.1 服务端 v6 接入监听（CSTP / DTLS over v6）
- **现状**：v1 传输层仍 v4 接入（设计文档 §0 锁定；`X-DTLS-Address-IP6` 仅信息性下发，DTLS 仍 v4）。
- **目标**：服务端在 v6 上监听 CSTP(443)/DTLS，解决 **B4「仅 v6 客户端也能连」**。
- **改动**：
  - 监听栈双栈化（CSTP HTTPS + DTLS UDP 同时绑 v4/v6）。
  - DTLS 传输层支持 v6（注意 `pion/dtls` v2/v3 约束：当前锁 v2.2.12，v3 会让 AnyConnect5 会话恢复静默失败）。
  - 客户端接入配置下发 v6 地址，并处理 v4/v6 接入优选与回退。
- **依赖**：DTLS 传输栈改造，工作量大；与 v1 数据面解耦但独立成项目。**工作量：大**。
- **解锁**：这是唯一能让"纯 v6 客户端"接入的能力——是 v6 双栈从"增值项"变"刚需"的前提。无此项则 v6 双栈始终只服务"已建 v4 隧道内的 v6 流量"。

---

## 4. 优先级与排期建议

| 项 | 业务驱动力 | 依赖 | 工作量 | 建议档位 |
|---|---|---|---|---|
| 1.1 v6 ACL | 内网 v6 资源要精细管控 | 前端校验+v1§1.3+共享v6解析helper | 中（原估低偏乐观） | v2 首选 |
| 1.3 v6 审计 | 合规要 v6 流量可见 | 与 1.1 共享 helper | 低–中（存储侧极低） | v2 |
| 1.2 v6 FakeDNS | 开了 FakeDNS 的组要真双栈 | 1.4 同批 | 中 | v2 |
| 1.4 v6 DNS 拦截 | 域名策略要覆盖 v6 | 1.2 | 低 | v2（随 1.2） |
| 2.1 组级 v6 隔离 | 多租户 v6 出网隔离 | 无 | 中 | v2（独立立项） |
| 3.1 v6 接入监听 | 纯 v6 客户端要接入 | DTLS 栈 | 大 | v3 前瞻 |

**共同点**：v1 数据面已铺好，上述全部为策略层/配置层增量，不返工数据面。

**排期原则**：
- 先按业务驱动排，不强制捆绑。
- 1.1 / 1.3 风险最低、零依赖，可随时独立插入。
- 1.2 + 1.4 同批（都动 DNS 拦截与 DNAT）。
- 2.1 独立（动 Group 结构与池模型），不与 1.x 冲突。
- 3.1 单独成项目，仅在"确有纯 v6 客户端接入需求"时启动。
