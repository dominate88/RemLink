package handler

import (
	"encoding/binary"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/songgao/water/waterutil"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/sessdata"
)

// DNS 拦截 - 返回 FakeIP 或透明转发
func interceptDNS(cSess *sessdata.ConnSession, pl *sessdata.Payload) bool {
	rp := cSess.Policy
	if cSess.FakeDNS == nil || !rp.EnableFakeDNS {
		return false
	}

	if pl.LType != sessdata.LTypeIPData || pl.PType != 0x00 {
		return false
	}

	if len(pl.Data) < 1 {
		return false
	}

	// 检查 IP 版本
	ipVersion := (pl.Data[0] & 0xF0) >> 4
	if ipVersion != 4 {
		return false // 不是 IPv4,静默丢弃
	}

	ipHeaderLen := int(pl.Data[0]&0x0F) * 4
	// 验证 IHL 值的合法性(5-15,对应 20-60 字节)
	if ipHeaderLen < 20 || ipHeaderLen > 60 {
		if ipHeaderLen != 0 {
			base.Debug("Invalid IP header length:", ipHeaderLen, "bytes, dropping")
		}
		return false
	}
	// 检查数据包是否包含完整的 IP 头 + UDP 头
	if len(pl.Data) < ipHeaderLen+8 {
		base.Debug("Packet too short:", len(pl.Data), "bytes, dropping")
		return false
	}

	ipProto := waterutil.IPv4Protocol(pl.Data)

	// 只处理 UDP 协议
	if ipProto != waterutil.UDP {
		return false
	}
	ipDst := waterutil.IPv4Destination(pl.Data)
	ipPort := waterutil.IPv4DestinationPort(pl.Data)

	// 判断是否是DNS请求
	if ipPort != 53 {
		return false
	}

	// 检查是否是配置的ClientDns服务器
	isDNSServer := false
	for _, dnsServer := range rp.ClientDns {
		if dnsServer.Val == ipDst.String() {
			isDNSServer = true
			break
		}
	}
	// 检查是否是 FakeDNS 上游服务器
	if !isDNSServer && rp.FakeDNSUpstream != "" {
		if rp.FakeDNSUpstream == ipDst.String() {
			isDNSServer = true
		}
	}

	if !isDNSServer {
		return false
	}

	// 提取 DNS 数据（IP头 + UDP头之后）
	dnsData := pl.Data[ipHeaderLen+8:]

	// 解析 DNS 请求
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsData); err != nil {
		base.Debug("Failed to parse DNS query:", err)
		return false
	}

	if len(msg.Question) == 0 {
		return false
	}

	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	qType := msg.Question[0].Qtype

	// 对命中 FakeDNS 规则的 AAAA 查询，返回空响应
	if qType == dns.TypeAAAA && shouldUseFakeIP(domain, rp) {
		resp := new(dns.Msg)
		resp.SetReply(msg)
		dnsResp, err := resp.Pack()
		if err == nil {
			respPacket := buildDNSResponsePacket(pl.Data, dnsResp)
			sendDNSResponse(cSess, respPacket)
			return true
		}
		return false
	}

	// 只处理 A 记录查询
	if qType != dns.TypeA {
		return false
	}

	// 检查是否需要返回 FakeIP
	if !shouldUseFakeIP(domain, rp) {
		base.Debug("Domain not matched FakeDNS rules, Not Intercepting:", domain)
		return false // 不拦截，正常转发
	}
	base.Debug("Intercepting DNS query for:", domain)

	// 分配 FakeIP
	fakeIP := cSess.FakeDNS.AcquireFakeIP(domain)
	if fakeIP == nil {
		base.Error("Failed to acquire FakeIP for:", domain)
		return false
	}

	base.Debug("Allocated FakeIP:", domain, "->", fakeIP.String())
	// 异步预解析并写入 NAT 规则
	cSess.FakeDNS.ResolveAndMapping(fakeIP.String(), domain, cSess.Policy.GetUpstreamDNS()+":53")

	// 构造 DNS 响应
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   msg.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: fakeIP,
	})

	dnsResp, err := resp.Pack()
	if err != nil {
		base.Error("Failed to pack DNS response:", err)
		return false
	}

	// 构造完整的响应包
	respPacket := buildDNSResponsePacket(pl.Data, dnsResp)

	// 发送响应包回客户端
	sendDNSResponse(cSess, respPacket)

	return true
}

// 还原 FakeIP 为真实域名并解析
func restoreFakeIP(cSess *sessdata.ConnSession, pl *sessdata.Payload) bool {
	rp := cSess.Policy
	if cSess.FakeDNS == nil || !rp.EnableFakeDNS {
		return false
	}

	// 连通优先：v6 包不做 FakeIP 还原（v6 FakeIP 留 v2），直接放行，避免误读 v6 头丢包
	if (pl.Data[0]&0xF0)>>4 != 4 {
		return false
	}

	ipDst := waterutil.IPv4Destination(pl.Data)
	if !cSess.FakeDNS.IsFakeIP(ipDst) {
		return false
	}

	fakeIPStr := ipDst.String()

	// 查 realIP、更新访问时间、判断是否需要刷新、取 domain
	realIP, domain, needRefresh := cSess.FakeDNS.LookupAndTouch(fakeIPStr)

	// 已有映射: 命中转发, 到期则异步换节点
	if realIP != "" {
		if needRefresh {
			cSess.FakeDNS.RenewMapping(fakeIPStr, domain, cSess.Policy.GetUpstreamDNS()+":53")
		}
		return false
	}

	// fakeIP 在池范围内但不在映射表中，是客户端缓存的旧 IP
	if domain == "" {
		base.Trace("FakeIP not in map (stale cache), dropping:", ipDst)
		return true
	}

	// 首次访问: 异步解析并写入 NAT 规则, 丢包让客户端 TCP 重传后恢复
	upstreamDNS := cSess.Policy.GetUpstreamDNS() + ":53"
	cSess.FakeDNS.ResolveAndMapping(fakeIPStr, domain, upstreamDNS)

	base.Debug("FakeIP mapping not ready, dropping packet, resolving async:", domain)
	return true
}

// 检查域名是否应该返回 FakeIP
func shouldUseFakeIP(domain string, p *dbdata.Policy) bool {
	domain = strings.ToLower(domain)

	// 有 include 规则：仅匹配 include 列表的域名返回 FakeIP
	if len(p.FakeDNSIncludeSet) > 0 {
		if len(p.FakeDNSExcludeSet) > 0 {
			base.Warn("FakeDNS: include and exclude both set, exclude will be ignored")
		}
		return matchDomainSet(domain, p.FakeDNSIncludeSet)
	}

	// 有 exclude 规则但没有 include：默认全部拦截，但排除 exclude 列表
	if len(p.FakeDNSExcludeSet) > 0 {
		return !matchDomainSet(domain, p.FakeDNSExcludeSet)
	}

	// 没有任何规则时不做拦截，避免误接管所有 DNS 流量
	return false
}

// 匹配域名集合
func matchDomainSet(domain string, set map[string]struct{}) bool {
	d := domain
	for {
		if _, ok := set[d]; ok {
			return true // 精确匹配或父域名匹配
		}
		idx := strings.IndexByte(d, '.')
		if idx < 0 {
			break
		}
		d = d[idx+1:] // 取子域名
	}
	return false
}

// 构建 DNS 响应包
func buildDNSResponsePacket(queryPacket []byte, dnsResp []byte) []byte {
	// 从原始查询包的 IHL 字段动态获取 IP 头长度
	ipHeaderLen := int(queryPacket[0]&0x0F) * 4
	udpHeaderLen := 8
	totalLen := ipHeaderLen + udpHeaderLen + len(dnsResp)

	respPacket := make([]byte, totalLen)

	// 复制并修改 IP 头
	copy(respPacket[:ipHeaderLen], queryPacket[:ipHeaderLen])

	// 交换源和目标IP
	copy(respPacket[12:16], queryPacket[16:20])
	copy(respPacket[16:20], queryPacket[12:16])

	binary.BigEndian.PutUint16(respPacket[2:4], uint16(totalLen))

	respPacket[10] = 0
	respPacket[11] = 0
	ipChecksum := calculateChecksum(respPacket[:ipHeaderLen])
	binary.BigEndian.PutUint16(respPacket[10:12], ipChecksum)

	copy(respPacket[ipHeaderLen:ipHeaderLen+udpHeaderLen], queryPacket[ipHeaderLen:ipHeaderLen+udpHeaderLen])

	// 交换源和目标端口
	copy(respPacket[ipHeaderLen:ipHeaderLen+2], queryPacket[ipHeaderLen+2:ipHeaderLen+4])
	copy(respPacket[ipHeaderLen+2:ipHeaderLen+4], queryPacket[ipHeaderLen:ipHeaderLen+2])

	udpLen := udpHeaderLen + len(dnsResp)
	binary.BigEndian.PutUint16(respPacket[ipHeaderLen+4:ipHeaderLen+6], uint16(udpLen))

	copy(respPacket[ipHeaderLen+udpHeaderLen:], dnsResp)

	respPacket[ipHeaderLen+6] = 0
	respPacket[ipHeaderLen+7] = 0

	return respPacket
}

func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// 发送 DNS 响应包到客户端
func sendDNSResponse(cSess *sessdata.ConnSession, respPacket []byte) {
	respPl := getPayload()
	respPl.LType = sessdata.LTypeIPData
	respPl.PType = 0x00
	copy(respPl.Data, respPacket)
	respPl.Data = respPl.Data[:len(respPacket)]

	dSess := cSess.GetDtlsSession()
	var ch chan *sessdata.Payload
	if dSess != nil {
		ch = cSess.PayloadOutDtls
	} else {
		ch = cSess.PayloadOutCstp
	}

	timer := time.NewTimer(1 * time.Second)
	defer timer.Stop()

	select {
	case ch <- respPl:
	case <-cSess.CloseChan:
		putPayload(respPl)
	case <-timer.C:
		putPayload(respPl)
		base.Debug("DNS response dropped: outbound channel full")
	}
}
