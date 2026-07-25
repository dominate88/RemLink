package handler

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/songgao/water/waterutil"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/sessdata"
)

// buildV6Packet 构造一个最小 IPv6 包：40 字节基础头 + payloadLen 字节负载。
// 负载的前 4 字节（若存在）用于放 TCP/UDP 的 src/dst 端口。
func buildV6Packet(nextHeader uint8, src, dst net.IP, payloadLen int) []byte {
	data := make([]byte, 40+payloadLen)
	data[0] = 0x60 // 版本=6
	data[6] = nextHeader
	copy(data[8:24], src.To16())
	copy(data[24:40], dst.To16())
	return data
}

func TestParseV6Header_TCP(t *testing.T) {
	dst := net.ParseIP("2001:db8::1")
	pkt := buildV6Packet(6, net.ParseIP("2001:db8::2"), dst, 20)
	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 443)

	info, ok := parseV6Header(pkt)
	if !ok {
		t.Fatal("expected ok for valid TCP packet")
	}
	if info.Proto != 6 {
		t.Errorf("proto = %d, want 6", info.Proto)
	}
	if !info.Dst.Equal(dst) {
		t.Errorf("dst = %v, want %v", info.Dst, dst)
	}
	if info.SrcPort != 12345 || info.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 12345/443", info.SrcPort, info.DstPort)
	}
}

func TestParseV6Header_UDP(t *testing.T) {
	pkt := buildV6Packet(17, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), 20)
	binary.BigEndian.PutUint16(pkt[40:42], 53)
	binary.BigEndian.PutUint16(pkt[42:44], 53)

	info, ok := parseV6Header(pkt)
	if !ok {
		t.Fatal("expected ok for valid UDP packet")
	}
	if info.Proto != 17 {
		t.Errorf("proto = %d, want 17", info.Proto)
	}
	if info.SrcPort != 53 || info.DstPort != 53 {
		t.Errorf("ports = %d/%d, want 53/53", info.SrcPort, info.DstPort)
	}
}

func TestParseV6Header_ICMPv6(t *testing.T) {
	pkt := buildV6Packet(58, net.ParseIP("fe80::1"), net.ParseIP("fe80::2"), 8)
	info, ok := parseV6Header(pkt)
	if !ok {
		t.Fatal("expected ok for valid ICMPv6 packet")
	}
	if info.Proto != 58 {
		t.Errorf("proto = %d, want 58 (ICMPv6)", info.Proto)
	}
	if info.SrcPort != 0 || info.DstPort != 0 {
		t.Errorf("ICMPv6 ports should be 0, got %d/%d", info.SrcPort, info.DstPort)
	}
}

func TestParseV6Header_WithHopByHop(t *testing.T) {
	// Hop-by-Hop(0) 扩展头：NextHeader=6(TCP) 在偏移 40，HdrExtLen=0 → 头长 8 字节
	pkt := make([]byte, 40+8+20)
	pkt[0] = 0x60
	pkt[6] = 0 // Hop-by-Hop
	pkt[40] = 6
	pkt[41] = 0 // Hdr Ext Len = 0
	binary.BigEndian.PutUint16(pkt[48:50], 1111)
	binary.BigEndian.PutUint16(pkt[50:52], 2222)

	info, ok := parseV6Header(pkt)
	if !ok {
		t.Fatal("expected ok for packet with Hop-by-Hop ext header")
	}
	if info.Proto != 6 {
		t.Errorf("proto = %d, want 6 (after skipping Hop-by-Hop)", info.Proto)
	}
	if info.SrcPort != 1111 || info.DstPort != 2222 {
		t.Errorf("ports = %d/%d, want 1111/2222", info.SrcPort, info.DstPort)
	}
}

func TestParseV6Header_WithFragment(t *testing.T) {
	// Fragment(44) 固定 8 字节，NextHeader 在扩展头首字节
	pkt := make([]byte, 40+8+20)
	pkt[0] = 0x60
	pkt[6] = 44 // Fragment
	pkt[40] = 6 // next header inside fragment header
	binary.BigEndian.PutUint16(pkt[48:50], 3333)
	binary.BigEndian.PutUint16(pkt[50:52], 4444)

	info, ok := parseV6Header(pkt)
	if !ok {
		t.Fatal("expected ok for packet with Fragment ext header")
	}
	if info.Proto != 6 {
		t.Errorf("proto = %d, want 6 (after skipping Fragment)", info.Proto)
	}
	if info.SrcPort != 3333 || info.DstPort != 4444 {
		t.Errorf("ports = %d/%d, want 3333/4444", info.SrcPort, info.DstPort)
	}
}

func TestParseV6Header_Malformed(t *testing.T) {
	// 长度不足 40
	if _, ok := parseV6Header(make([]byte, 20)); ok {
		t.Error("expected false for too-short packet")
	}
	// 版本非 6
	bad := make([]byte, 40)
	bad[0] = 0x40 // 版本=4
	if _, ok := parseV6Header(bad); ok {
		t.Error("expected false for non-v6 packet")
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", s, err)
	}
	return ipNet
}

func TestCheckLinkAcl_v6_NoRule(t *testing.T) {
	rp := &dbdata.Policy{LinkAcl: nil}
	pkt := buildV6Packet(6, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), 20)
	binary.BigEndian.PutUint16(pkt[42:44], 443)
	pl := &sessdata.Payload{LType: sessdata.LTypeIPData, PType: 0x00, Data: pkt}
	if !checkLinkAcl(rp, pl) {
		t.Error("expected allow when no ACL rule configured")
	}
}

func TestCheckLinkAcl_v6_Allow(t *testing.T) {
	rp := &dbdata.Policy{
		LinkAcl: []dbdata.GroupLinkAcl{
			{
				Action:   dbdata.Allow,
				Protocol: "tcp",
				IpProto:  waterutil.TCP,
				Val:      "2001:db8::/32",
				IpNet:    mustCIDR(t, "2001:db8::/32"),
				Ports:    map[uint16]int8{443: 1},
			},
		},
	}
	// 目的在 2001:db8::/32 且端口 443 → 放行
	pkt := buildV6Packet(6, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), 20)
	binary.BigEndian.PutUint16(pkt[42:44], 443)
	pl := &sessdata.Payload{LType: sessdata.LTypeIPData, PType: 0x00, Data: pkt}
	if !checkLinkAcl(rp, pl) {
		t.Error("expected allow for v6 dst in CIDR with matching port")
	}

	// 目的不在 CIDR（属于其他段）→ 默认拒绝
	pkt2 := buildV6Packet(6, net.ParseIP("2001:db9::2"), net.ParseIP("2001:db9::1"), 20)
	binary.BigEndian.PutUint16(pkt2[42:44], 443)
	pl2 := &sessdata.Payload{LType: sessdata.LTypeIPData, PType: 0x00, Data: pkt2}
	if checkLinkAcl(rp, pl2) {
		t.Error("expected deny for v6 dst outside CIDR")
	}
}

func TestCheckLinkAcl_v6_ICMP(t *testing.T) {
	// 一条 icmp allow 规则应同时放行 ping(ICMPv4) 与 ping6(ICMPv6)
	rp := &dbdata.Policy{
		LinkAcl: []dbdata.GroupLinkAcl{
			{
				Action:   dbdata.Allow,
				Protocol: "icmp",
				IpProto:  waterutil.ICMP,
				Val:      "2001:db8::/32",
				IpNet:    mustCIDR(t, "2001:db8::/32"),
			},
		},
	}
	pkt := buildV6Packet(58, net.ParseIP("2001:db8::2"), net.ParseIP("2001:db8::1"), 8)
	pl := &sessdata.Payload{LType: sessdata.LTypeIPData, PType: 0x00, Data: pkt}
	if !checkLinkAcl(rp, pl) {
		t.Error("expected allow for ICMPv6 matched by icmp allow rule")
	}
}

func TestCheckLinkAcl_v6_MalformedDeny(t *testing.T) {
	rp := &dbdata.Policy{
		LinkAcl: []dbdata.GroupLinkAcl{
			{Action: dbdata.Allow, Protocol: "tcp", IpProto: waterutil.TCP,
				Val: "2001:db8::/32", IpNet: mustCIDR(t, "2001:db8::/32")},
		},
	}
	// 畸形 v6 包（版本=6 但长度不足 40）→ 安全拒绝
	bad := make([]byte, 20)
	bad[0] = 0x60 // 版本=6
	pl := &sessdata.Payload{LType: sessdata.LTypeIPData, PType: 0x00, Data: bad}
	if checkLinkAcl(rp, pl) {
		t.Error("expected deny for malformed v6 packet (safe default)")
	}
}
