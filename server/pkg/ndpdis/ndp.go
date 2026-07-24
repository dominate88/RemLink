package ndpdis

// IPv6 邻居发现(NDP)代答，与 arpdis 的 ARP 代答对应。
// 区别：客户端 v6 地址(/128)由服务端分配、会话期内静态，
// 会话建立时注册、关闭时删除即可，无需老化过期和主动探测。

import (
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	table   = make(map[string]net.HardwareAddr, 128)
	tableMu sync.RWMutex
)

func Add(ip net.IP, hw net.HardwareAddr) {
	if ip == nil || hw == nil {
		return
	}
	tableMu.Lock()
	defer tableMu.Unlock()
	table[ip.String()] = hw
}

func Delete(ip net.IP) {
	if ip == nil {
		return
	}
	tableMu.Lock()
	defer tableMu.Unlock()
	delete(table, ip.String())
}

func Lookup(ip net.IP) net.HardwareAddr {
	tableMu.RLock()
	defer tableMu.RUnlock()
	return table[ip.String()]
}

var serializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

// NewNAReply 构造邻居通告(NA)以太网帧，代答对客户端 v6 地址的邻居请求(NS)
func NewNAReply(targetIP net.IP, targetHw net.HardwareAddr, dstIP net.IP, dstHw net.HardwareAddr) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       targetHw,
		DstMAC:       dstHw,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		Version:    6,
		HopLimit:   255, // NDP 要求 HopLimit 必须为 255，否则接收方丢弃
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      targetIP.To16(),
		DstIP:      dstIP.To16(),
	}
	icmp := layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0),
	}
	if err := icmp.SetNetworkLayerForChecksum(&ip6); err != nil {
		return nil, err
	}
	na := layers.ICMPv6NeighborAdvertisement{
		Flags:         0x60, // Solicited + Override
		TargetAddress: targetIP.To16(),
		Options: layers.ICMPv6Options{
			{Type: layers.ICMPv6OptTargetAddress, Data: targetHw},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOpts, &eth, &ip6, &icmp, &na); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
