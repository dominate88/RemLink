package handler

import (
	"fmt"
	"io"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/vishvananda/netlink"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/pkg/arpdis"
	"github.com/wsczx/remlink/sessdata"
)

const bridgeName = "remlink0"

var (
	// 网关mac地址
	gatewayHw net.HardwareAddr
)

type LinkDriver interface {
	io.ReadWriteCloser
	Name() string
}

func _setGateway() {
	dstAddr := arpdis.Lookup(sessdata.IpPool.Ipv4Gateway, false)
	gatewayHw = dstAddr.HardwareAddr
	// 设置为静态地址映射
	dstAddr.Type = arpdis.TypeStatic
	arpdis.Add(dstAddr)
}

func _checkTapIp(ifName string) {
	iFace, err := net.InterfaceByName(ifName)
	if err != nil {
		base.Fatal("testTap err: ", err)
	}

	var ifIp net.IP

	addrs, err := iFace.Addrs()
	if err != nil {
		base.Fatal("testTap err: ", err)
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.To4() == nil {
			continue
		}
		ifIp = ip
	}

	if !sessdata.IpPool.Ipv4IPNet.Contains(ifIp) {
		base.Fatal("tapIp or Ip network err")
	}
}

func checkTap() {
	_setGateway()
	_checkTapIp(bridgeName)
}

// 创建tap网卡
func LinkTap(cSess *sessdata.ConnSession) error {
	cfg := water.Config{
		DeviceType: water.TAP,
	}

	ifce, err := water.New(cfg)
	if err != nil {
		base.Error(err)
		return err
	}

	cSess.SetIfName(ifce.Name())

	link, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 设置mtu
	if err = netlink.LinkSetMTU(link, cSess.Mtu); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 设置多播
	if err = netlink.LinkSetAllmulticastOn(link); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 设置名字
	if err = netlink.LinkSetUp(link); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 设置网卡
	if err = netlink.LinkSetMaster(link, bridge); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}

	err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifce.Name()), "1")
	if err != nil {
		base.Warn(err)
	}

	go allTapRead(ifce, cSess)
	go allTapWrite(ifce, cSess)
	return nil
}

func allTapWrite(ifce LinkDriver, cSess *sessdata.ConnSession) {
	defer func() {
		base.Debug("LinkTap return", cSess.IpAddr)
		cSess.Close()
		ifce.Close()
	}()

	var (
		err   error
		dstHw net.HardwareAddr
		pl    *sessdata.Payload
		frame = make(ethernet.Frame, BufferSize)
		ipDst = net.IPv4(1, 2, 3, 4)
	)

	for {
		frame.Resize(BufferSize)

		select {
		case pl = <-cSess.PayloadIn:
		case <-cSess.CloseChan:
			return
		}

		switch pl.LType {
		default:
		case sessdata.LTypeEthernet:
			copy(frame, pl.Data)
			frame = frame[:len(pl.Data)]

		case sessdata.LTypeIPData: // 需要转换成 Ethernet 数据
			ipSrc := waterutil.IPv4Source(pl.Data)
			if !ipSrc.Equal(cSess.IpAddr) {
				// 非分配给客户端ip，直接丢弃
				continue
			}

			if waterutil.IsIPv6(pl.Data) {
				// 过滤掉IPv6的数据
				continue
			}

			// 手动设置ipv4地址
			ipDst[12] = pl.Data[16]
			ipDst[13] = pl.Data[17]
			ipDst[14] = pl.Data[18]
			ipDst[15] = pl.Data[19]

			dstHw = gatewayHw
			if sessdata.IpPool.Ipv4IPNet.Contains(ipDst) {
				dstAddr := arpdis.Lookup(ipDst, true)
				if dstAddr != nil {
					dstHw = dstAddr.HardwareAddr
				}
			}

			frame.Prepare(dstHw, cSess.MacHw, ethernet.NotTagged, ethernet.IPv4, len(pl.Data))
			copy(frame[12+2:], pl.Data)
		}

		_, err = ifce.Write(frame)
		if err != nil {
			base.Error("tap Write err", err)
			return
		}

		putPayloadInBefore(cSess, pl)
	}
}

func allTapRead(ifce LinkDriver, cSess *sessdata.ConnSession) {
	defer func() {
		base.Debug("tapRead return", cSess.IpAddr)
		ifce.Close()
	}()

	var (
		err   error
		n     int
		data  []byte
		frame = make(ethernet.Frame, BufferSize)
	)

	for {
		frame.Resize(BufferSize)

		n, err = ifce.Read(frame)
		if err != nil {
			base.Error("tap Read err", n, err)
			return
		}
		frame = frame[:n]

		switch frame.Ethertype() {
		default:
			continue
		case ethernet.IPv6:
			continue
		case ethernet.IPv4:
			// 发送IP数据
			data = frame.Payload()

			ip_dst := waterutil.IPv4Destination(data)
			if !ip_dst.Equal(cSess.IpAddr) {
				// 过滤非本机地址
				continue
			}

			pl := getPayload()
			// 拷贝数据到pl
			copy(pl.Data, data)
			// 更新切片长度
			pl.Data = pl.Data[:len(data)]
			if payloadOut(cSess, pl) {
				return
			}

		case ethernet.ARP:
			// 暂时仅实现了ARP协议
			packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.NoCopy)
			layer := packet.Layer(layers.LayerTypeARP)
			arpReq := layer.(*layers.ARP)

			if !cSess.IpAddr.Equal(arpReq.DstProtAddress) {
				// 过滤非本机地址
				continue
			}

			// 返回ARP数据
			src := &arpdis.Addr{IP: cSess.IpAddr, HardwareAddr: cSess.MacHw}
			dst := &arpdis.Addr{IP: arpReq.SourceProtAddress, HardwareAddr: arpReq.SourceHwAddress}
			data, err = arpdis.NewARPReply(src, dst)
			if err != nil {
				base.Error(err)
				return
			}

			// 从接受的arp信息添加arp地址
			addr := &arpdis.Addr{
				IP:           append([]byte{}, dst.IP...),
				HardwareAddr: append([]byte{}, dst.HardwareAddr...),
			}
			arpdis.Add(addr)

			pl := getPayload()
			// 设置为二层数据类型
			pl.LType = sessdata.LTypeEthernet
			// 拷贝数据到pl
			copy(pl.Data, data)
			// 更新切片长度
			pl.Data = pl.Data[:len(data)]

			if payloadIn(cSess, pl) {
				return
			}

		}
	}
}
