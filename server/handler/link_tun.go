package handler

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/wsczx/remlink/sessdata"
)

var groupNatCIDRs sync.Map

func checkTun() {
	// 测试ip命令
	base.CheckModOrLoad("tun")

	// 测试tun
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	ifce, err := water.New(cfg)
	if err != nil {
		base.Fatal("open tun err: ", err)
	}
	defer ifce.Close()

	link, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		base.Fatal("testTun err: ", err)
	}
	if err = netlink.LinkSetMTU(link, 1399); err != nil {
		base.Fatal("testTun err: ", err)
	}
	if err = netlink.LinkSetAllmulticastOff(link); err != nil {
		base.Fatal("testTun err: ", err)
	}
	if err = netlink.LinkSetUp(link); err != nil {
		base.Fatal("testTun err: ", err)
	}
	if base.GetCfg().GlobalNat {
		// 校验主网卡是否存在
		masterDev := base.GetCfg().Ipv4Master
		if _, err := netlink.LinkByName(masterDev); err != nil {
			ifaces := utils.GetPhysicalInterfaces()
			base.Warn("========================================")
			base.Warn("NAT 配置错误：主网卡未正确配置!")
			base.Warn("当前可用物理网卡: " + strings.Join(ifaces, ", "))
			base.Warn("NAT 转发规则将无法生效, 请在web后台更新配置")
			base.Warn("========================================")
		}

		fw := sessdata.GetFirewall()
		if fw == nil {
			base.Error("初始化防火墙失败: firewall is nil, 请检查防火墙后端配置")
			return
		}
		if _, ok := fw.(*sessdata.IPT); ok {
			base.CheckModOrLoad("iptable_filter")
			base.CheckModOrLoad("iptable_nat")
		}
		if err := fw.SetupGlobalNAT(base.GetCfg().Ipv4CIDR, base.GetCfg().Ipv4Master, base.InContainer); err != nil {
			base.Error("设置NAT转发失败:", err, ", 请在web后台更新配置后重启服务")
		}
	}
}

// 创建tun网卡
func LinkTun(cSess *sessdata.ConnSession) error {
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	ifce, err := water.New(cfg)
	if err != nil {
		base.Error(err)
		return err
	}
	cSess.SetIfName(ifce.Name())

	alias := utils.ParseName(cSess.Group.Name + "." + cSess.Username)
	link, err := netlink.LinkByName(ifce.Name())
	if err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}

	//	设置mtu
	if err = netlink.LinkSetMTU(link, cSess.Mtu); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 禁用广播
	if err = netlink.LinkSetAllmulticastOff(link); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	if err = netlink.LinkSetUp(link); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}
	// 设置 alias
	if err = netlink.LinkSetAlias(link, alias); err != nil {
		base.Warn("set alias err: ", err)
	}

	localIP := cSess.IpPool.Ipv4Gateway
	peerIP := cSess.IpAddr
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   localIP,
			Mask: net.CIDRMask(32, 32),
		},
		Peer: &net.IPNet{
			IP:   peerIP,
			Mask: net.CIDRMask(32, 32),
		},
	}
	if err = netlink.AddrAdd(link, addr); err != nil {
		base.Error(err)
		_ = ifce.Close()
		return err
	}

	// 设置组NAT
	setGroupNAT(cSess)
	err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifce.Name()), "1")
	if err != nil {
		base.Warn(err)
	}

	go tunRead(ifce, cSess)
	go tunWrite(ifce, cSess)
	return nil
}

func tunWrite(ifce *water.Interface, cSess *sessdata.ConnSession) {
	defer func() {
		base.Debug("LinkTun return", cSess.IpAddr)
		cSess.Close()
		_ = ifce.Close()
	}()

	var (
		err error
		pl  *sessdata.Payload
	)

	for {
		select {
		case pl = <-cSess.PayloadIn:
		case <-cSess.CloseChan:
			return
		}

		_, err = ifce.Write(pl.Data)
		if err != nil {
			base.Error("tun Write err", err)
			return
		}

		putPayloadInBefore(cSess, pl)
	}
}

func tunRead(ifce *water.Interface, cSess *sessdata.ConnSession) {
	defer func() {
		base.Debug("tunRead return", cSess.IpAddr)
		_ = ifce.Close()
	}()
	var (
		err error
		n   int
	)

	for {
		// data := make([]byte, BufferSize)
		pl := getPayload()
		n, err = ifce.Read(pl.Data)
		if err != nil {
			base.Error("tun Read err", n, err)
			return
		}

		// 更新数据长度
		pl.Data = (pl.Data)[:n]

		if payloadOut(cSess, pl) {
			return
		}
	}
}
func setGroupNAT(cSess *sessdata.ConnSession) {
	if cSess.IpPool == nil || cSess.IpPool.Ipv4IPNet == nil {
		return
	}
	// 回退到全局池则
	if cSess.IpPool == sessdata.IpPool {
		return
	}
	cidr := cSess.IpPool.Ipv4IPNet.String()
	// 已添加过则跳过
	if _, loaded := groupNatCIDRs.Load(cidr); loaded {
		return
	}

	fw := sessdata.GetFirewall()
	if fw == nil {
		return
	}
	if err := fw.AddGroupNAT(cidr, base.GetCfg().Ipv4Master, base.InContainer); err != nil {
		base.Warn("组", cSess.Group.Name, "设置NAT失败:", err)
		return // 允许下次连接重试
	}
	groupNatCIDRs.Store(cidr, true)
	base.Info("为组", cSess.Group.Name, "动态添加NAT规则:", cidr)
}
