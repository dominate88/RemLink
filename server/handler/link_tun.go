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
		masterDev := base.GetCfg().MasterDev
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
		if err := fw.SetupGlobalNAT(base.GetCfg().Ipv4CIDR, base.GetCfg().MasterDev, base.InContainer); err != nil {
			base.Error("设置NAT转发失败:", err, ", 请在web后台更新配置后重启服务")
		}
		// IPv6 双栈：始终下发 stateful FORWARD；GlobalNat 开时追加 NAT66（MASQUERADE 带 conntrack，安全基线）
		if base.GetCfg().Ipv6CIDR != "" {
			if err := fw.SetupGlobalNAT6(base.GetCfg().Ipv6CIDR, base.GetCfg().MasterDev, base.InContainer, base.GetCfg().GlobalNat); err != nil {
				base.Error("设置 IPv6 NAT/转发失败:", err, ", 请在web后台更新配置后重启服务")
			}
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

	// IPv6 双栈：客户端 /128，网关 /128（点对点）；v6 地址池为全局单池，网关取全局池
	if cSess.IpAddr6 != nil {
		// 部分环境（容器/默认 sysctl）新接口继承 disable_ipv6=1，必须先启用，
		// 否则给 TUN 加 v6 地址会返回 EACCES（permission denied）
		if err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifce.Name()), "0"); err != nil {
			base.Warn("enable ipv6 on tun failed: ", err)
		}
		// 显式开启该 TUN 接口的 IPv6 转发（新建接口从 default.forwarding 继承，可能仍为 0，导致 v6 转发不生效）
		if err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifce.Name()), "1"); err != nil {
			base.Warn("enable ipv6 forwarding on tun failed: ", err)
		}
		v6Addr := &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   cSess.IpPool.V6Gateway(),
				Mask: net.CIDRMask(128, 128),
			},
			Peer: &net.IPNet{
				IP:   cSess.IpAddr6,
				Mask: net.CIDRMask(128, 128),
			},
		}
		if err = netlink.AddrAdd(link, v6Addr); err != nil {
			base.Error(err)
			_ = ifce.Close()
			return err
		}
	}

	// 设置组NAT
	setGroupNAT(cSess)
	// 仅纯 v4 时禁用 TUN 接口的 IPv6，避免无地址的 v6 流量；启用 v6 双栈时不禁用
	if cSess.IpAddr6 == nil {
		if err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifce.Name()), "1"); err != nil {
			base.Warn(err)
		}
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
	fw := sessdata.GetFirewall()
	if fw == nil {
		return
	}

	cidr := cSess.IpPool.Ipv4IPNet.String()
	// 已添加过则跳过（失败不 Store，允许下次连接重试）
	if _, loaded := groupNatCIDRs.Load(cidr); !loaded {
		if err := fw.AddGroupNAT(cidr, base.GetCfg().MasterDev, base.InContainer); err != nil {
			base.Warn("组", cSess.Group.Name, "设置NAT失败:", err)
		} else {
			groupNatCIDRs.Store(cidr, true)
			base.Info("为组", cSess.Group.Name, "动态添加NAT规则:", cidr)
		}
	}

	// 组配置了独立 v6 段时按组下发 NAT66/stateful FORWARD
	if cSess.IpPool.Ipv6IPNet != nil {
		cidr6 := cSess.IpPool.Ipv6IPNet.String()
		if _, loaded := groupNatCIDRs.Load(cidr6); !loaded {
			if err := fw.AddGroupNAT6(cidr6, base.GetCfg().MasterDev, base.InContainer, base.GetCfg().GlobalNat); err != nil {
				base.Warn("组", cSess.Group.Name, "设置 IPv6 NAT 失败:", err)
			} else {
				groupNatCIDRs.Store(cidr6, true)
				base.Info("为组", cSess.Group.Name, "动态添加 IPv6 NAT 规则:", cidr6)
			}
		}
	}
}
