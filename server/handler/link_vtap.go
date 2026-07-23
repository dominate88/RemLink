package handler

import (
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/vishvananda/netlink"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/wsczx/remlink/sessdata"
)

// link vtap
const vTapPrefix = "lvtap"

type Vtap struct {
	*os.File
	ifName string
}

func (v *Vtap) Close() error {
	v.File.Close()
	link, err := netlink.LinkByName(v.ifName)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func checkMacvtap() {
	// 加载 macvtap
	base.CheckModOrLoad("macvtap")

	_setGateway()
	_checkTapIp(base.GetCfg().Ipv4Master)

	ifName := "remlinkMacvtap"

	// 开启主网卡混杂模式
	masterLink, err := netlink.LinkByName(base.GetCfg().Ipv4Master)
	if err != nil {
		base.Fatal(err)
	}
	if err = netlink.SetPromiscOn(masterLink); err != nil {
		base.Fatal(err)
	}

	// 测试 macvtap 功能
	macvtap := &netlink.Macvtap{
		Macvlan: netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        ifName,
				ParentIndex: masterLink.Attrs().Index,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
	}
	if err = netlink.LinkAdd(macvtap); err != nil {
		base.Fatal(err)
	}

	testLink, err := netlink.LinkByName(ifName)
	if err != nil {
		base.Fatal(err)
	}
	if err = netlink.LinkDel(testLink); err != nil {
		base.Fatal(err)
	}
}

// 创建 Macvtap 网卡
func LinkMacvtap(cSess *sessdata.ConnSession) error {
	capL := sessdata.IpPool.IpLongMax - sessdata.IpPool.IpLongMin
	ipN := utils.Ip2long(cSess.IpAddr) % capL
	ifName := fmt.Sprintf("%s%d", vTapPrefix, ipN)

	cSess.SetIfName(ifName)

	alias := utils.ParseName(cSess.Group.Name + "." + cSess.Username)
	// 创建 macvtap 网卡
	masterLink, err := netlink.LinkByName(base.GetCfg().Ipv4Master)
	if err != nil {
		base.Error(err)
		return err
	}
	macvtap := &netlink.Macvtap{
		Macvlan: netlink.Macvlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        ifName,
				ParentIndex: masterLink.Attrs().Index,
				Alias:       alias,
			},
			Mode: netlink.MACVLAN_MODE_BRIDGE,
		},
	}
	if err = netlink.LinkAdd(macvtap); err != nil {
		base.Error(err)
		return err
	}
	//
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		base.Error(err)
		return err
	}
	if err = netlink.LinkSetMTU(link, cSess.Mtu); err != nil {
		base.Error(err)
		return err
	}
	// 设置 mac
	mac, err := net.ParseMAC(cSess.MacHw.String())
	if err != nil {
		base.Error(err)
		return err
	}
	if err = netlink.LinkSetHardwareAddr(link, mac); err != nil {
		base.Error(err)
		return err
	}
	// 启动网卡
	if err = netlink.LinkSetUp(link); err != nil {
		base.Error(err)
		return err
	}
	err = sysctlSet(fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6", ifName), "1")
	if err != nil {
		base.Warn(err)
	}

	return createVtap(cSess, ifName)
}

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func createVtap(cSess *sessdata.ConnSession, ifName string) error {
	// 初始化 ifName
	inf, err := net.InterfaceByName(ifName)
	if err != nil {
		base.Error(err)
		return err
	}

	tName := fmt.Sprintf("/dev/tap%d", inf.Index)

	var fdInt int

	fdInt, err = syscall.Open(tName, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}

	var flags uint16 = syscall.IFF_TAP | syscall.IFF_NO_PI
	var req ifReq
	req.Flags = flags

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fdInt),
		uintptr(syscall.TUNSETIFF),
		uintptr(unsafe.Pointer(&req)),
	)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}

	file := os.NewFile(uintptr(fdInt), tName)
	ifce := &Vtap{file, ifName}

	go allTapRead(ifce, cSess)
	go allTapWrite(ifce, cSess)
	return nil
}

// 销毁未关闭的vtap
func destroyVtap() {
	its, err := net.Interfaces()
	if err != nil {
		base.Error(err)
		return
	}
	for _, v := range its {
		if strings.HasPrefix(v.Name, vTapPrefix) {
			// 删除原来的网卡
			link, err := netlink.LinkByName(v.Name)
			if err != nil {
				base.Error(err)
				continue
			}
			netlink.LinkDel(link)
		}
	}
}
