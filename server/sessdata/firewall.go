package sessdata

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/wsczx/remlink/base"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

const (
	nftGlobalNatTable   = "REMLINK_GLOBAL_NAT"
	nftPostRoutingChain = "REMLINK_GLOBAL_NAT_POSTROUTING"
	nftForwardChain     = "REMLINK_GLOBAL_NAT_FORWARD"

	nftTableName             = "REMLINK_FAKEIP"
	nftDnatMapName           = "REMLINK_FAKEIP_DNATMAP"
	nftFakeIPPreRoutingChain = "REMLINK_FAKEIP_PREROUTING"

	iptDnatChain = "REMLINK_FAKEIP_DNAT"
)

// 防火墙后端接口
type Firewall interface {
	CreateChains(vpnCIDR, fakeIPRange string) error                   // 创建自定义链
	AddNatRule(fakeIP, realIP string) error                           // 添加 DNAT 规则（回包由 conntrack 自动反向）
	DelNatRule(fakeIP, realIP string) error                           // 删除 DNAT 规则
	SetupGlobalNAT(vpnCIDR, masterDev string, inContainer bool) error // 设置全局 NAT 规则
	AddGroupNAT(groupCIDR, masterDev string, inContainer bool) error  // 为组自定义 CIDR 添加 NAT 规则
	CleanupFakeIP() error                                             // 清理所有fakeIP规则
	CleanupGlobal() error                                             // 清理全局NAT规则
}

// 全局单例
var (
	GlobalFirewall     Firewall
	GlobalFirewallMu   sync.Mutex
	GlobalFirewallDone bool
)

// 获取全局防火墙单例（初始化失败时允许重试）
func GetFirewall() Firewall {
	GlobalFirewallMu.Lock()
	defer GlobalFirewallMu.Unlock()

	if GlobalFirewallDone {
		return GlobalFirewall
	}

	fw, err := newFirewall()
	if err != nil {
		base.Error("Failed to initialize firewall:", err)
		return nil
	}
	GlobalFirewall = fw
	GlobalFirewallDone = true
	return GlobalFirewall
}
func newFirewall() (Firewall, error) {
	cfg := base.GetCfg()
	driver := cfg.FirewallDriver
	if driver == "" {
		driver = "auto"
	}

	switch driver {
	case "iptables":
		ipt, err := NewIPT()
		if err != nil {
			return nil, fmt.Errorf("iptables initialization failed:%v", err)
		}
		base.Info("Firewall driver: using iptables")
		return ipt, nil

	case "nftables":
		nft, err := NewNFT()
		if err != nil {
			return nil, fmt.Errorf("nftables initialization failed: %v", err)
		}
		if err = nft.Probe(); err != nil {
			return nil, fmt.Errorf("nftables Probe failed: %v", err)
		}
		base.Info("Firewall driver: using nftables")
		return nft, nil

	default: // "auto"
		nft, err := NewNFT()
		if err == nil {
			if err = nft.Probe(); err == nil {
				base.Info("Firewall driver: using nftables")
				return nft, nil
			}
			base.Error("nftables initialization failed, falling back to iptables:", err)
		} else {
			base.Error("nftables not available, falling back to iptables:", err)
		}

		ipt, err := NewIPT()
		if err != nil {
			return nil, fmt.Errorf("no supported firewall driver found (iptables error: %v)", err)
		}
		base.Info("Firewall driver: using iptables")
		return ipt, nil
	}
}

// iptables 实现
type IPT struct {
	ipt *iptables.IPTables
}

func NewIPT() (*IPT, error) {
	ipt, err := iptables.New()
	if err != nil {
		return nil, err
	}
	return &IPT{ipt: ipt}, nil
}
func (i *IPT) SetupGlobalNAT(vpnCIDR, masterDev string, inContainer bool) error {
	// MASQUERADE 规则
	natRule := []string{"-s", vpnCIDR, "-o", masterDev, "-j", "MASQUERADE"}
	if !inContainer {
		// 添加注释
		natRule = append(natRule, "-m", "comment", "--comment", "RemLink")
	}
	if err := i.ipt.InsertUnique("nat", "POSTROUTING", 1, natRule...); err != nil {
		return err
	}

	// FORWARD 规则
	forwardRule := []string{"-j", "ACCEPT"}
	if !inContainer {
		// 添加注释
		forwardRule = append(forwardRule, "-m", "comment", "--comment", "RemLink")
	}
	return i.ipt.InsertUnique("filter", "FORWARD", 1, forwardRule...)
}
func (i *IPT) AddGroupNAT(groupCIDR, masterDev string, inContainer bool) error {
	// 组自定义 CIDR 添加 MASQUERADE 规则
	natRule := []string{"-s", groupCIDR, "-o", masterDev, "-j", "MASQUERADE"}
	if !inContainer {
		natRule = append(natRule, "-m", "comment", "--comment", "RemLink")
	}
	return i.ipt.InsertUnique("nat", "POSTROUTING", 1, natRule...)
}

func (i *IPT) CreateChains(vpnCIDR, fakeIPRange string) error {
	// 创建 DNAT 自定义链
	err := i.ipt.NewChain("nat", iptDnatChain)
	if err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return fmt.Errorf("failed to create DNAT chain: %v", err)
	}

	// 在 PREROUTING 链中添加跳转规则
	dnatJumpRule := []string{"-s", vpnCIDR, "-d", fakeIPRange, "-j", iptDnatChain}
	err = i.ipt.AppendUnique("nat", "PREROUTING", dnatJumpRule...)
	if err != nil {
		return fmt.Errorf("failed to add DNAT jump rule: %v", err)
	}

	base.Info("Created FakeIP iptables chains")
	return nil
}

func (i *IPT) AddNatRule(fakeIP, realIP string) error {
	dnatrule := []string{"-d", fakeIP, "-j", "DNAT", "--to-destination", realIP}
	return i.ipt.AppendUnique("nat", iptDnatChain, dnatrule...)
}

func (i *IPT) DelNatRule(fakeIP, realIP string) error {
	dnatRule := []string{"-d", fakeIP, "-j", "DNAT", "--to-destination", realIP}
	return i.ipt.Delete("nat", iptDnatChain, dnatRule...)
}

func (i *IPT) CleanupFakeIP() error {
	// 获取所有 PREROUTING 规则
	rules, _ := i.ipt.List("nat", "PREROUTING")
	for _, rule := range rules {
		if strings.Contains(rule, iptDnatChain) {
			parts := strings.Fields(rule)
			if len(parts) > 2 {
				i.ipt.Delete("nat", "PREROUTING", parts[2:]...)
			}
		}
	}

	// 清空并删除 DNAT 链
	i.ipt.ClearChain("nat", iptDnatChain)
	i.ipt.DeleteChain("nat", iptDnatChain)

	return nil
}
func (i *IPT) CleanupGlobal() error {
	// 清理 全局 NAT 规则
	// 删除 nat 表 POSTROUTING 中的 MASQUERADE 规则
	natRules, _ := i.ipt.List("nat", "POSTROUTING")
	for _, rule := range natRules {
		if strings.Contains(rule, "RemLink") {
			parts := strings.Fields(rule)
			if len(parts) > 2 {
				i.ipt.Delete("nat", "POSTROUTING", parts[2:]...)
			}
		}
	}

	// 删除 filter 表 FORWARD 中的 RemLink ACCEPT 规则
	fwdRules, _ := i.ipt.List("filter", "FORWARD")
	for _, rule := range fwdRules {
		if strings.Contains(rule, "RemLink") {
			parts := strings.Fields(rule)
			if len(parts) > 2 {
				i.ipt.Delete("filter", "FORWARD", parts[2:]...)
			}
		}
	}
	return nil
}

// nftables 实现
type NFT struct {
	mu    sync.Mutex
	conn  *nftables.Conn
	table *nftables.Table
}

func NewNFT() (*NFT, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %v", err)
	}
	return &NFT{conn: c}, nil
}
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name)
	return b
}

// 设置全局NAT规则，IP伪装(MASQUERADE)和转发(FORWARD)规则
func (n *NFT) SetupGlobalNAT(vpnCIDR, masterDev string, inContainer bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 创建全局NAT表
	globalNatTable := n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftGlobalNatTable,
	})

	_, ipNet, err := net.ParseCIDR(vpnCIDR)
	if err != nil {
		return fmt.Errorf("invalid vpnCIDR: %v", err)
	}
	ones, _ := ipNet.Mask.Size()
	prefixMask := net.CIDRMask(ones, 32)

	// POSTROUTING: MASQUERADE
	postrouting := n.conn.AddChain(&nftables.Chain{
		Name:     nftPostRoutingChain,
		Table:    globalNatTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	n.conn.AddRule(&nftables.Rule{
		Table: globalNatTable,
		Chain: postrouting,
		Exprs: n.MasqueradeExprs(ipNet, prefixMask, masterDev),
	})

	// FORWARD: ACCEPT（匹配来自 VPN CIDR 的转发包）
	forwardChain := n.conn.AddChain(&nftables.Chain{
		Name:     nftForwardChain,
		Table:    globalNatTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityMangle,
	})
	// 回程流量
	n.conn.AddRule(&nftables.Rule{
		Table: globalNatTable,
		Chain: forwardChain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			// ct_state 以主机字节序存储，用 binaryutil 避免字节序错误
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(6), // ESTABLISHED|RELATED
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			// ct_state & 6 != 0
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// 来自 VPN CIDR 的出站转发流量
	n.conn.AddRule(&nftables.Rule{
		Table: globalNatTable,
		Chain: forwardChain,
		Exprs: n.ForwardAcceptExprs(ipNet, prefixMask),
	})

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("flush nftables failed: %v", err)
	}
	base.Info("nftables: Setup Global NAT and Forward rules")
	return nil
}
func (n *NFT) AddGroupNAT(groupCIDR, masterDev string, inContainer bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	_, ipNet, err := net.ParseCIDR(groupCIDR)
	if err != nil {
		return fmt.Errorf("invalid groupCIDR: %v", err)
	}
	ones, _ := ipNet.Mask.Size()
	prefixMask := net.CIDRMask(ones, 32)

	globalNatTable := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftGlobalNatTable,
	}
	postroutingChain := &nftables.Chain{
		Name:  nftPostRoutingChain,
		Table: globalNatTable,
	}
	forwardChain := &nftables.Chain{
		Name:  nftForwardChain,
		Table: globalNatTable,
	}

	// POSTROUTING: MASQUERADE（组 CIDR 出站伪装）
	n.conn.AddRule(&nftables.Rule{
		Table: globalNatTable,
		Chain: postroutingChain,
		Exprs: n.MasqueradeExprs(ipNet, prefixMask, masterDev),
	})

	// FORWARD: ACCEPT（允许组 CIDR 的出站转发流量）
	n.conn.AddRule(&nftables.Rule{
		Table: globalNatTable,
		Chain: forwardChain,
		Exprs: n.ForwardAcceptExprs(ipNet, prefixMask),
	})

	return n.conn.Flush()
}

// MASQUERADE 规则表达式（匹配源 CIDR + 出站接口）
func (n *NFT) MasqueradeExprs(ipNet *net.IPNet, prefixMask net.IPMask, masterDev string) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           prefixMask,
			Xor:            net.IPv4zero.To4(),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipNet.IP.To4(),
		},
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 2},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 2,
			Data:     ifname(masterDev),
		},
		&expr.Masq{},
	}
}

// FORWARD ACCEPT 规则的表达式（匹配源 CIDR）
func (n *NFT) ForwardAcceptExprs(ipNet *net.IPNet, prefixMask net.IPMask) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           prefixMask,
			Xor:            net.IPv4zero.To4(),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipNet.IP.To4(),
		},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

// 初始化 Table, Map 和跳转规则
func (n *NFT) CreateChains(vpnCIDR, fakeIPRange string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 创建 IPv4 表
	n.table = n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nftTableName,
	})

	// 创建 DNAT Map (Key: FakeIP -> Val: RealIP)
	dnatMap := &nftables.Set{
		Table:    n.table,
		Name:     nftDnatMapName,
		IsMap:    true,
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
	}
	if err := n.conn.AddSet(dnatMap, nil); err != nil {
		return err
	}

	// 创建 PREROUTING 规则: 如果目的地址在 dnat_map 中，执行 DNAT
	prerouting := n.conn.AddChain(&nftables.Chain{
		Name:     nftFakeIPPreRoutingChain,
		Table:    n.table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: prerouting,
		Exprs: []expr.Any{
			// 从 IP 头提取目的地址（DAddr）到寄存器 1
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			// 用寄存器 1 的值去 dnat_map 查找，结果覆盖回寄存器 1
			&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: nftDnatMapName},
			// 用寄存器 1 的值执行 DNAT
			&expr.NAT{Type: expr.NATTypeDestNAT, Family: uint32(nftables.TableFamilyIPv4), RegAddrMin: 1},
		},
	})

	base.Info("nftables initialized with map-based rules")
	return n.conn.Flush()
}
func (n *NFT) AddNatRule(fakeIP, realIP string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	fakeIPParsed := net.ParseIP(fakeIP).To4()
	realIPParsed := net.ParseIP(realIP).To4()

	if fakeIPParsed == nil {
		return fmt.Errorf("invalid fake IP address: %s", fakeIP)
	}
	if realIPParsed == nil {
		return fmt.Errorf("invalid real IP address: %s", realIP)
	}
	dnatSet := &nftables.Set{Table: n.table, Name: nftDnatMapName}
	n.conn.SetAddElements(dnatSet, []nftables.SetElement{
		{Key: fakeIPParsed, Val: realIPParsed},
	})
	if err := n.conn.Flush(); err != nil && !isNftDuplicateError(err) {
		return err
	}
	return nil
}

func (n *NFT) DelNatRule(fakeIP, realIP string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	fakeIPParsed := net.ParseIP(fakeIP).To4()
	if fakeIPParsed == nil {
		return fmt.Errorf("invalid fake IP address: %s", fakeIP)
	}
	dnatSet := &nftables.Set{Table: n.table, Name: nftDnatMapName}
	n.conn.SetDeleteElements(dnatSet, []nftables.SetElement{
		{Key: fakeIPParsed},
	})
	if err := n.conn.Flush(); err != nil && !strings.Contains(err.Error(), "no such file") {
		return err
	}
	return nil
}

// 探测 nftables 是否可用
func (n *NFT) Probe() error {
	testTable := n.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "REMLINK_PROBE_TEST",
	})
	n.conn.AddChain(&nftables.Chain{
		Name:     "PROBE_CHAIN",
		Table:    testTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	err := n.conn.Flush()
	n.conn.DelTable(testTable)
	n.conn.Flush()
	return err
}
func (n *NFT) CleanupFakeIP() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.table != nil {
		n.conn.DelTable(n.table)
	} else {
		n.conn.DelTable(&nftables.Table{Name: nftTableName, Family: nftables.TableFamilyIPv4})
	}
	return n.conn.Flush()
}
func (n *NFT) CleanupGlobal() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 清理全局 NAT 表
	n.conn.DelTable(&nftables.Table{Name: nftGlobalNatTable, Family: nftables.TableFamilyIPv4})
	return n.conn.Flush()
}

// 清理所有防火墙后端规则
func CleanupAllNatRules() {
	if ipt, err := NewIPT(); err == nil {
		ipt.CleanupGlobal()
		ipt.CleanupFakeIP()
	}
	if nft, err := NewNFT(); err == nil {
		nft.CleanupGlobal()
		nft.CleanupFakeIP()
	}
}

// 判断 nftables 规则已存在的错误
func isNftDuplicateError(err error) bool {
	return strings.Contains(err.Error(), "file exists")
}
