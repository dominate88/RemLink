package sessdata

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
)

var (
	IpPool   = &ipPoolConfig{}
	ipActive = map[string]bool{}
	// ipKeep and ipLease  ipAddr => macAddr
	// ipKeep    = map[string]string{}
	ipPoolMux sync.Mutex

	// 组池缓存
	groupPoolCache = map[string]*ipPoolConfig{}
	groupPoolMux   sync.Mutex
)

type ipPoolConfig struct {
	// 计算动态ip
	Ipv4Gateway net.IP
	Ipv4Mask    net.IP
	Ipv4IPNet   *net.IPNet
	IpLongMin   uint32
	IpLongMax   uint32
	loopCurIp   uint32        // 每池独立的循环游标
	loopFarIp   *dbdata.IpMap // 每池独立的最早登录记录
}

func GetGroupIpPool(group *dbdata.Group) *ipPoolConfig {
	// 优先使用组级别配置
	if group != nil && group.ClientCidr != "" && group.ClientStart != "" && group.ClientEnd != "" && group.ClientGateway != "" {
		cacheKey := group.ClientCidr + "|" + group.ClientStart + "|" + group.ClientEnd + "|" + group.ClientGateway

		groupPoolMux.Lock()
		defer groupPoolMux.Unlock()
		if p, ok := groupPoolCache[cacheKey]; ok {
			return p // 复用，游标得以跨连接累积
		}

		_, ipNet, err := net.ParseCIDR(group.ClientCidr)
		if err != nil {
			base.Warn("组", group.Name, "IP网段配置无效，回退到全局:", err)
		} else {
			start := net.ParseIP(group.ClientStart)
			end := net.ParseIP(group.ClientEnd)
			gateway := net.ParseIP(group.ClientGateway)
			if start != nil && end != nil && gateway != nil &&
				ipNet.Contains(start) && ipNet.Contains(end) && ipNet.Contains(gateway) {
				p := &ipPoolConfig{
					Ipv4Gateway: gateway,
					Ipv4Mask:    net.IP(ipNet.Mask),
					Ipv4IPNet:   ipNet,
					IpLongMin:   utils.Ip2long(start),
					IpLongMax:   utils.Ip2long(end),
				}
				p.loopCurIp = p.IpLongMin
				groupPoolCache[cacheKey] = p
				return p
			}
			base.Warn("组", group.Name, "IP范围不在网段内，回退到全局")
		}
	}

	// 回退到全局配置
	return IpPool
}

func initIpPool() error {

	// 地址处理
	_, ipNet, err := net.ParseCIDR(base.GetCfg().Ipv4CIDR)
	if err != nil {
		return fmt.Errorf("IPv4 CIDR 配置错误(%s): %v", base.GetCfg().Ipv4CIDR, err)
	}
	IpPool.Ipv4IPNet = ipNet
	IpPool.Ipv4Mask = net.IP(ipNet.Mask)

	ipv4Gateway := net.ParseIP(base.GetCfg().Ipv4Gateway)
	ipStart := net.ParseIP(base.GetCfg().Ipv4Start)
	ipEnd := net.ParseIP(base.GetCfg().Ipv4End)
	if !ipNet.Contains(ipv4Gateway) || !ipNet.Contains(ipStart) || !ipNet.Contains(ipEnd) {
		return fmt.Errorf("IPv4 网关/起始/结束地址不在 CIDR(%s) 网段内，网关=%s 起始=%s 结束=%s",
			base.GetCfg().Ipv4CIDR, base.GetCfg().Ipv4Gateway, base.GetCfg().Ipv4Start, base.GetCfg().Ipv4End)
	}
	// ip地址池
	IpPool.Ipv4Gateway = ipv4Gateway
	IpPool.IpLongMin = utils.Ip2long(ipStart)
	IpPool.IpLongMax = utils.Ip2long(ipEnd)

	IpPool.loopCurIp = IpPool.IpLongMin

	// 网络地址零值
	// zero := binary.BigEndian.Uint32(ip.Mask(mask))
	// 广播地址
	// one, _ := ipNet.Mask.Size()
	// max := min | uint32(math.Pow(2, float64(32-one))-1)

	// 获取IpLease数据
	// go cronIpLease()

	return nil
}

// func cronIpLease() {
// 	getIpLease()
// 	tick := time.NewTicker(time.Minute * 30)
// 	for range tick.C {
// 		getIpLease()
// 	}
// }
//
// func getIpLease() {
// 	xdb := dbdata.GetXdb()
// 	keepIpMaps := []dbdata.IpMap{}
// 	// sNow := time.Now().Add(-1 * time.Duration(base.GetCfg().IpLease) * time.Second)
// 	err := xdb.Cols("ip_addr", "mac_addr").Where("keep=?", true).Find(&keepIpMaps)
// 	if err != nil {
// 		base.Error(err)
// 	}
// 	log.Println(keepIpMaps)
// 	ipPoolMux.Lock()
// 	ipKeep = map[string]string{}
// 	for _, v := range keepIpMaps {
// 		ipKeep[v.IpAddr] = v.MacAddr
// 	}
// 	ipPoolMux.Unlock()
// }

func ipInPool(ip net.IP, ipRange *ipPoolConfig) bool {
	if ipRange == nil {
		ipRange = GetGroupIpPool(nil) // fallback to global
	}
	ipLong := utils.Ip2long(ip)
	if ipLong >= ipRange.IpLongMin && ipLong <= ipRange.IpLongMax {
		return true
	}
	return false
}

// 获取动态ip（使用全局 IP 池，向后兼容）
func AcquireIp(username, macAddr string, uniqueMac bool) (newIp net.IP) {
	return AcquireIpWithRange(username, macAddr, uniqueMac, nil)
}

// 在指定 IP 范围内获取动态 ip
func AcquireIpWithRange(username, macAddr string, uniqueMac bool, ipRange *ipPoolConfig) (newIp net.IP) {
	base.Trace("AcquireIp start:", username, macAddr, uniqueMac)
	ipPoolMux.Lock()
	defer func() {
		ipPoolMux.Unlock()
		base.Trace("AcquireIp end:", username, macAddr, uniqueMac, newIp)
		base.Debug("AcquireIp ip:", username, macAddr, uniqueMac, newIp)
	}()

	if ipRange == nil {
		ipRange = GetGroupIpPool(nil)
	}

	var (
		err  error
		tNow = time.Now()
	)

	// 获取到客户端 macAddr 的情况
	if uniqueMac {
		// 判断是否已经分配过
		mi := &dbdata.IpMap{}
		err = dbdata.One("mac_addr", macAddr, mi)
		if err != nil {
			// 没有查询到数据
			if dbdata.CheckErrNotFound(err) {
				return loopIp(username, macAddr, uniqueMac, ipRange)
			}
			// 查询报错
			base.Error(err)
			return nil
		}

		// 存在ip记录
		base.Trace("uniqueMac:", username, mi)
		ipStr := mi.IpAddr
		ip := net.ParseIP(ipStr)
		// 跳过活跃连接
		_, ok := ipActive[ipStr]
		// 检测原有ip是否在新的ip池内
		if !ok && ipInPool(ip, ipRange) {
			mi.Username = username
			mi.LastLogin = tNow
			mi.UniqueMac = uniqueMac
			// 回写db数据
			if err = dbdata.Set(mi); err != nil {
				base.Error("IP池 Set 失败:", err)
			}
			ipActive[ipStr] = true
			return ip
		}

		// ip保留
		if mi.Keep {
			base.Error(username, macAddr, ipStr, "保留ip不匹配CIDR")
			return nil
		}

		// 删除当前macAddr
		mi = &dbdata.IpMap{MacAddr: macAddr}
		if err = dbdata.Del(mi); err != nil {
			base.Error("IP池 Del 失败:", err)
		}
		return loopIp(username, macAddr, uniqueMac, ipRange)
	}

	// 没有获取到mac的情况
	ipMaps := []dbdata.IpMap{}
	err = dbdata.FindWhere(&ipMaps, 30, 1, "username=?", username)
	if err != nil {
		// 没有查询到数据
		if dbdata.CheckErrNotFound(err) {
			return loopIp(username, macAddr, uniqueMac, ipRange)
		}
		// 查询报错
		base.Error(err)
		return nil
	}

	// 遍历mac记录
	for _, mi := range ipMaps {
		ipStr := mi.IpAddr
		ip := net.ParseIP(ipStr)

		// 跳过活跃连接
		if _, ok := ipActive[ipStr]; ok {
			continue
		}
		// 跳过保留ip
		if mi.Keep {
			continue
		}
		if mi.UniqueMac {
			continue
		}

		// 没有mac的 不需要验证租期
		if ipInPool(ip, ipRange) {
			mi.Username = username
			mi.LastLogin = tNow
			mi.MacAddr = macAddr
			mi.UniqueMac = uniqueMac
			// 回写db数据
			if err = dbdata.Set(mi); err != nil {
				base.Error("IP池 Set 失败:", err)
			}
			ipActive[ipStr] = true
			return ip
		}
	}

	return loopIp(username, macAddr, uniqueMac, ipRange)
}

func loopIp(username, macAddr string, uniqueMac bool, ipRange *ipPoolConfig) net.IP {
	var (
		i  uint32
		ip net.IP
	)

	if ipRange == nil {
		ipRange = GetGroupIpPool(nil)
	}

	// 重新赋值
	ipRange.loopFarIp = &dbdata.IpMap{LastLogin: time.Now()}

	i, ip = loopLong(ipRange.loopCurIp, ipRange.IpLongMax, username, macAddr, uniqueMac, ipRange)
	if ip != nil {
		ipRange.loopCurIp = i
		return ip
	}

	i, ip = loopLong(ipRange.IpLongMin, ipRange.loopCurIp, username, macAddr, uniqueMac, ipRange)
	if ip != nil {
		ipRange.loopCurIp = i
		return ip
	}

	// ip分配完,从头开始
	ipRange.loopCurIp = ipRange.IpLongMin

	if ipRange.loopFarIp.Id > 0 {
		// 使用最早登陆的 ip
		ipStr := ipRange.loopFarIp.IpAddr
		ip = net.ParseIP(ipStr)
		mi := &dbdata.IpMap{IpAddr: ipStr, MacAddr: macAddr, UniqueMac: uniqueMac, Username: username, LastLogin: time.Now()}
		// 回写db数据
		if setErr := dbdata.Set(mi); setErr != nil {
			base.Error("IP池 Set(最早) 失败:", setErr)
		}
		ipActive[ipStr] = true

		return ip
	}

	// 全都在线，没有数据可用
	base.Warn("no ip available, please see ip_map table row", username, macAddr)
	return nil
}

func loopLong(start, end uint32, username, macAddr string, uniqueMac bool, ipRange *ipPoolConfig) (uint32, net.IP) {
	var (
		err       error
		tNow      = time.Now()
		leaseTime = time.Now().Add(-1 * time.Duration(base.GetCfg().IpLease) * time.Second)
	)

	if ipRange == nil {
		ipRange = GetGroupIpPool(nil)
	}

	// 全局遍历超过租期和未保留的ip
	for i := start; i <= end; i++ {
		ip := utils.Long2ip(i)
		ipStr := ip.String()

		// 跳过活跃连接
		if _, ok := ipActive[ipStr]; ok {
			continue
		}

		mi := &dbdata.IpMap{}
		err = dbdata.One("ip_addr", ipStr, mi)
		if err != nil {
			// 没有查询到数据
			if dbdata.CheckErrNotFound(err) {
				// 该ip没有被使用
				mi = &dbdata.IpMap{IpAddr: ipStr, MacAddr: macAddr, UniqueMac: uniqueMac, Username: username, LastLogin: tNow}
				if err = dbdata.Add(mi); err != nil {
					base.Error("IP池 Add 失败:", err)
				}
				ipActive[ipStr] = true
				return i, ip
			}
			// 查询报错
			base.Error(err)
			return 0, nil
		}

		// 查询到已经使用的ip
		// 跳过保留ip
		if mi.Keep {
			continue
		}
		// 判断租期
		if mi.LastLogin.Before(leaseTime) {
			// 存在记录，说明已经超过租期，可以直接使用
			mi.Username = username
			mi.LastLogin = tNow
			mi.MacAddr = macAddr
			mi.UniqueMac = uniqueMac
			// 回写db数据
			if err = dbdata.Set(mi); err != nil {
				base.Error("IP池 Set(租期) 失败:", err)
			}
			ipActive[ipStr] = true
			return i, ip
		}
		// 其他情况判断最早登陆
		if mi.LastLogin.Before(ipRange.loopFarIp.LastLogin) {
			ipRange.loopFarIp = mi
		}
	}

	return 0, nil
}

// 回收ip
func ReleaseIp(ip net.IP, macAddr string) {
	ipPoolMux.Lock()
	defer ipPoolMux.Unlock()

	delete(ipActive, ip.String())

	mi := &dbdata.IpMap{}
	err := dbdata.One("ip_addr", ip.String(), mi)
	if err == nil {
		mi.LastLogin = time.Now()
		if err = dbdata.Set(mi); err != nil {
			base.Error("IP池 ReleaseIp Set 失败:", err)
		}
	}
}
