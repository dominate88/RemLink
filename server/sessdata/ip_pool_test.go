package sessdata

import (
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
)

func preData(tmpDir string) {
	// 注册认证器
	for _, name := range []string{"local", "ldap", "radius", "otp", "cert", "saml", "wxwork", "feishu"} {
		if !auth.IsRegistered(name) {
			n := name
			auth.Register(n, func() auth.Authenticator { return &testAuthStub{name: n} })
		}
	}

	base.Test()
	tmpDb := path.Join(tmpDir, "test.db")
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.DbType = "sqlite3"
		c.DbSource = tmpDb
		c.Ipv4CIDR = "192.168.3.0/24"
		c.Ipv4Gateway = "192.168.3.1"
		c.Ipv4Start = "192.168.3.100"
		c.Ipv4End = "192.168.3.150"
		c.Ipv6CIDR = "2001:db8:3::/120"
		c.MaxClient = 100
		c.MaxUserClient = 3
		c.IpLease = 5
	})

	dbdata.Start()
	p := dbdata.Policy{
		Name:      "ip-pool-test-policy",
		Status:    1,
		Bandwidth: 1000,
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
	}
	_ = dbdata.Add(&p)
	group := dbdata.Group{
		Name:     "group1",
		PolicyId: p.Id,
	}
	_ = dbdata.Add(&group)

	user := dbdata.User{
		Username: "user-test",
		Mtu:      1000,
	}
	_ = dbdata.Add(&user)
	if err := initIpPool(); err != nil {
		panic(err)
	}
}

func cleardata(tmpDir string) {
	_ = dbdata.Stop()
	tmpDb := path.Join(tmpDir, "test.db")
	os.Remove(tmpDb)
}

func TestIpPool(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	var ip net.IP

	for i := 100; i <= 150; i++ {
		_ = AcquireIp(getTestUser(i), getTestMacAddr(i), true)
	}

	// 回收
	ReleaseIp(net.IPv4(192, 168, 3, 140), nil, getTestMacAddr(140))
	time.Sleep(time.Second * 6)

	// 从头循环获取可用ip
	user_new := getTestUser(210)
	mac_new := getTestMacAddr(210)
	ip = AcquireIp(user_new, mac_new, true)
	t.Log("mac_new", ip)
	assert.NotNil(ip)
	assert.True(net.IPv4(192, 168, 3, 140).Equal(ip))

	// 回收全部
	for i := 100; i <= 150; i++ {
		ReleaseIp(net.IPv4(192, 168, 3, byte(i)), nil, getTestMacAddr(i))
	}
}

func TestIpv6Pool(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	// 重置 v6 池游标与活跃表，保证干净起步
	ipActive = map[string]bool{}
	_ = initIpPool()

	// 分配若干 v6 地址
	const n = 50
	var ips []net.IP
	for i := range n {
		ip := acquireIpV6(getTestUser(3000+i), getTestMacAddr(3000+i), true, IpPool)
		assert.NotNil(ip)
		assert.Equal(16, len(ip)) // 128 位
		ips = append(ips, ip)
	}

	// 全部应在 Ipv6CIDR(2001:db8:3::/120) 网段内
	_, v6Net, _ := net.ParseCIDR("2001:db8:3::/120")
	for _, ip := range ips {
		assert.True(v6Net.Contains(ip), "v6 地址不在池网段内: %s", ip)
	}

	// 释放后过租期再次分配应仍在池内（轮询游标继续，半满池不保证返回同一地址；回绕后才复用）
	ReleaseIp(nil, ips[0], getTestMacAddr(3000))
	time.Sleep(time.Second * 6)
	ip2 := acquireIpV6(getTestUser(3999), getTestMacAddr(3999), true, IpPool)
	assert.NotNil(ip2)
	assert.True(v6Net.Contains(ip2), "复用分配的 v6 地址应在池网段内: %s", ip2)

	// 回收全部，避免影响其他用例
	for i := range n {
		ReleaseIp(nil, ips[i], getTestMacAddr(3000+i))
	}
	ReleaseIp(nil, ip2, getTestMacAddr(3999))
}

// 启用 IPv6 时若配置 MTU<1280，initIpPool 应自动上调到 1280
func TestIpv6MtuFloor(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	base.GetCfg().Mtu = 1000
	assert.NoError(initIpPool())
	assert.Equal(1280, base.GetCfg().Mtu, "启用 IPv6 且 MTU<1280 时应被自动上调到 1280")
}
func TestGroupIpPoolIsolation(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)

	// 清理跨用例可能残留的状态，保证干净起步
	ipActive = map[string]bool{}
	groupPoolCache = map[string]*ipPoolConfig{}

	// 组B范围数值上高于组A，才能暴露旧的“共享游标”bug
	groupA := &dbdata.Group{
		Name:          "groupA",
		ClientCidr:    "10.0.1.0/24",
		ClientStart:   "10.0.1.100",
		ClientEnd:     "10.0.1.150",
		ClientGateway: "10.0.1.1",
	}
	groupB := &dbdata.Group{
		Name:          "groupB",
		ClientCidr:    "10.0.2.0/24",
		ClientStart:   "10.0.2.100",
		ClientEnd:     "10.0.2.150",
		ClientGateway: "10.0.2.1",
	}

	poolA := GetGroupIpPool(groupA)
	poolB := GetGroupIpPool(groupB)

	// 缓存复用：同一组配置必须返回同一实例（游标才能累积）
	poolA2 := GetGroupIpPool(groupA)
	assert.Same(poolA, poolA2)

	// 池配置断言
	assert.Equal(utils.Ip2long(net.ParseIP("10.0.1.100")), poolA.IpLongMin)
	assert.Equal(utils.Ip2long(net.ParseIP("10.0.1.150")), poolA.IpLongMax)
	assert.Equal(utils.Ip2long(net.ParseIP("10.0.2.100")), poolB.IpLongMin)
	assert.Equal(utils.Ip2long(net.ParseIP("10.0.2.150")), poolB.IpLongMax)

	// 确定性顺序：先把组A灌若干个，再灌组B
	var ipsA, ipsB []net.IP
	for i := range 10 {
		ip := AcquireIpWithRange(getTestUser(1000+i), getTestMacAddr(1000+i), true, poolA)
		assert.NotNil(ip)
		ipsA = append(ipsA, ip)
	}
	for i := range 10 {
		ip := AcquireIpWithRange(getTestUser(2000+i), getTestMacAddr(2000+i), true, poolB)
		assert.NotNil(ip)
		ipsB = append(ipsB, ip)
	}

	// 断言：组A的IP必须全部在 10.0.1.100-150 范围内
	for _, ip := range ipsA {
		ipLong := utils.Ip2long(ip)
		assert.True(ipLong >= poolA.IpLongMin && ipLong <= poolA.IpLongMax,
			"组A分配了超出范围的IP: %s (min=%d max=%d)", ip, poolA.IpLongMin, poolA.IpLongMax)
	}
	// 断言：组B的IP必须全部在 10.0.2.100-150 范围内
	for _, ip := range ipsB {
		ipLong := utils.Ip2long(ip)
		assert.True(ipLong >= poolB.IpLongMin && ipLong <= poolB.IpLongMax,
			"组B分配了超出范围的IP: %s (min=%d max=%d)", ip, poolB.IpLongMin, poolB.IpLongMax)
	}

	t.Logf("组A分配了 %d 个IP, 组B分配了 %d 个IP", len(ipsA), len(ipsB))
}

func getTestUser(i int) string {
	return fmt.Sprintf("user-%d", i)
}

func getTestMacAddr(i int) string {
	// 前缀mac
	macAddr := "02:00:00:00:00"
	return fmt.Sprintf("%s:%x", macAddr, i)
}

// testAuthStub 无状态认证桩，避免循环依赖 auth/authsrv
type testAuthStub struct {
	name string
}

func (a *testAuthStub) Name() string { return a.name }
func (a *testAuthStub) Authenticate(*auth.Context) (auth.StepResult, error) {
	return auth.StepPass, nil
}

// ========== 组级 v6 池（V2） ==========

func TestInitV6_GatewayAndBounds(t *testing.T) {
	p := &ipPoolConfig{}
	assert.Nil(t, p.initV6("2001:db8:5::/120"))
	// gw = 网络地址 + 1
	assert.True(t, p.Ipv6Gateway.Equal(net.ParseIP("2001:db8:5::1")))
	// start = 网络地址 + 2
	assert.Equal(t, 0, p.ipv6Start.Cmp(ipToBig(net.ParseIP("2001:db8:5::2"))))
	// end = 网段末地址
	_, net120, _ := net.ParseCIDR("2001:db8:5::/120")
	end := new(big.Int).Add(ipToBig(net120.IP.Mask(net120.Mask)),
		new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(128-120)), big.NewInt(1)))
	assert.Equal(t, 0, p.ipv6End.Cmp(end))
	// 前缀 = 128 无分配空间，应报错
	assert.Error(t, p.initV6("2001:db8:6::/128"))
	// v4 CIDR 应报错
	assert.Error(t, p.initV6("10.0.0.0/24"))
}

func TestGroupV6Pool_Isolated(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)
	ipActive = map[string]bool{}
	groupPoolCache = map[string]*ipPoolConfig{}

	g := &dbdata.Group{
		Name:          "v6group",
		ClientCidr:    "10.0.9.0/24",
		ClientStart:   "10.0.9.100",
		ClientEnd:     "10.0.9.150",
		ClientGateway: "10.0.9.1",
		ClientCidr6:   "2001:db8:9::/120",
	}
	p := GetGroupIpPool(g)
	assert.NotNil(p.Ipv6IPNet)
	assert.True(p.Ipv6IPNet.Contains(net.ParseIP("2001:db8:9::5")))
	// 组级 v6 网关优先
	assert.True(p.Ipv6Gateway.Equal(net.ParseIP("2001:db8:9::1")))
	// 不回退全局网关
	assert.False(p.V6Gateway().Equal(IpPool.Ipv6Gateway))
}

func TestGroupV6Pool_FallbackGateway(t *testing.T) {
	assert := assert.New(t)
	tmp := t.TempDir()
	preData(tmp)
	defer cleardata(tmp)
	ipActive = map[string]bool{}
	groupPoolCache = map[string]*ipPoolConfig{}

	g := &dbdata.Group{
		Name:          "nov6group",
		ClientCidr:    "10.0.8.0/24",
		ClientStart:   "10.0.8.100",
		ClientEnd:     "10.0.8.150",
		ClientGateway: "10.0.8.1",
	}
	p := GetGroupIpPool(g)
	assert.Nil(p.Ipv6IPNet) // 组池本身无 v6 字段
	// V6Gateway 回退全局池
	assert.True(p.V6Gateway().Equal(IpPool.Ipv6Gateway))
	// 用该组池分配 v6 应回退全局池
	ip := acquireIpV6("u-fb", "mac-fb", true, p)
	assert.NotNil(ip)
	assert.True(IpPool.Ipv6IPNet.Contains(ip), "v6 应回退全局池分配: %s", ip)
	ReleaseIp(nil, ip, "mac-fb")
}
