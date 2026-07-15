package sessdata

import (
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/stretchr/testify/assert"
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
	ReleaseIp(net.IPv4(192, 168, 3, 140), getTestMacAddr(140))
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
		ReleaseIp(net.IPv4(192, 168, 3, byte(i)), getTestMacAddr(i))
	}
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
	for i := 0; i < 10; i++ {
		ip := AcquireIpWithRange(getTestUser(1000+i), getTestMacAddr(1000+i), true, poolA)
		assert.NotNil(ip)
		ipsA = append(ipsA, ip)
	}
	for i := 0; i < 10; i++ {
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
