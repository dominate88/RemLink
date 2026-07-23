package dbdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/songgao/water/waterutil"
	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/pkg/utils"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

const (
	Allow = "allow"
	Deny  = "deny"
	ALL   = "all"
	TCP   = "tcp"
	UDP   = "udp"
	ICMP  = "icmp"
)

// 域名分流最大字符2万
const DsMaxLen = 20000

type GroupLinkAcl struct {
	// 自上而下匹配 默认 allow * *
	Action   string               `json:"action"`      // allow、deny
	Protocol string               `json:"protocol"`    // 支持 ALL、TCP、UDP、ICMP 协议
	IpProto  waterutil.IPProtocol `json:"ip_protocol"` // 判断协议使用
	Val      string               `json:"val"`
	Port     string               `json:"port"` // 兼容单端口历史数据类型uint16
	Ports    map[uint16]int8      `json:"ports"`
	IpNet    *net.IPNet           `json:"ip_net"`
	Note     string               `json:"note"`
}

type ValData struct {
	Val    string `json:"val"`
	IpMask string `json:"ip_mask"`
	Note   string `json:"note"`
}

type GroupNameId struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}

// 返回所有用户组名称
func GetGroupNames() []string {
	var datas []Group
	err := Find(&datas, 0, 0)
	if err != nil {
		base.Error(err)
		return nil
	}
	if len(datas) == 0 {
		return []string{}
	}
	var names []string
	for _, v := range datas {
		names = append(names, v.Name)
	}
	return names
}

// 返回所有启用状态的用户组名称
func GetGroupNamesNormal() []string {
	var datas []Group
	err := FindWhere(&datas, 0, 0, "status=1")
	if err != nil {
		base.Error(err)
		return nil
	}
	if len(datas) == 0 {
		return []string{}
	}
	var names []string
	for _, v := range datas {
		names = append(names, v.Name)
	}
	return names
}

// 返回所有启用状态的用户组
func GetAllGroups() ([]Group, error) {
	var groups []Group
	if err := FindWhere(&groups, 0, 0, "status=1"); err != nil {
		base.Error(err)
		return nil, err
	}
	return groups, nil
}

// 返回所有用户组的 ID-名称映射
func GetGroupNamesIds() []GroupNameId {
	var datas []Group
	err := Find(&datas, 0, 0)
	if err != nil {
		base.Error(err)
		return nil
	}
	var names []GroupNameId
	for _, v := range datas {
		names = append(names, GroupNameId{Id: v.Id, Name: v.Name})
	}
	return names
}

// 新增或更新用户组配置
func SetGroup(g *Group) error {
	var err error
	if g.Name == "" {
		return errors.New("用户组名错误")
	}

	// 校验策略引用：启用状态的组必须指定一个有效的启用策略
	if g.Status == 1 && g.PolicyId <= 0 {
		return errors.New("启用的用户组必须指定策略")
	}
	if g.PolicyId > 0 {
		var policy Policy
		if err := One("Id", g.PolicyId, &policy); err != nil {
			return errors.New("引用的策略不存在")
		}
		if policy.Status != 1 {
			return errors.New("引用的策略已停用，请选择启用的策略")
		}
	}

	// SplitDns 验证
	splitDns := []ValData{}
	for _, v := range g.SplitDns {
		v.Val = strings.TrimSpace(v.Val)
		if v.Val != "" {
			if !ValidateDomainName(v.Val) {
				return errors.New("域名 错误")
			}
			splitDns = append(splitDns, v)
		}
	}
	g.SplitDns = splitDns

	// 校验组IP池 配置：全空不启用
	n := 0
	for _, f := range []string{g.ClientCidr, g.ClientStart, g.ClientEnd, g.ClientGateway} {
		if f != "" {
			n++
		}
	}
	switch n {
	case 0:
		// 全空，不启用组 IP
	case 4:
		_, ipNet, err := net.ParseCIDR(g.ClientCidr)
		if err != nil {
			return fmt.Errorf("组 IP 网段格式无效: %v", err)
		}
		start := net.ParseIP(g.ClientStart)
		end := net.ParseIP(g.ClientEnd)
		gateway := net.ParseIP(g.ClientGateway)
		for _, a := range []struct {
			name string
			ip   net.IP
		}{
			{"起始地址", start},
			{"结束地址", end},
			{"网关地址", gateway},
		} {
			if a.ip == nil {
				return fmt.Errorf("组 IP %s 格式无效", a.name)
			}
			if !ipNet.Contains(a.ip) {
				return fmt.Errorf("组 IP %s 不在网段内", a.name)
			}
		}
		if utils.Ip2long(start) >= utils.Ip2long(end) {
			return errors.New("组 IP 起始地址必须小于结束地址")
		}
	default:
		return errors.New("组 IP 配置必须全部填写：网段、起始地址、结束地址、网关")
	}

	// 处理认证配置（Pipeline 格式）
	if len(g.AuthProfile) == 0 {
		g.AuthProfile = json.RawMessage(`{"step":[{"type":"local"}]}`)
	}
	// 校验 AuthProfile 格式
	profile, err := auth.ParseAuthProfile(g.AuthProfile)
	if err != nil {
		return errors.New("认证配置格式无效: " + err.Error())
	}
	// 校验每个步骤
	for i, step := range profile.Step {
		if !auth.IsRegistered(step.Type) {
			return fmt.Errorf("未知的认证方式 %q (步骤 %d)", step.Type, i+1)
		}
		switch step.Type {
		case "ldap", "radius", "wxwork", "feishu":
			if step.Provider == "" {
				return fmt.Errorf("认证类型 %q 必须设置 Provider (步骤 %d)", step.Type, i+1)
			}
		default:
			if step.Provider != "" {
				return fmt.Errorf("认证类型 %q 不支持 Provider 引用 (步骤 %d)", step.Type, i+1)
			}
		}
	}

	g.UpdatedAt = time.Now()
	if g.Id > 0 {
		err = Set(g)
	} else {
		err = Add(g)
	}

	return err
}

// 检查端口是否在端口映射中
func ContainsInPorts(ports map[uint16]int8, port uint16) bool {
	_, ok := ports[port]
	return ok
}

// 使用 Pipeline 测试认证（后台"测试认证配置"入口）
func GroupAuthLogin(name, pwd string, authProfile json.RawMessage) error {
	profile, err := auth.ParseAuthProfile(authProfile)
	if err != nil {
		return fmt.Errorf("认证配置解析失败: %w", err)
	}

	pipeline, err := auth.GetPipeline(*profile, ResolveProviderConfig)
	if err != nil {
		return err
	}

	ctx := &auth.Context{
		Conn: auth.ConnInfo{
			Username:  name,
			Password:  pwd,
			GroupName: "",
		},
	}

	result, err := pipeline.Run(ctx)
	if err != nil {
		return err
	}

	switch result {
	case auth.StepPass:
		return nil
	case auth.StepFail:
		return fmt.Errorf("认证失败")
	case auth.StepPending:
		return fmt.Errorf("该认证流程需要额外交互（如 OTP 验证码），无法在此测试")
	default:
		return fmt.Errorf("认证返回未知状态: %v", result)
	}
}

// 检查 AuthProfile 中是否包含指定认证类型
func HasAuthType(authProfile json.RawMessage, authType string) bool {
	profile, err := auth.ParseAuthProfile(authProfile)
	if err != nil {
		return false
	}
	for _, step := range profile.Step {
		if step.Type == authType {
			return true
		}
	}
	return false
}

// 检查组是否引用了指定 Provider
func GroupUsesProvider(g *Group, providerName string) bool {
	profile, err := auth.ParseAuthProfile(g.AuthProfile)
	if err != nil {
		return false
	}
	for _, step := range profile.Step {
		if step.Provider == providerName {
			return true
		}
	}
	return false
}

// SyncExternalUsersForOTP 组配置了外部认证 + OTP 时自动同步用户到本地。
// LDAP/企微等有用户目录的外部 IdP，在管线要求 OTP 时必须先把用户同步到本地生成秘钥。
func SyncExternalUsersForOTP(g *Group) {
	if !HasAuthType(g.AuthProfile, "otp") {
		return
	}

	if HasAuthType(g.AuthProfile, "ldap") {
		authLdap, err := ResolveLdapConfig(g)
		if err != nil {
			base.Error("解析LDAP配置失败:", err)
		} else {
			authLdap.EnableOtp = true
			go func() {
				if err := authLdap.SaveUsers(g); err != nil {
					base.Error("LDAP用户同步失败:", g.Name, err)
				} else {
					base.Info("LDAP用户同步成功:", g.Name)
				}
			}()
		}
	}

	if HasAuthType(g.AuthProfile, "wxwork") {
		authWx, err := ResolveWxworkConfig(g)
		if err != nil {
			base.Error("解析企微配置失败:", err)
		} else {
			go func() {
				if err := authWx.SaveUsers(g); err != nil {
					base.Error("企微用户同步失败:", g.Name, err)
				} else {
					base.Info("企微用户同步成功:", g.Name)
				}
			}()
		}
	}

	if HasAuthType(g.AuthProfile, "feishu") {
		authFs, err := ResolveFeishuConfig(g)
		if err != nil {
			base.Error("解析飞书配置失败:", err)
		} else {
			go func() {
				if err := authFs.SaveUsers(g); err != nil {
					base.Error("飞书用户同步失败:", g.Name, err)
				} else {
					base.Info("飞书用户同步成功:", g.Name)
				}
			}()
		}
	}
}

func parseIpNet(s string) (string, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", nil, err
	}

	mask := net.IP(ipNet.Mask)
	ipMask := fmt.Sprintf("%s/%s", ip, mask)

	return ipMask, ipNet, nil
}

// 校验域名拆分规则格式
func CheckDomainNames(domains string) error {
	if domains == "" {
		return nil
	}
	strLen := 0
	strSlice := strings.SplitSeq(domains, ",")
	for val := range strSlice {
		if val == "" {
			return errors.New(val + " 请以逗号分隔域名")
		}
		if !ValidateDomainName(val) {
			return errors.New(val + " 域名有误")
		}
		strLen += len(val)
	}
	if strLen > DsMaxLen {
		p := message.NewPrinter(language.English)
		return fmt.Errorf("字符长度超出限制，最大%s个(不包含逗号), 请删减一些域名", p.Sprintf("%d", DsMaxLen))
	}
	return nil
}

// 校验 FakeDNS 域名规则格式
func CheckFakeDNSDomains(domains string) error {
	if domains == "" {
		return nil
	}
	strSlice := strings.SplitSeq(domains, ",")
	for val := range strSlice {
		if val == "" {
			return errors.New(val + " 请以逗号分隔域名")
		}
		if !ValidateDomainName(val) {
			return errors.New(val + " 域名有误")
		}
	}
	return nil
}

// 校验域名格式
func ValidateDomainName(domain string) bool {
	regExp := regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[A-Za-z]{2,18}$`)
	return regExp.MatchString(domain)
}
