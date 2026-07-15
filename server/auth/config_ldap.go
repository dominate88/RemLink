// LDAP Provider 配置类型及 LDAP 通用操作

package auth

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/go-ldap/ldap"
)

var (
	// IP:Port 格式正则（IPv4），validateAddr 和 RADIUS 校验共用
	ipPortRe = regexp.MustCompile(`^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\:([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-5]{2}[0-3][0-5])$`)
	// DN 格式正则（LDAP Distinguished Name）
	dnRe = regexp.MustCompile(`^(?:(?:CN|cn|OU|ou|DC|dc)\=[^,'"]+,)*(?:CN|cn|OU|ou|DC|dc)\=[^,'"]+$`)
	// Domain:Port 格式正则
	domainPortRe = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}\.)+[A-Za-z]{2,18}\:([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-5]{2}[0-3][0-5])$`)
)

type LDAPConfig struct {
	Addr           string `json:"addr"`
	Tls            bool   `json:"tls"`
	BindName       string `json:"bind_name"`
	BindPwd        string `json:"bind_pwd"`
	BaseDn         string `json:"base_dn"`
	ObjectClass    string `json:"object_class"`
	SearchAttr     string `json:"search_attr"`
	MemberOf       string `json:"member_of"`
	SyncUserStatus bool   `json:"sync_user_status"`
	EnableOtp      bool   `json:"enable_otp"` // 同步用户时启用 OTP
}

// 填充 LDAP 默认值
func (c *LDAPConfig) Defaults() {
	if c.ObjectClass == "" {
		c.ObjectClass = "person"
	}
}

// 验证 LDAP 配置参数
func (c *LDAPConfig) ValidateConfig() error {
	if !validateAddr(c.Addr) {
		return fmt.Errorf("LDAP 服务器地址格式有误")
	}
	if c.BindName == "" {
		return fmt.Errorf("管理员 DN 不能为空")
	}
	if c.BindPwd == "" {
		return fmt.Errorf("管理员密码不能为空")
	}
	if c.BaseDn == "" || !validateDN(c.BaseDn) {
		return fmt.Errorf("Base DN 格式有误")
	}
	if c.ObjectClass == "" {
		return fmt.Errorf("用户对象类不能为空")
	}
	if c.SearchAttr == "" {
		return fmt.Errorf("用户唯一 ID 不能为空")
	}
	if c.MemberOf != "" && !validateDN(c.MemberOf) {
		return fmt.Errorf("受限用户组格式有误")
	}
	return nil
}

// 建立 LDAP 连接
func (c *LDAPConfig) Connect() (*ldap.Conn, error) {
	l, err := ldap.Dial("tcp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("LDAP 连接失败: %w", err)
	}

	if c.Tls {
		if err := l.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			l.Close()
			return nil, fmt.Errorf("LDAP TLS 连接失败: %w", err)
		}
	}

	if err := l.Bind(c.BindName, c.BindPwd); err != nil {
		l.Close()
		return nil, fmt.Errorf("LDAP 管理员 DN/密码错误: %w", err)
	}

	return l, nil
}

// 构建 LDAP 搜索过滤器
func (c *LDAPConfig) SearchFilter(username string) string {
	f := "(objectClass=" + c.ObjectClass + ")"
	if username != "" {
		f += "(" + c.SearchAttr + "=" + ldap.EscapeFilter(username) + ")"
	} else {
		f += "(" + c.SearchAttr + "=*)"
	}
	if c.MemberOf != "" {
		f += "(memberOf:=" + c.MemberOf + ")"
	}
	return "(&" + f + ")"
}

// 搜索 LDAP 用户
func (c *LDAPConfig) SearchUsers(l *ldap.Conn, username string, attributes []string) (*ldap.SearchResult, error) {
	filter := c.SearchFilter(username)
	pagingControl := ldap.NewControlPaging(100)

	searchRequest := ldap.NewSearchRequest(
		c.BaseDn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		filter,
		attributes,
		[]ldap.Control{pagingControl},
	)

	return l.SearchWithPaging(searchRequest, 100)
}

func validateAddr(addr string) bool {
	return ipPortRe.MatchString(addr) || domainPortRe.MatchString(addr)
}

func validateDN(dn string) bool {
	return dnRe.MatchString(dn)
}

// 检查 LDAP 账号状态（AD/LDAP 通用）
func CheckAccountStatus(sr *ldap.SearchResult) error {
	const (
		ACCOUNTDISABLE = 2
		LOCKOUT        = 16
		// AD 中 accountExpires 为此值时表示"永不过期"
		accountNeverExpires = 9223372036854775807
	)

	for _, attr := range sr.Entries[0].Attributes {
		switch attr.Name {
		case "userAccountControl":
			if len(attr.Values) > 0 {
				val, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					continue
				}
				if (val & LOCKOUT) != 0 {
					return fmt.Errorf("账号已被锁定")
				}
				if (val & ACCOUNTDISABLE) != 0 {
					return fmt.Errorf("账号已禁用")
				}
			}
		case "accountExpires":
			if len(attr.Values) > 0 {
				val, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					continue
				}
				if val > 0 && val < accountNeverExpires {
					expireTime := time.Unix((val-116444736000000000)/10000000, 0)
					if expireTime.Before(time.Now()) {
						return fmt.Errorf("账号已过期(%s)", expireTime.Format("2006-01-02 15:04:05"))
					}
				}
			}
		case "shadowExpire":
			if len(attr.Values) > 0 {
				val, err := strconv.ParseInt(attr.Values[0], 10, 64)
				if err != nil {
					continue
				}
				switch {
				case val == -1:
					return nil
				case val == 1:
					return fmt.Errorf("账号已停用")
				case val > 1:
					expireTime := time.Unix(val*86400, 0)
					t := time.Date(expireTime.Year(), expireTime.Month(), expireTime.Day(), 23, 59, 59, 0, time.Local)
					if t.Before(time.Now()) {
						return fmt.Errorf("账号已过期(%s)", t.Format("2006-01-02"))
					}
					return nil
				default:
					return fmt.Errorf("shadowExpire 值异常: %d", val)
				}
			}
		}
	}
	return nil
}
