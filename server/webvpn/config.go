package webvpn

import (
	"net"
	"strings"

	"github.com/wsczx/remlink/base"
)

// WebVPN 自有会话 cookie 名。
// WebVPN 反代转发给后端时必须剥离这些 cookie，避免把网关的会话令牌泄漏给被代理的内网应用
const sessionCookieName = "webvpn_session"

// 门户登录后签发的一次性免登授权 cookie 名
// 与 sessionCookieName 完全独立，二者 Domain/Scope 解耦
const grantCookieName = "webvpn_grant"

// 去掉 host:port 中的端口部分，仅保留主机名。
func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// 处理 [IPv6]:port
		if strings.Contains(host, "]") {
			return host[:strings.LastIndexByte(host, ':')]
		}
		return host[:i]
	}
	return host
}

// 返回注册域的最后两段（如 example.com）。
// 用于计算跨子域共享会话 cookie 的通配作用域，与门户 portalCookieDomain 算法解耦
// 这里只服务于 WebVPN 自身，不再依赖门户的 WebVpnDomain 判定
func base2Domain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = stripPort(domain)
	if domain == "" {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) < 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// 返回 WebVPN 会话/授权 cookie 应写入的 Domain
// 规则：host 属于 WebVpnDomain 注册域时，按 .base2 通配；IP 访问、未配置、或 host 不属于
// 该注册域时返回 ""（按当前 host 存储），与门户会话域完全独立
func CookieDomain(host string) string {
	domain := base.GetCfg().WebVpnDomain
	if domain == "" {
		return ""
	}
	host = stripPort(host)
	if net.ParseIP(host) != nil {
		return ""
	}
	base2 := base2Domain(domain)
	if base2 == "" {
		return ""
	}
	if host == base2 || strings.HasSuffix(host, "."+base2) {
		return "." + base2
	}
	return ""
}

// 返回 WebVpnDomain 对应的通配域（.base2），未配置返回空
// 仅在 exchange-token 方案下作为 grant cookie 的清除域使用
func wildcardDomain() string {
	base2 := base2Domain(base.GetCfg().WebVpnDomain)
	if base2 == "" {
		return ""
	}
	return "." + base2
}
