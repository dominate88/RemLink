package handler

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wsczx/remlink/admin"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// WebVPN 会话与门户会话（portal_session）相互独立：
// 复用 admin 的 JWT 签发/吊销基础设施，但使用独立的 cookie 名与 claim 前缀，
// 用户退出 WebVPN 不影响门户登录态，反之亦然。
const webVpnSessionCookie = "webvpn_session"

// remLinkSessionCookies 是 RemLink 自有会话 cookie 名清单。
// WebVPN 反代转发给后端时必须剥离这些 cookie，避免把网关的会话令牌泄漏给被代理的内网应用
// （若内部应用被攻破或存在 XSS，可能借这些令牌冒充用户/重放认证流程）。
var remLinkSessionCookies = []string{
	webVpnSessionCookie,             // webvpn_session
	portalCookieName,                // portal_session
	"auth-session-id",               // WebAuth/OTP 认证会话
	"acSamlv2Token",                 // SAML SSO 会话令牌
}

// WebVPN 会话滑动续期周期（分钟），默认 60。用户持续活跃时按此周期刷新登录态。
// 0 表示未配置，回退默认值。
const webVpnSessionTTLDefaultMin = 60

// WebVPN 会话绝对寿命上限（分钟），默认 480（8h）。自首次登录起算，超过后强制重新登录。
const webVpnSessionMaxLifetimeDefaultMin = 480

// WebVPN 会话滑动续期周期
func webVpnSessionTTL() time.Duration {
	min := base.GetCfg().WebVpnSessionTTL
	if min <= 0 {
		min = webVpnSessionTTLDefaultMin
	}
	return time.Duration(min) * time.Minute
}

// WebVPN 会话绝对寿命上限
func webVpnSessionMaxLifetime() time.Duration {
	min := base.GetCfg().WebVpnSessionMaxLifetime
	if min <= 0 {
		min = webVpnSessionMaxLifetimeDefaultMin
	}
	return time.Duration(min) * time.Minute
}

// 进程内用户缓存，避免每次请求回查 DB。
// WebVPN 反代命中率高（同一用户连续访问），TTL 60s。
var (
	webVpnUserCacheMu  sync.Mutex
	webVpnUserCache    = map[string]*webVpnUserCacheEntry{}
	webVpnUserCacheTTL = 60 * time.Second

	// 防无界增长：条目数超过该阈值时，惰性清理过期条目（最多每 minCleanInterval 一次）。
	webVpnUserCacheMaxSize   = 1000
	webVpnUserCacheMinClean  = time.Minute
	webVpnUserCacheLastClean time.Time
)

// 惰性清理过期缓存条目，防止长时间运行后 map 无界膨胀。
// 调用方须已持有 webVpnUserCacheMu 写锁。仅当条目数超阈值且距上次清理足够久才扫描，
// 避免高频请求下每次写入都遍历全表。
func webVpnUserCacheMaybeClean(now time.Time) {
	if len(webVpnUserCache) <= webVpnUserCacheMaxSize {
		return
	}
	if now.Sub(webVpnUserCacheLastClean) < webVpnUserCacheMinClean {
		return
	}
	webVpnUserCacheLastClean = now
	for k, e := range webVpnUserCache {
		if !e.expire.After(now) {
			delete(webVpnUserCache, k)
		}
	}
}

type webVpnUserCacheEntry struct {
	user   *dbdata.User
	expire time.Time
}

// 签发 WebVPN 会话 JWT 并设置 cookie。
// issuedAt 为会话首次登录时间（unix 秒）；续期时传入旧 token 的 webvpn_issued 锚点，
// 保证绝对寿命从首次登录起算、滑动续期不重置寿命计时。
func webVpnIssueSession(w http.ResponseWriter, r *http.Request, user *dbdata.User, issuedAt int64) (string, error) {
	now := time.Now()
	if issuedAt <= 0 {
		issuedAt = now.Unix()
	}
	expiresAt := now.Add(webVpnSessionTTL()).Unix()
	token, err := admin.SetJwtData(map[string]any{
		"webvpn_user":   user.Username,
		"webvpn_type":   user.Type,
		"webvpn_groups": user.Groups,
		"webvpn_issued": issuedAt,
	}, expiresAt)
	if err != nil {
		return "", err
	}
	webVpnSetSessionCookie(w, r, token)
	return token, nil
}

// 写 webvpn_session cookie（HttpOnly、跨子域共享）。
// w 为 nil 时仅返回不实际写入
func webVpnSetSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     webVpnSessionCookie,
		Value:    token,
		Path:     "/",
		Domain:   webVpnCookieDomain(r),
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

func webVpnCurrentUser(r *http.Request) (*dbdata.User, bool) {
	cookie, err := r.Cookie(webVpnSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	return webVpnUserFromToken(cookie.Value)
}

// jwtInt64 兼容 JWT 解析后数字字段的多种类型（float64 / int64 / json.Number / string），
// 避免依赖具体类型断言导致整用户踢出阈值等关键逻辑失效。
func jwtInt64(data map[string]any, key string) int64 {
	switch v := data[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

func webVpnUserFromToken(token string) (*dbdata.User, bool) {
	data, err := admin.GetJwtData(token)
	if err != nil {
		base.Warn("DEBUG webVpnUserFromToken: GetJwtData err=", err)
		return nil, false
	}
	username, _ := data["webvpn_user"].(string)
	if username == "" {
		return nil, false
	}

	// 整用户踢出阈值：该时间戳及之前签发的会话一律视为已吊销
	if iat := jwtInt64(data, "iat"); iat > 0 {
		before := dbdata.WebVpnRevokeBeforeOf(username)
		if before > 0 && iat <= before {
			return nil, false
		}
	}

	// 绝对寿命上限：会话自首次登录（webvpn_issued）起算，超过上限强制重新登录，
	// 即使持续活跃、不断滑动续期也会到期。无锚点（旧 token）按 iat 兜底。
	if issued := jwtInt64(data, "webvpn_issued"); issued > 0 {
		if max := webVpnSessionMaxLifetime(); max > 0 {
			if time.Since(time.Unix(issued, 0)) > max {
				return nil, false
			}
		}
	}

	// 解析得到基础 user（缓存优先，未命中回查 DB）；组在下方统一按 token 注入。
	var user *dbdata.User
	webVpnUserCacheMu.Lock()
	if e, ok := webVpnUserCache[username]; ok && e.expire.After(time.Now()) {
		user = e.user
		webVpnUserCacheMu.Unlock()
		if user == nil || user.Status != 1 {
			return nil, false
		}
	} else {
		webVpnUserCacheMu.Unlock()
		u := &dbdata.User{}
		if err := dbdata.One("Username", username, u); err != nil || u.Status != 1 {
			webVpnUserCacheMu.Lock()
			webVpnUserCache[username] = &webVpnUserCacheEntry{user: nil, expire: time.Now().Add(webVpnUserCacheTTL)}
			webVpnUserCacheMaybeClean(time.Now())
			webVpnUserCacheMu.Unlock()
			return nil, false
		}
		webVpnUserCacheMu.Lock()
		webVpnUserCache[username] = &webVpnUserCacheEntry{user: u, expire: time.Now().Add(webVpnUserCacheTTL)}
		webVpnUserCacheMaybeClean(time.Now())
		webVpnUserCacheMu.Unlock()
		user = u
	}

	// 会话令牌携带的组用于应用组授权。组随每次请求 token 重新解析，不写入缓存 user，避免不同 token 的组在缓存命中时被串。
	if g, ok := data["webvpn_groups"]; ok {
		var gs []string
		switch v := g.(type) {
		case []string:
			gs = v
		case []any:
			gs = make([]string, 0, len(v))
			for _, it := range v {
				if s, ok := it.(string); ok {
					gs = append(gs, s)
				}
			}
		case string:
			if v != "" {
				gs = strings.Split(v, ",")
			}
		}
		if len(gs) > 0 {
			u2 := *user
			u2.Groups = gs
			return &u2, true
		}
	}
	return user, true
}

// 从数据库重新加载用户当前状态
// 用于会话续期时以服务端权威数据重新签发，避免沿用 token 内固化的旧权限快照。用户不存在或已禁用时返回 nil。
func webVpnFreshUser(username string) *dbdata.User {
	if username == "" {
		return nil
	}
	u := &dbdata.User{}
	if err := dbdata.One("Username", username, u); err != nil || u.Status != 1 {
		return nil
	}
	return u
}

// 若用户持有门户 portal_session 但无 webvpn_session，
// 则兑换签发独立 WebVPN 会话。用于首次访问免重复登录。
func webVpnExchangeFromPortal(r *http.Request) (*dbdata.User, string, bool) {
	pc, e := r.Cookie(portalCookieName)
	if e != nil || pc.Value == "" {
		return nil, "", false
	}
	puser, ok := portalCurrentUser(r)
	if !ok || puser == nil {
		return nil, "", false
	}
	token, err := webVpnIssueSession(nil, r, puser, 0)
	if err != nil {
		return nil, "", false
	}
	return puser, token, true
}

func webVpnSessionClaims(r *http.Request) (jti string, iat, exp int64, ok bool) {
	cookie, err := r.Cookie(webVpnSessionCookie)
	if err != nil || cookie.Value == "" {
		return "", 0, 0, false
	}
	data, err := admin.GetJwtData(cookie.Value)
	if err != nil {
		return "", 0, 0, false
	}
	jti, _ = data["jti"].(string)
	iat = jwtInt64(data, "iat")
	exp = jwtInt64(data, "exp")
	if jti == "" {
		return "", 0, 0, false
	}
	return jti, iat, exp, true
}

// 取当前请求的 WebVPN 会话 token claims（未登录/解析失败返回 nil）。
func getWebVpnTokenClaims(r *http.Request) map[string]any {
	cookie, err := r.Cookie(webVpnSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil
	}
	data, err := admin.GetJwtData(cookie.Value)
	if err != nil {
		return nil
	}
	return data
}

// 吊销当前请求的 WebVPN 会话（单点登出）。
func webVpnRevokeCurrentSession(r *http.Request) {
	if jti, _, exp, ok := webVpnSessionClaims(r); ok {
		admin.RevokeJwt(jti, exp)
	}
}

// 整用户踢出（管理后台"全量登出"）。
// 通过吊销阈值实现 O(1)：将该用户名对应的阈值设为当前时间，此前签发的会话立即失效。
func webVpnRevokeAllForUser(username string) {
	dbdata.WebVpnRevokeUser(username)
	// 清该用户缓存，避免命中旧 user
	webVpnUserCacheMu.Lock()
	delete(webVpnUserCache, username)
	webVpnUserCacheMu.Unlock()
}

// 清除客户端 webvpn_session cookie。
func webVpnClearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     webVpnSessionCookie,
		Value:    "",
		Path:     "/",
		Domain:   webVpnCookieDomain(r),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// 取 TCP 连接的 RemoteAddr 为准，不信任客户端伪造的 X-Forwarded-For：
// WebVPN 反代作为直接入口，审计与来源 IP 白名单必须基于真实连接，避免伪造 XFF 绕过限制。
func webVpnRealClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// 从 Host 提取 WebVPN 子域名前缀。
// 命中 *.WebVpnDomain 返回前缀；否则返回 ""（非 WebVPN 请求）。
// DNS 主机名大小写不敏感，统一转小写比较，避免 `Host: APP.WV.EXAMPLE.COM` 等大写写法
// 绕过 WebVPN 分支落入主路由（审计/授权/代理边界被跳过）。
func webVpnHostPrefix(host string) string {
	domain := base.GetCfg().WebVpnDomain
	if domain == "" {
		return ""
	}
	host = strings.ToLower(stripPort(host))
	domain = strings.ToLower(domain)
	// 必须 .domain 结尾，且前缀非空、不含点（子域名只一层）
	if !strings.HasSuffix(host, "."+domain) {
		return ""
	}
	prefix := strings.TrimSuffix(host, "."+domain)
	if prefix == "" || strings.Contains(prefix, ".") {
		return ""
	}
	return prefix
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// 从 host:port 取出端口部分，无端口返回 ""。
// 用于自定义端口（如 :8443）场景，保证跳转链接/登录回跳沿用用户真实端口。
func portOf(host string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		return port
	}
	return ""
}

// Unwrap 透出底层 writer，保证 http.NewResponseController 正常工作；
// 同时记录状态码与写出字节数供访问审计使用。
type webVpnRespWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *webVpnRespWriter) WriteHeader(code int) {
	if rw.statusCode == 0 {
		rw.statusCode = code
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *webVpnRespWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func (rw *webVpnRespWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func webVpnCookieDomain(r *http.Request) string {
	return portalCookieDomain(r)
}

// WebVPN 分支入口：*.WebVpnDomain 请求在此处理，不进入 initRoute（避免被全局安全头污染）。
// 非 WebVPN 请求返回 false，由调用方 delegate 回主路由。
func WebVpnHandler(w http.ResponseWriter, r *http.Request) bool {
	prefix := webVpnHostPrefix(r.Host)
	if prefix == "" {
		return false
	}
	// WebVPN 自有端点（/webvpn/*，如登录/登出/me）不走代理，交由 initRoute 处理
	if strings.HasPrefix(r.URL.Path, "/webvpn/") {
		return false
	}
	// 门户静态资源（/ui/*）必须放行：WebVPN 登录卡片前端由此加载
	if strings.HasPrefix(r.URL.Path, "/ui/") {
		return false
	}
	// 门户相关路径一律禁止在 WebVPN 子域下访问：
	// 子域请求会带上 .WebVpnDomain 通配的 portal_session cookie，若放行到门户路由，可越权调用门户
	// 接口（跨子域 CSRF）。仅放行：
	//   - GET /portal（登录页壳，只读，未登录时 redirect 302 到这里）；
	//   - 登录前置接口（未登录状态下登录流程必需，不依赖已登录 portal_session，
	//     放行不会构成越权）：账号密码/短信/OTP 登录、登录配置、me 登录态检测。
	// 其余 /portal 任意路径、任意方法（含非 GET 的精确 /portal，以及 logout/change_password/
	// devices/offline/certs 等已登录才用到的写接口）一律 403，不 delegate、不反代。
	if r.URL.Path == "/portal" && r.Method == http.MethodGet {
		return false
	}
	if r.URL.Path == "/portal" || strings.HasPrefix(r.URL.Path, "/portal/") {
		if webVpnPortalLoginEndpoint(r.URL.Path, r.Method) {
			return false
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
		return true
	}
	webVpnProxy(w, r, prefix)
	return true
}

// 描述一个「子域名可放行的门户登录前置接口」。
// 这类接口仅在未登录状态下登录流程必需、且不依赖已登录 portal_session，
// 放行它们保证 WebVPN 子域名登录页可正常加载配置、完成登录并检测登录态；
// 其余门户写接口（登出/改密/设备/证书等）仍由 WebVpnHandler 403 拦截，杜绝越权。
type portalLoginEndpoint struct {
	path    string
	method  string
	handler func(http.ResponseWriter, *http.Request)
}

// 是 WebVPN 子域名登录所放行的门户接口唯一来源：
// initRoute 据此注册路由（见 server.go），WebVpnHandler 据此判断放行（webVpnPortalLoginEndpoint）。
// 新增子域名登录必需的门户接口只需改此处。
var portalLoginEndpoints = []portalLoginEndpoint{
	{"/portal/api/login", http.MethodPost, PortalLogin},
	{"/portal/api/verify", http.MethodPost, PortalVerify},
	{"/portal/api/sms/send", http.MethodPost, PortalSmsSend},
	{"/portal/api/sms/verify", http.MethodPost, PortalSmsVerify},
	{"/portal/api/login-config", http.MethodGet, PortalLoginConfig},
	{"/portal/api/me", http.MethodGet, PortalMe},
	{"/portal/api/otp/status", http.MethodGet, PortalOTPStatus},
	{"/portal/api/sso", http.MethodGet, PortalSSO},
}

// 判断子域名下是否放行某门户登录接口（以 portalLoginEndpoints 为唯一来源）。
func webVpnPortalLoginEndpoint(path, method string) bool {
	for _, ep := range portalLoginEndpoints {
		if ep.path == path && ep.method == method {
			return true
		}
	}
	return false
}

func webVpnProxy(w http.ResponseWriter, r *http.Request, prefix string) {
	rw := &webVpnRespWriter{ResponseWriter: w}
	start := time.Now()
	var auditUser string
	var auditGroup string

	// 所有早退路径都在请求结束时投递一条审计记录
	defer func() {
		webVpnAuditLog(dbdata.WebVpnAudit{
			Username:   auditUser,
			GroupName:  auditGroup,
			AppName:    prefix,
			Host:       r.Host,
			Method:     r.Method,
			Path:       r.URL.Path,
			StatusCode: rw.statusCode,
			BytesSent:  rw.bytesWritten,
			ClientIP:   webVpnRealClientIP(r),
			DurationMs: time.Since(start).Milliseconds(),
			RiskLevel:  webVpnAuditRisk(rw.statusCode),
		})
	}()

	// 超时豁免：WebVPN 反代可能承载 >100s 的流式下载/大文件上传/WebSocket，
	// 清除 server 级 100s Read/Write deadline（Go 1.20+ ResponseController）。
	rc := http.NewResponseController(rw)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})

	// 查应用配置（带缓存）
	app, err := dbdata.GetWebVpnAppByName(prefix)
	if err != nil || app == nil {
		webVpnAppErrorPage(rw, r, prefix, "notfound", "应用不存在或已被删除")
		return
	}
	if app.Status != 1 {
		webVpnAppErrorPage(rw, r, prefix, "disabled", "应用已停用")
		return
	}

	// 优先 WebVPN 独立会话；无 webvpn_session 但持有 portal_session 时自动兑换并种回（门户点卡片免重复登录）
	user, ok := webVpnCurrentUser(r)
	if !ok || user == nil {
		if exUser, exToken, exOk := webVpnExchangeFromPortal(r); exOk {
			webVpnSetSessionCookie(rw, r, exToken)
			user = exUser
			ok = true
		}
	}
	if !ok || user == nil {
		redirectToWebVpnLogin(rw, r)
		return
	}
	auditUser = user.Username
	if len(user.Groups) > 0 {
		auditGroup = user.Groups[0]
	}

	// 授权校验
	if !webVpnAuthorized(app, user, r) {
		webVpnForbiddenPage(rw, r, user.Username, app.Name)
		return
	}

	// 滑动续期：距签发已超过 TTL-1h（即剩余 <1h）时重签并刷新 cookie。
	// 续期以数据库当前用户状态为准重新签发，避免 token 内固化的旧组/权限快照被无限延续。
	// 绝对寿命上限：从首次登录（webvpn_issued）起算，超过则不再续期、强制重新登录
	if jti, iat, _, claimsOk := webVpnSessionClaims(r); claimsOk && jti != "" && iat > 0 {
		if time.Since(time.Unix(iat, 0)) > webVpnSessionTTL()-time.Hour {
			issued := jwtInt64(getWebVpnTokenClaims(r), "webvpn_issued")
			if fresh := webVpnFreshUser(user.Username); fresh != nil {
				user = fresh
			}
			_, _ = webVpnIssueSession(rw, r, user, issued) // cookie 已写入 rw
		}
	}

	target, err := url.Parse(app.Backend)
	if err != nil {
		base.Error("WebVPN 后端地址解析失败:", app.Backend, err)
		http.Error(rw, "后端配置错误", http.StatusBadGateway)
		return
	}

	proxy := &httputil.ReverseProxy{
		// 后端为自签/内网证书时跳过 TLS 校验（仅当后端是 https 且应用开启 SkipVerify）。
		Transport: webVpnBackendTransport(app.SkipVerify && target.Scheme == "https"),
		Director: func(req *http.Request) {
			// 入站头清洗：完全剥掉客户端伪造的 X-Forwarded-*/X-Real-IP。
			// 注意：不要手动 Set X-Forwarded-For —— httputil.ReverseProxy 会在发送时
			// 自动把真实客户端 IP 追加到该头，从而后端只看到真实来源，不会被伪造值污染。
			// 同时剥掉客户端伪造的 X-RemLink-WebVpn（否则攻击者可直接给自己打标“来自可信网关”，
			// 若后端据此放宽鉴权则会绕过）。该头由下方统一注入，客户端无法伪造。
			req.Header.Del("X-Forwarded-For")
			req.Header.Del("X-Forwarded-Proto")
			req.Header.Del("X-Forwarded-Host")
			req.Header.Del("X-Real-IP")
			req.Header.Del("X-RemLink-WebVpn")

			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			// 子域名方案下相对链接天然正确，仅重写 Host 头为后端；
			// 若应用配置了 HostRewrite 则优先用其覆盖（部分后端按 Host 虚拟主机分发）。
			if app.HostRewrite != "" {
				req.Host = app.HostRewrite
			} else {
				req.Host = target.Host
			}
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Forwarded-Host", r.Host)
			// 删除 RemLink 自有会话 cookie（portal_session/webvpn_session）
			req.Header.Set("Cookie", stripRemLinkCookies(r.Cookies()))
			req.Header.Set("X-RemLink-WebVpn", "1")
		},
		ModifyResponse: func(resp *http.Response) error {
			// 302 等 Location 指向后端地址时，改写回子域名。
			// 仅当 Location 的主机与后端主机一致或是其后缀子域（如 back.internal / app.back.internal）
			// 才改写；用精确/后缀匹配而非子串包含，避免把 badexample.com.evil.org 之类误判为后端地址。
			loc := resp.Header.Get("Location")
			if loc != "" {
				if u, e := url.Parse(loc); e == nil && u.Host != "" {
					if webVpnHostMatchesBackend(u.Host, target.Host) {
						u.Host = r.Host
						resp.Header.Set("Location", u.String())
					}
				}
			}
			// 后端下发的 Set-Cookie 若带 Domain 指向后端主机，浏览器会拒绝在子域上
			// 存储该 cookie，导致应用登录态丢失。把 Domain 属性（指向后端）剥离，
			// 让浏览器按当前 WebVPN 子域名存储，从而应用自身的登录会话得以保持。
			webVpnScrubSetCookieDomain(resp, target.Host)
			// 不继承任何全局安全头（被代理响应不应带 COEP/CORP require-corp 等）
			resp.Header.Del("Content-Security-Policy")
			resp.Header.Del("Cross-Origin-Embedder-Policy")
			resp.Header.Del("Cross-Origin-Resource-Policy")
			resp.Header.Del("X-Frame-Options")
			return nil
		},
		ErrorHandler: func(ew http.ResponseWriter, req *http.Request, e error) {
			// 客户端在响应返回前主动断开（回跳/导航/页面卸载等）会触发 context.Canceled
			if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) ||
				strings.Contains(e.Error(), "client disconnected") ||
				strings.Contains(e.Error(), "connection reset by peer") {
				base.Info("WebVPN 反代中断（客户端取消）:", app.Name, e)
			} else {
				base.Error("WebVPN 反代错误:", app.Name, e)
			}
			ew.WriteHeader(http.StatusBadGateway)
			ew.Write([]byte("WebVPN 后端连接失败"))
		},
	}
	proxy.ServeHTTP(rw, r)
}

// 从客户端请求里删除 RemLink 自有会话 cookie（remLinkSessionCookies 清单）。
// 避免把网关的 portal_session / webvpn_session / auth-session-id / acSamlv2Token 等令牌
// 透传给被代理的内网后端。
func stripRemLinkCookies(cookies []*http.Cookie) string {
	drop := make(map[string]bool, len(remLinkSessionCookies))
	for _, n := range remLinkSessionCookies {
		drop[n] = true
	}
	var kept []*http.Cookie
	for _, c := range cookies {
		if drop[c.Name] {
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return ""
	}
	var b strings.Builder
	for i, c := range kept {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.Name)
		b.WriteString("=")
		b.WriteString(c.Value)
	}
	return b.String()
}

// 清洗后端响应 Set-Cookie 头里的 Domain 属性。
// 若 Domain 指向后端主机（target.Host），浏览器会因「响应来自子域、Domain 却指向
// 别的域」而拒绝存储该 cookie，直接导致应用登录态存不下来。剥离该 Domain 后，
// 浏览器按当前 WebVPN 子域名存储应用自身的会话 cookie，登录态得以保持。
// 注意：只处理指向后端主机的 Domain，应用若显式下发其它合法 Domain 不受影响。
func webVpnScrubSetCookieDomain(resp *http.Response, backendHost string) {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")
	bh := strings.ToLower(stripPort(backendHost))
	for _, c := range cookies {
		// 找 Domain= 片段（大小写不敏感、允许前导点）
		idx := strings.Index(c, "Domain=")
		if idx < 0 {
			resp.Header.Add("Set-Cookie", c)
			continue
		}
		// 取 domain 值（到下一个 ; 或结尾）
		rest := c[idx+len("Domain="):]
		end := strings.IndexByte(rest, ';')
		dom := rest
		tail := ""
		if end >= 0 {
			dom = rest[:end]
			tail = rest[end:]
		}
		d := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(dom, ".")))
		if d != "" && (strings.EqualFold(d, bh) || strings.HasSuffix(bh, "."+d)) {
			// 命中后端主机：删掉整个 Domain=... 片段（含值，保留后续 ; 与属性）
			c = strings.TrimRight(c[:idx], " ") + tail
			c = strings.TrimSpace(strings.TrimSuffix(c, ";"))
		}
		resp.Header.Add("Set-Cookie", c)
	}
}

// 判断 Location 主机是否应改写为 WebVPN 子域：仅当它指向后端主机（相等或是其后缀子域）时改写。
// 用「相等或 .backend 后缀」精确匹配，避免 strings.Contains 把 badexample.com.evil.org
// 这类包含后端主机的无关域名误判。host 可带端口，比较时剥离；大小写不敏感。
func webVpnHostMatchesBackend(locHost, backendHost string) bool {
	lh := strings.ToLower(stripPort(locHost))
	bh := strings.ToLower(stripPort(backendHost))
	if lh == "" || bh == "" {
		return false
	}
	if lh == bh {
		return true
	}
	// 后缀子域匹配，须以 . 边界分隔，避免 IP 尾缀误配（如 10.0.0.50 不应命中 10.0.0.5）
	return strings.HasSuffix(lh, "."+bh)
}

// skipVerify 为真（且后端为 https）时跳过对端证书校验，用于后端使用自签/内网证书的场景。
func webVpnBackendTransport(skipVerify bool) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if skipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport
}

// 校验用户/组/IP/路径白名单
func webVpnAuthorized(app *dbdata.WebVpnApp, user *dbdata.User, r *http.Request) bool {
	// 用户/组白名单：空=全部用户/不限组
	if !dbdata.WebVpnUserAllowed(app, user) {
		return false
	}
	// 来源 IP 白名单：空=不限制
	if len(app.IpAllowList) > 0 {
		ip := net.ParseIP(webVpnRealClientIP(r))
		if ip == nil {
			return false
		}
		if !ipInAllowList(ip, app.IpAllowList) {
			return false
		}
	}
	// 路径前缀白名单：空=全部路径
	if len(app.AllowPath) > 0 {
		ok := false
		for _, p := range app.AllowPath {
			if strings.HasPrefix(r.URL.Path, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// 未登录时 302 到门户登录页（WebVPN 登录入口复用门户登录 UI），带 redirect 回跳。
func redirectToWebVpnLogin(w http.ResponseWriter, r *http.Request) {
	// redirect 只存路径（不含 host），登录成功后由前端基于 window.location.origin 自动补全
	redirect := url.QueryEscape(r.URL.RequestURI())
	loginURL := "/portal?redirect=" + redirect
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func ipInAllowList(ip net.IP, list []string) bool {
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			_, cidr, err := net.ParseCIDR(item)
			if err == nil && cidr.Contains(ip) {
				return true
			}
			continue
		}
		if ip.String() == item {
			return true
		}
	}
	return false
}

// 当前登录入口复用门户登录页，仅返回前端所需子域等基础配置；供未来独立登录页使用。
func webVpnLoginConfig(w http.ResponseWriter, r *http.Request) {
	portalOK(w, map[string]any{
		"domain": base.GetCfg().WebVpnDomain,
	})
}

// 在 WebVPN 子域本地渲染「无权限」错误页。
func webVpnForbiddenPage(w http.ResponseWriter, _ *http.Request, username, appName string) {
	msg := "您当前没有访问该应用的权限，如需开通请联系系统管理员。"
	if username != "" {
		msg = username + "，您当前没有访问「" + appName + "」的权限，如需开通请联系系统管理员。"
	}
	webVpnErrorHTML(w, webVpnErrorData{
		Reason:   "forbidden",
		Title:    "无权访问该应用",
		Subtitle: msg,
		AppName:  appName,
	})
}

// 应用不存在/已禁用时，同样在 WebVPN 子域本地渲染错误页（认证前即可命中）。
// reason 取值：notfound（不存在，返回 404）/ disabled（已禁用，返回 403）。
func webVpnAppErrorPage(w http.ResponseWriter, _ *http.Request, appName, reason, msg string) {
	title := "应用不存在"
	status := http.StatusNotFound
	if reason == "disabled" {
		title = "应用已停用"
		status = http.StatusForbidden
	}
	webVpnErrorHTML(w, webVpnErrorData{
		Reason:     reason,
		Title:      title,
		Subtitle:   msg,
		AppName:    appName,
		StatusCode: status,
	})
}

// 错误页模板数据。
type webVpnErrorData struct {
	Reason     string // forbidden / notfound / disabled
	Title      string
	Subtitle   string
	AppName    string // 子域前缀，空则不展示
	StatusCode int    // 0 时回退 403
}

// 在 WebVPN 子域本地渲染错误页
func webVpnErrorHTML(w http.ResponseWriter, data webVpnErrorData) {
	if data.Title == "" {
		data.Title = "无法访问"
	}
	if data.Subtitle == "" {
		data.Subtitle = "无权访问该应用"
	}
	if data.StatusCode == 0 {
		data.StatusCode = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(data.StatusCode)
	if err := webVpnErrorTmpl.Execute(w, data); err != nil {
		base.Error("WebVPN 错误页渲染失败:", err)
	}
}

// 错误页模板：深色渐变背景 + 居中卡片，风格对齐门户登录页。
// reason 决定图标与强调色：forbidden=橙色锁、notfound/disabled=灰蓝。自适应明暗（prefers-color-scheme）。
var webVpnErrorTmpl = template.Must(template.New("webvpnError").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{--accent:{{if eq .Reason "forbidden"}}#f59e0b{{else}}#5b7ca8{{end}};--accent-bg:{{if eq .Reason "forbidden"}}rgba(245,158,11,.14){{else}}rgba(91,124,168,.16){{end}};}
*{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
  background:linear-gradient(135deg,#1b2138 0%,#2a3a5c 40%,#1a3668 100%);
  color:#e6ebf5;
}
.card{
  width:100%;max-width:440px;background:rgba(30,38,60,.72);
  border:1px solid rgba(255,255,255,.08);border-radius:16px;
  box-shadow:0 20px 60px rgba(0,0,0,.35),0 0 0 1px rgba(255,255,255,.04);
  backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
  padding:44px 36px 36px;text-align:center;
}
.icon{
  width:76px;height:76px;margin:0 auto 24px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;
  background:var(--accent-bg);color:var(--accent);
}
.icon svg{width:38px;height:38px;}
h1{font-size:22px;font-weight:600;color:#fff;margin-bottom:12px;letter-spacing:.5px;}
.sub{font-size:14px;line-height:1.7;color:#a9b4c9;margin-bottom:8px;word-break:break-all;}
{{if .AppName}}.app{
  display:inline-block;margin-top:18px;padding:6px 14px;border-radius:8px;
  font-size:13px;color:#cbd5e8;background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.08);
}
.app b{color:var(--accent);font-weight:600;}{{end}}
.foot{margin-top:28px;padding-top:20px;border-top:1px solid rgba(255,255,255,.07);font-size:12px;color:#6b7793;}
</style>
</head>
<body>
<div class="card">
  <div class="icon">
    {{if eq .Reason "forbidden"}}
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    {{else}}
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    {{end}}
  </div>
  <h1>{{.Title}}</h1>
  <p class="sub">{{.Subtitle}}</p>
  {{if .AppName}}<div class="app">应用：<b>{{.AppName}}</b></div>{{end}}
  <div class="foot">RemLink WebVPN 安全网关</div>
</div>
</body>
</html>`))

// 供门户"我的应用"展示，返回当前用户有权访问的 WebVPN 应用列表（含跳转 URL），点击直接跳转到对应子域。
func webVpnMyApps(w http.ResponseWriter, r *http.Request) {
	// WebVPN 应用列表同时服务于两种场景：
	//  1) 已登录 WebVPN 会话（webvpn_session）的用户；
	//  2) 在门户域已登录（portal_session）的用户，门户首页“我的应用”卡片需要展示。
	// webvpn_session 优先，缺失时回退门户会话。
	user, ok := webVpnCurrentUser(r)
	if !ok || user == nil {
		user, ok = portalCurrentUser(r)
		if !ok || user == nil {
			portalError(w, "未登录")
			return
		}
	}
	apps, err := dbdata.WebVpnAppsForUser(user)
	if err != nil {
		portalError(w, "获取应用列表失败")
		return
	}
	domain := base.GetCfg().WebVpnDomain

	host := stripPort(domain)
	port := portOf(domain)
	if port == "" {
		port = portOf(r.Host)
	}
	datas := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		urlStr := ""
		if domain != "" {
			urlStr = "https://" + a.Name + "." + host
			if port != "" {
				urlStr += ":" + port
			}
		}
		datas = append(datas, map[string]any{
			"name": a.Name,
			"note": a.Note,
			"url":  urlStr,
		})
	}
	portalOK(w, datas)
}

func webVpnMe(w http.ResponseWriter, r *http.Request) {
	user, ok := webVpnCurrentUser(r)
	if !ok || user == nil {
		portalError(w, "未登录")
		return
	}
	portalOK(w, map[string]any{
		"username": user.Username,
		"nickname": user.Nickname,
		"type":     user.Type,
		"email":    user.Email,
	})
}

// 单点登出：清除 WebVPN 会话 cookie 并吊销当前 jti。
// 仅影响 WebVPN 访问，门户登录态不受影响。
func webVpnLogout(w http.ResponseWriter, r *http.Request) {
	// CSRF 防护：注销会改变服务端状态，要求请求来源必须是本站域。
	// 浏览器跨站表单/脚本发起的 POST 不会携带与本域匹配的 Origin，从而被拒绝，
	// 避免恶意页面诱导已登录用户强制下线。
	if !webVpnSameOrigin(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	webVpnRevokeCurrentSession(r)
	webVpnClearSessionCookie(w, r)
	portalOK(w, nil)
}

// 校验请求来源是否属于本站域（协议+主机一致）。
// 优先比对 Origin 头（跨站请求才会带、且不可被前端 JS 伪造到其它域）；
// 无 Origin（同源传统表单/同域 fetch）时退化为 Referer 同域校验，均不满足则拒绝。
func webVpnSameOrigin(r *http.Request) bool {
	host := r.Host
	if host == "" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err == nil {
			return strings.EqualFold(u.Host, host) &&
				(u.Scheme == "https" || (u.Scheme == "http" && r.TLS == nil))
		}
		return false
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			return strings.EqualFold(u.Host, host)
		}
		return false
	}
	// 既无 Origin 也无 Referer：同域浏览器原生导航行为，放行。
	return true
}
