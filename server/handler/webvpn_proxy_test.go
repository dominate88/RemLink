package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/wsczx/remlink/admin"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"xorm.io/xorm"
)

// webVpnProxy 的集成测试：用 httptest 起后端，直接调用真实代理代码，
// 覆盖 design-webvpn.md checklist M5 的代理层断言（入站头清洗 / Host 改写 /
// cookie 剥离 / 302 Location 改写 / 安全头剥离 / 502 错误页 / 授权拒绝 /
// 未登录重定向 / 整用户踢出失效）。

var backendSeen struct {
	sync.Mutex
	last *http.Request
}

func setupWebVpnTest(t *testing.T) (backend *httptest.Server, teardown func()) {
	// 配置
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.DbType = "sqlite3"
		c.DbSource = path.Join(t.TempDir(), "webvpn_test.db")
		c.WebVpnDomain = "wv.example.com"
		c.JwtSecret = "unit-test-secret"
	})
	base.ReinitLog() // 初始化日志器，避免 base.Info/Error 在测试中 nil panic

	// 建表
	eng, err := xorm.NewEngine("sqlite3", base.GetCfg().DbSource)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	dbdata.XdbSet(eng)
	if err := eng.Sync2(dbdata.TableModels()...); err != nil {
		t.Fatalf("sync2: %v", err)
	}

	// 后端：记录收到的请求头，并按路径返回特定响应
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendSeen.Lock()
		backendSeen.last = r
		backendSeen.Unlock()

		switch {
		case r.URL.Path == "/redirect":
			http.Redirect(w, r, "http://"+r.Host+"/internal", http.StatusFound)
		case r.URL.Path == "/csp":
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Backend", "hit")
			w.Write([]byte("csp-page"))
		case strings.HasPrefix(r.URL.Path, "/slow"):
			w.WriteHeader(200)
			w.Write([]byte("chunk"))
			// 模拟慢响应：proxy 侧不应被 100s deadline 掐断（此处用短等待验证通道可用）
			time.Sleep(50 * time.Millisecond)
		default:
			w.Header().Set("X-Backend", "hit")
			w.Write([]byte("OK backend"))
		}
	}))

	beURL, _ := url.Parse(backend.URL)

	// 应用：app1 授权给 alice；app2 仅授权给 bob（alice 访问应 403）
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "app1", Backend: beURL.String(), Status: 1, Users: []string{"alice"},
	}))
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "app2", Backend: beURL.String(), Status: 1, Users: []string{"bob"},
	}))
	// appG：仅授权给 ops 组（alice 无该组应 403）
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "appG", Backend: beURL.String(), Status: 1, Users: []string{"alice"}, Groups: []string{"ops"},
	}))
	// appIp：仅允许来源 IP 在 10.0.0.0/8（客户端 203.0.113.9 不在内，应 403）
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "appIp", Backend: beURL.String(), Status: 1, Users: []string{"alice"},
		IpAllowList: []string{"10.0.0.0/8"},
	}))
	// appPath：仅允许路径前缀 /api/（访问 /admin 应 403）
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "appPath", Backend: beURL.String(), Status: 1, Users: []string{"alice"},
		AllowPath: []string{"/api/"},
	}))
	// appHost：反向代理时改写后端 Host 为 backend.internal
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "appHost", Backend: beURL.String(), Status: 1, Users: []string{"alice"},
		HostRewrite: "backend.internal",
	}))
	// 禁用应用：先创建（默认启用），再更新为禁用
	appx := &dbdata.WebVpnApp{Name: "appx", Backend: beURL.String(), Users: []string{"alice"}}
	assert.NoError(t, dbdata.SetWebVpnApp(appx))
	got, err := dbdata.GetWebVpnAppByName("appx")
	assert.NoError(t, err)
	got.Status = 0
	assert.NoError(t, dbdata.SetWebVpnApp(got))

	// 用户
	alice := &dbdata.User{Username: "alice", Type: "local", Status: 1}
	assert.NoError(t, dbdata.Add(alice))
	bob := &dbdata.User{Username: "bob", Type: "local", Status: 1}
	assert.NoError(t, dbdata.Add(bob))

	// 重置跨用例的全局状态，消除用例间相互污染（踢出水位、用户缓存）
	dbdata.WebVpnRevokeReset()
	webVpnUserCacheMu.Lock()
	webVpnUserCache = map[string]*webVpnUserCacheEntry{}
	webVpnUserCacheMu.Unlock()

	// 审计批处理协程：每用例独立启停（日志器已在 base.ReinitLog 初始化后才启动）
	webVpnAuditStart()
	teardown = func() {
		webVpnAuditStop()
		backend.Close()
		eng.Close()
	}
	return backend, teardown
}

// newWebVpnReq 构造一个带 webvpn_session 的代理请求
func newWebVpnReq(t *testing.T, backend *httptest.Server, user, path string) (*http.Request, *httptest.ResponseRecorder) {
	token, err := admin.SetJwtData(map[string]any{
		"webvpn_user":  user,
		"webvpn_type":  "local",
		"webvpn_groups": []string{},
	}, time.Now().Add(3*time.Hour).Unix())
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://app1.wv.example.com"+path, nil)
	req.Host = "app1.wv.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // 伪造，应被清洗
	req.Header.Set("Cookie", "portal_session=fake; theme=dark")
	req.AddCookie(&http.Cookie{Name: webVpnSessionCookie, Value: token})
	// RemoteAddr 模拟客户端来源
	req.RemoteAddr = "203.0.113.9:54321"

	rec := httptest.NewRecorder()
	return req, rec
}

// webVpnReqOpts 构造代理请求的自定义选项
type webVpnReqOpts struct {
	host       string   // 子域名，默认 app1
	user       string   // webvpn_user，默认 alice
	groups     []string // webvpn_groups，默认空
	path       string   // 请求路径，默认 /
	clientIP   string   // RemoteAddr 的 IP 部分，默认 203.0.113.9
	portal     string   // 附加的 portal_session cookie 值（用于兑换测试）
	iatOffset  int64    // 签发 iat 相对现在的偏移（秒），默认 0
	expOffset  int64    // 过期时间相对现在偏移（秒），默认 +3h
	noSession  bool     // 不带 webvpn_session cookie
}

// newWebVpnReqEx 通用请求构造：支持组授权、来源 IP、门户兑换、滑动续期等场景。
func newWebVpnReqEx(t *testing.T, opts webVpnReqOpts) (*http.Request, *httptest.ResponseRecorder, string) {
	if opts.host == "" {
		opts.host = "app1"
	}
	if opts.user == "" {
		opts.user = "alice"
	}
	if opts.path == "" {
		opts.path = "/"
	}
	if opts.clientIP == "" {
		opts.clientIP = "203.0.113.9"
	}
	if opts.expOffset == 0 {
		opts.expOffset = int64((3 * time.Hour).Seconds())
	}

	var rec *httptest.ResponseRecorder
	var req *http.Request
	token := ""
	if !opts.noSession {
		iat := time.Now().Unix() + opts.iatOffset
		exp := time.Now().Unix() + opts.expOffset
		// 直接构造 claims 以精确控制 iat（SetJwtData 内部会覆盖 iat 为 now）
		token = issueWebVpnTokenForTest(t, opts.user, opts.groups, iat, exp)
		req = httptest.NewRequest(http.MethodGet, "https://"+opts.host+".wv.example.com"+opts.path, nil)
		req.AddCookie(&http.Cookie{Name: webVpnSessionCookie, Value: token})
	} else {
		req = httptest.NewRequest(http.MethodGet, "https://"+opts.host+".wv.example.com"+opts.path, nil)
	}
	req.Host = opts.host + ".wv.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")    // 伪造，应被清洗
	req.Header.Set("X-Real-IP", "9.9.9.9")          // 伪造，应被清洗
	// 注意：必须用 AddCookie 追加，不能用 Header.Set("Cookie",...) 覆盖已设置的会话 cookie
	req.AddCookie(&http.Cookie{Name: "theme", Value: "dark"})
	if opts.portal != "" {
		req.AddCookie(&http.Cookie{Name: "portal_session", Value: opts.portal})
	} else {
		req.AddCookie(&http.Cookie{Name: "portal_session", Value: "fake"})
	}
	req.RemoteAddr = opts.clientIP + ":54321"
	rec = httptest.NewRecorder()
	return req, rec, token
}

// issueWebVpnTokenForTest 直接签发 WebVPN 会话 JWT，可精确控制 iat/exp。
func issueWebVpnTokenForTest(t *testing.T, user string, groups []string, iat, exp int64) string {
	data := map[string]any{
		"webvpn_user":  user,
		"webvpn_type":  "local",
		"webvpn_groups": groups,
		"iat":          iat,
		"exp":          exp,
	}
	tok, err := admin.SetJwtData(data, exp)
	assert.NoError(t, err)
	return tok
}

// issuePortalTokenForTest 签发门户会话 JWT（portal_user/portal_groups），用于兑换测试。
func issuePortalTokenForTest(t *testing.T, user string, groups []string) string {
	data := map[string]any{
		"portal_user":   user,
		"portal_type":   "local",
		"portal_groups": groups,
	}
	tok, err := admin.SetJwtData(data, time.Now().Add(3*time.Hour).Unix())
	assert.NoError(t, err)
	return tok
}

func TestWebVpnProxyRewrite(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()
	beHost := strings.TrimPrefix(backend.URL, "http://")

	req, rec := newWebVpnReq(t, backend, "alice", "/")
	webVpnProxy(rec, req, "app1")

	// 后端应收到改写后的 Host（= 后端地址），而非子域名
	backendSeen.Lock()
	got := backendSeen.last
	backendSeen.Unlock()
	assert.NotNil(t, got, "后端应收到请求")
	assert.Equal(t, beHost, got.Host, "Host 应改写为后端地址")
	// 入站 XFF 被清洗后用真实客户端 IP 重写
	assert.Equal(t, "203.0.113.9", got.Header.Get("X-Forwarded-For"), "XFF 应重写为真实客户端 IP")
	assert.Equal(t, "app1.wv.example.com", got.Header.Get("X-Forwarded-Host"))
	// RemLink 自有会话 cookie（portal_session）不应泄漏给后端，
	// 但应用自身 cookie（如 theme）必须原样转发，否则无法在后端应用内登录。
	assert.NotContains(t, got.Header.Get("Cookie"), "portal_session", "portal_session 不应泄漏给后端")
	assert.Contains(t, got.Header.Get("Cookie"), "theme=dark", "应用自身 cookie 应转发给后端")
	// 代理标记应注入
	assert.Equal(t, "1", got.Header.Get("X-RemLink-WebVpn"))
}

func TestWebVpnProxyLocationRewrite(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec := newWebVpnReq(t, backend, "alice", "/redirect")
	webVpnProxy(rec, req, "app1")

	loc := rec.Result().Header.Get("Location")
	assert.True(t, strings.Contains(loc, "app1.wv.example.com"),
		"302 Location 应改写回子域名，实际: %s", loc)
	assert.False(t, strings.Contains(loc, "127.0.0.1"),
		"Location 不应残留后端地址，实际: %s", loc)
}

func TestWebVpnProxyStripSecurityHeaders(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec := newWebVpnReq(t, backend, "alice", "/csp")
	webVpnProxy(rec, req, "app1")

	assert.Empty(t, rec.Result().Header.Get("Content-Security-Policy"),
		"被代理响应不应继承全局 CSP")
}

func TestWebVpnProxyUnauthorized(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	// alice 不在 app2 的白名单 -> 403
	req, rec := newWebVpnReq(t, backend, "alice", "/")
	req.Host = "app2.wv.example.com"
	webVpnProxy(rec, req, "app2")
	assert.Equal(t, http.StatusForbidden, rec.Code, "未授权用户应 403")
}

func TestWebVpnProxyDisabledApp(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec := newWebVpnReq(t, backend, "alice", "/")
	req.Host = "appx.wv.example.com"
	webVpnProxy(rec, req, "appx")
	assert.Equal(t, http.StatusForbidden, rec.Code, "禁用应用应拒绝")
}

func TestWebVpnProxyUnauthenticated(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	req := httptest.NewRequest(http.MethodGet, "https://app1.wv.example.com/", nil)
	req.Host = "app1.wv.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	webVpnProxy(rec, req, "app1")

	assert.Equal(t, http.StatusFound, rec.Code, "未登录应 302 到登录")
	loc := rec.Result().Header.Get("Location")
	assert.True(t, strings.Contains(loc, "/portal"), "应跳转门户登录，实际: %s", loc)
}

func TestWebVpnProxyBackendDown(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	backend.Close() // 后端立即不可用
	// teardown 仍会调用 backend.Close（幂等）和 eng.Close

	req, rec := newWebVpnReq(t, backend, "alice", "/")
	webVpnProxy(rec, req, "app1")
	assert.Equal(t, http.StatusBadGateway, rec.Code, "后端不可达应 502")
	assert.Contains(t, rec.Body.String(), "后端", "应返回友好错误页")
	teardown()
}

// TestWebVpnProxySkipVerify 验证后端为自签证书时，skip_verify 开启可跳过校验、关闭则 502。
func TestWebVpnProxySkipVerify(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	// 起一个自签证书的 https 后端（httptest.NewTLSServer 使用不被信任的证书）
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tls-ok"))
	}))
	defer tlsBackend.Close()

	// 关闭 skip_verify：证书不受信任，应 502
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "tlsNoSkip", Backend: tlsBackend.URL, Status: 1, Users: []string{"alice"},
	}))
	req, rec := newWebVpnReq(t, backend, "alice", "/")
	req.Host = "tlsnoskip.wv.example.com"
	webVpnProxy(rec, req, "tlsNoSkip")
	assert.Equal(t, http.StatusBadGateway, rec.Code, "自签证书且未开启跳过校验应 502")

	// 开启 skip_verify：应成功反代
	assert.NoError(t, dbdata.SetWebVpnApp(&dbdata.WebVpnApp{
		Name: "tlsSkip", Backend: tlsBackend.URL, Status: 1, Users: []string{"alice"}, SkipVerify: true,
	}))
	req2, rec2 := newWebVpnReq(t, backend, "alice", "/")
	req2.Host = "tlsskip.wv.example.com"
	webVpnProxy(rec2, req2, "tlsSkip")
	assert.Equal(t, http.StatusOK, rec2.Code, "开启跳过校验后自签后端应可访问")
	assert.Equal(t, "tls-ok", rec2.Body.String())
}

func TestWebVpnRevokeAllForUser(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// 踢出 alice 前应可解析
	token, err := admin.SetJwtData(map[string]any{
		"webvpn_user": "alice", "webvpn_type": "local", "webvpn_groups": []string{},
	}, time.Now().Add(3*time.Hour).Unix())
	assert.NoError(t, err)
	u, ok := webVpnUserFromToken(token)
	assert.True(t, ok)
	assert.Equal(t, "alice", u.Username)

	// 整用户踢出
	webVpnRevokeAllForUser("alice")
	u, ok = webVpnUserFromToken(token)
	assert.False(t, ok, "踢出后旧会话应立即失效")
}

// TestWebVpnProxyStripClientIPSpoofing 验证设计 §3 入站头清洗：
// 客户端伪造的 X-Forwarded-For / X-Real-IP 必须被丢弃，后端只收到真实 RemoteAddr。
func TestWebVpnProxyStripClientIPSpoofing(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{})
	webVpnProxy(rec, req, "app1")

	backendSeen.Lock()
	got := backendSeen.last
	backendSeen.Unlock()
	if !assert.NotNil(t, got, "应成功反代到后端") {
		return
	}
	// 真实客户端 IP 来自 RemoteAddr，非伪造值
	assert.Equal(t, "203.0.113.9", got.Header.Get("X-Forwarded-For"), "XFF 应重写为真实客户端 IP")
	assert.Empty(t, got.Header.Get("X-Real-IP"), "伪造的 X-Real-IP 必须被剥离")
	assert.NotContains(t, got.Header.Get("X-Forwarded-For"), "1.2.3.4", "伪造 XFF 不应泄漏")
}

// TestWebVpnProxyStripAllSecurityHeaders 验证设计 §3：后端下发的 4 类跨域约束头全部剥离。
func TestWebVpnProxyStripAllSecurityHeaders(t *testing.T) {
	backend, teardown := setupWebVpnTest(t)
	defer teardown()

	// 临时给后端加一个返回全部安全头的路由
	backend.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendSeen.Lock()
		backendSeen.last = r
		backendSeen.Unlock()
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write([]byte("secure-page"))
	})

	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "app1", path: "/"})
	webVpnProxy(rec, req, "app1")

	h := rec.Result().Header
	assert.Empty(t, h.Get("Content-Security-Policy"), "CSP 应被剥离")
	assert.Empty(t, h.Get("Cross-Origin-Embedder-Policy"), "COEP 应被剥离")
	assert.Empty(t, h.Get("Cross-Origin-Resource-Policy"), "CORP 应被剥离")
	assert.Empty(t, h.Get("X-Frame-Options"), "X-Frame-Options 应被剥离")
}

// TestWebVpnProxyGroupAuthorization 验证设计 §2/§3：组白名单拦截无组用户。
func TestWebVpnProxyGroupAuthorization(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// alice 无 ops 组 → 403
	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appG", groups: []string{"dev"}})
	webVpnProxy(rec, req, "appG")
	assert.Equal(t, http.StatusForbidden, rec.Code, "无授权组的用户应 403")

	// alice 有 ops 组 → 200
	req2, rec2, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appG", groups: []string{"ops"}})
	webVpnProxy(rec2, req2, "appG")
	assert.Equal(t, http.StatusOK, rec2.Code, "命中授权组的用户应放行")
}

// TestWebVpnProxyIpAllowList 验证设计 §3：来源 IP 不在白名单应拒绝。
func TestWebVpnProxyIpAllowList(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// 客户端 203.0.113.9 不在 10.0.0.0/8 → 403
	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appIp", clientIP: "203.0.113.9"})
	webVpnProxy(rec, req, "appIp")
	assert.Equal(t, http.StatusForbidden, rec.Code, "不在 IP 白名单应 403")

	// 客户端 10.1.2.3 在 10.0.0.0/8 → 200
	req2, rec2, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appIp", clientIP: "10.1.2.3"})
	webVpnProxy(rec2, req2, "appIp")
	assert.Equal(t, http.StatusOK, rec2.Code, "命中 IP 白名单应放行")
}

// TestWebVpnProxyPathAllowList 验证设计 §3：路径前缀白名单拦截越权路径。
func TestWebVpnProxyPathAllowList(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// /admin 不在 /api/ 前缀 → 403
	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appPath", path: "/admin"})
	webVpnProxy(rec, req, "appPath")
	assert.Equal(t, http.StatusForbidden, rec.Code, "越权路径应 403")

	// /api/users 命中前缀 → 200
	req2, rec2, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appPath", path: "/api/users"})
	webVpnProxy(rec2, req2, "appPath")
	assert.Equal(t, http.StatusOK, rec2.Code, "命中路径白名单应放行")
}

// TestWebVpnProxySlidingRenewal 验证设计 §2 滑动续期：签名时间过早的会话不被直接拒绝，
// 代理层应放行并续期（此处仅验证放行，续期由 WebVpnHandler 外层完成）。
func TestWebVpnProxySlidingRenewal(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// iat 设为 2 小时前，仍远未到 exp（3h 后），代理层应放行
	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{iatOffset: -2 * 3600})
	webVpnProxy(rec, req, "app1")
	assert.Equal(t, http.StatusOK, rec.Code, "滑动续期：旧但有效的会话应放行")
}

// TestWebVpnProxyHostRewrite 验证设计数据模型 HostRewrite 字段：反代时改写后端 Host。
func TestWebVpnProxyHostRewrite(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "appHost"})
	webVpnProxy(rec, req, "appHost")

	backendSeen.Lock()
	got := backendSeen.last
	backendSeen.Unlock()
	if !assert.NotNil(t, got, "应成功反代到后端") {
		return
	}
	assert.Equal(t, "backend.internal", got.Host, "Host 应改写为 HostRewrite 配置值")
}

// TestWebVpnProxyAppNotFound 验证设计 early-return：访问未配置的子域返回 404。
func TestWebVpnProxyAppNotFound(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "ghost", noSession: true})
	webVpnProxy(rec, req, "ghost")
	assert.Equal(t, http.StatusNotFound, rec.Code, "未配置的应用应 404")
}

// TestWebVpnExchangeFromPortal 验证设计 M3 免重复登录：持门户会话无 webvpn_session 时自动兑换。
func TestWebVpnExchangeFromPortal(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	portalTok := issuePortalTokenForTest(t, "alice", []string{"users"})
	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "app1", noSession: true, portal: portalTok})
	webVpnProxy(rec, req, "app1")

	assert.Equal(t, http.StatusOK, rec.Code, "持门户会话应自动兑换并放行")
	// 应种回 webvpn_session cookie（跨子域 Domain）
	var gotWebVpn bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == webVpnSessionCookie {
			gotWebVpn = true
			assert.Equal(t, "wv.example.com", c.Domain, "会话 cookie 应为跨子域 Domain（前导点被标准库归一化）")
		}
	}
	assert.True(t, gotWebVpn, "应种回 webvpn_session cookie")
}

// TestWebVpnLogoutRevokesSession 验证设计 M3 单点登出：登出后原会话立即失效。
func TestWebVpnLogoutRevokesSession(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	// 先以合法会话通过代理
	req, rec, token := newWebVpnReqEx(t, webVpnReqOpts{host: "app1"})
	webVpnProxy(rec, req, "app1")
	assert.Equal(t, http.StatusOK, rec.Code)

	// 调用单点登出（吊销该会话 jti）
	logoutReq := httptest.NewRequest(http.MethodPost, "/webvpn/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: webVpnSessionCookie, Value: token})
	logoutRec := httptest.NewRecorder()
	webVpnLogout(logoutRec, logoutReq)

	// 用同一会话（被吊销的原 token）再访问 → 应被拒绝（登出后立即失效）
	req2, rec2, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "app1", noSession: true})
	req2.AddCookie(&http.Cookie{Name: webVpnSessionCookie, Value: token})
	webVpnProxy(rec2, req2, "app1")
	assert.NotEqual(t, http.StatusOK, rec2.Code, "登出后原会话应立即失效")
}

// TestWebVpnProxyAuditLogged 验证设计 §6：每次代理请求落一条审计记录（含真实客户端 IP）。
func TestWebVpnProxyAuditLogged(t *testing.T) {
	_, teardown := setupWebVpnTest(t)
	defer teardown()

	req, rec, _ := newWebVpnReqEx(t, webVpnReqOpts{host: "app1", clientIP: "203.0.113.9"})
	webVpnProxy(rec, req, "app1")
	assert.Equal(t, http.StatusOK, rec.Code)

	// 等待审计批处理落库（ticker 1s）
	assert.Eventually(t, func() bool {
		list, _, err := dbdata.WebVpnAuditList(10, 1, dbdata.WebVpnAuditSearch{Username: "alice", AppName: "app1"})
		if err != nil {
			return false
		}
		for _, a := range list {
			if a.ClientIP == "203.0.113.9" && a.StatusCode == 200 {
				return true
			}
		}
		return false
	}, 3*time.Second, 100*time.Millisecond, "审计记录应落库且含真实客户端 IP")
}
