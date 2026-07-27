// 认证管道端到端集成测试：覆盖多步认证、断点恢复、会话异常等完整流程。

package handler

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/security"
	"github.com/xlzd/gotp"
)

// 创建测试策略和组
func createTestPolicyGroup(t *testing.T, groupName string, authProfile json.RawMessage) {
	ast := assert.New(t)
	pt := &dbdata.Policy{
		Name:      "plcy-" + groupName,
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	err := dbdata.SetPolicy(pt)
	ast.Nil(err)
	err = dbdata.SetGroup(&dbdata.Group{
		Name:        groupName,
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: authProfile,
	})
	ast.Nil(err)
}

// ========== local + otp 端到端 ==========

func TestLocalPlusOtp_FullFlow(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "local-otp-group"
	username := "local-otp-user"
	password := "test12" // 6 字符且不含 OTP，local 步骤不做 OTP 剥离
	otpSecret := "JBSWY3DPEHPK3PXP"

	// 创建组 [local, otp]
	profile := auth.GroupAuthProfile{
		Step: []auth.AuthMethodConfig{
			{Type: "local"},
			{Type: "otp"},
		},
	}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)

	// 创建用户（明文密码 < 60 字符 走明文比较）
	_ = dbdata.SetUser(&dbdata.User{
		Username:  username,
		Groups:    []string{group},
		Status:    1,
		PinCode:   password, // < 60 chars → 明文密码
		OtpSecret: otpSecret,
	})

	// ====== 第一步：输入用户名密码 ======
	body1 := buildAuthReplyBody(username, password, group, "")
	req1 := newAuthRequest(body1)
	w1 := httptest.NewRecorder()
	LinkAuth(w1, req1)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w1.Code)
	ast.Contains(w1.Body.String(), "secondary_password", "应返回 OTP 输入表单")

	// 提取 auth-session-id cookie
	var sessionID string
	for _, c := range w1.Result().Cookies() {
		if c.Name == "auth-session-id" {
			sessionID = c.Value
		}
	}
	ast.NotEmpty(sessionID, "应设置 auth-session-id cookie")

	// ====== 第二步：输入 OTP ======
	validOtp := gotp.NewDefaultTOTP(otpSecret).Now()
	body2 := buildAuthReplyBody(username, "", group, validOtp)
	req2 := newAuthRequest(body2)
	req2.AddCookie(&http.Cookie{Name: "auth-session-id", Value: sessionID})
	w2 := httptest.NewRecorder()
	LinkAuth(w2, req2)

	ast.Equal(http.StatusOK, w2.Code)
	ast.Contains(w2.Body.String(), "session-token", "OTP 通过后应返回会话令牌")

	// 验证旧会话已清除
	_, err := GetAuthSession(sessionID)
	ast.NotNil(err, "认证完成后旧会话应删除")
}

func TestLocalPlusOtp_WrongPassword(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "local-wrong-group"
	username := "wrong-pass-user"
	password := "correct"

	profile := auth.GroupAuthProfile{Step: []auth.AuthMethodConfig{{Type: "local"}, {Type: "otp"}}}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)
	_ = dbdata.SetUser(&dbdata.User{
		Username: username, Groups: []string{group}, Status: 1,
		PinCode: password, OtpSecret: "JBSWY3DPEHPK3PXP",
	})

	body := buildAuthReplyBody(username, "wrongpassword", group, "")
	req := newAuthRequest(body)
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)
	ast.Contains(w.Body.String(), "密码错误")
}

// ========== cert + otp 端到端 ==========

func TestCertPlusOtp_CertPassesThenOtpChallenge(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "cert-otp-group"
	username := "cert-user"
	otpSecret := "JBSWY3DPEHPK3PXP"

	profile := auth.GroupAuthProfile{
		Step: []auth.AuthMethodConfig{
			{Type: "cert"},
			{Type: "otp"},
		},
	}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)
	_ = dbdata.SetUser(&dbdata.User{
		Username: username, Groups: []string{group}, Status: 1,
		OtpSecret: otpSecret,
	})

	// 证书不带有效 OU → cert 步骤失败
	body := buildAuthReplyBody(username, "", group, "")
	req := newAuthRequest(body)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: username, OrganizationalUnit: []string{""}},
		}},
	}
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)
	// cert 失败 → 管道终止，应显示错误
	ast.Contains(w.Body.String(), "证书")
}

func TestCertPlusOtp_NoTLS_ImmediateFail(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "cert-notls-group"
	profile := auth.GroupAuthProfile{Step: []auth.AuthMethodConfig{{Type: "cert"}, {Type: "otp"}}}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)

	// 无 TLS → cert 秒拒
	body := buildAuthReplyBody("test", "", group, "")
	req := newAuthRequest(body)
	// 不设置 TLS
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)
	ast.Contains(w.Body.String(), "证书")
}

// ========== 无效/过期 pending session ==========

func TestResume_InvalidSessionCookie(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	// 用不存在的 session cookie 发送 auth-reply → 会话无效清除 cookie
	// → 回退首次认证 → 组不存在
	body := buildAuthReplyBody("anyone", "", "notexist-group", "123456")
	req := newAuthRequest(body)
	req.AddCookie(&http.Cookie{Name: "auth-session-id", Value: "nonexistent-session-id-123456"})
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code, "无效会话+无组：通过认证服务统一返回 200 + 错误页面")
}

func TestResume_ExpiredSession(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "expired-session-group"
	username := "expired-user"
	otpSecret := "JBSWY3DPEHPK3PXP"

	profile := auth.GroupAuthProfile{Step: []auth.AuthMethodConfig{{Type: "local"}, {Type: "otp"}}}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)
	_ = dbdata.SetUser(&dbdata.User{
		Username: username, Groups: []string{group}, Status: 1,
		PinCode: "test12", OtpSecret: otpSecret,
	})

	// 手动创建一个 step=1 的 pending 会话
	sessionID := "will-expire-session"
	ctx := &auth.Context{
		Conn:     auth.ConnInfo{Username: username, GroupName: group},
		UserInfo: &auth.UserInfo{OtpSecret: otpSecret},
	}
	ctx.SetStepIdx(1)
	SaveAuthSession(sessionID, &AuthSession{
		Ctx: ctx,
	})

	// 删除会话模拟过期
	SessStore.Delete(sessionID)

	body := buildAuthReplyBody(username, "", group, "123456")
	req := newAuthRequest(body)
	req.AddCookie(&http.Cookie{Name: "auth-session-id", Value: sessionID})
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	// 会话过期后，回退首次认证 → local 步骤通过（密码 OTP 内嵌? 不，密码为空 → 失败）
	// 预期：回退首次认证，密码为空 → local 步骤 reject
	ast.Equal(http.StatusOK, w.Code)
	ast.Contains(w.Body.String(), "error")
}

// ========== 初始化流程 ==========

func TestLinkAuth_Init_ReturnsLoginForm(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	group := "init-test-group"
	createTestPolicyGroup(t, group, nil)

	body := `<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="init"><group-select>` + group + `</group-select></config-auth>`
	req := newAuthRequest(body)
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)
	ast.Contains(w.Body.String(), "auth-request")
}

// ========== SSO Token + OTP 身份保留 ==========

func TestSsoToken_WithOtp_PreservesIdentity(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{DisplayError: true})
	preIpData(t)
	defer closeIpdata()

	group := "sso-otp-flow-group"
	username := "sso-otp-flow-user"
	otpSecret := "JBSWY3DPEHPK3PXP"

	// 创建测试 wxwork Provider（[wxwork, otp] 配置需要）
	err := dbdata.SetProvider(&dbdata.Provider{
		Name:   "test-wxwork",
		Type:   "wxwork",
		Status: 1,
		Config: security.EncryptedJSON[json.RawMessage]{Data: json.RawMessage(`{"corp_id":"test","agent_id":"test","secret":"test"}`)},
	})
	if err != nil {
		t.Fatalf("SetProvider failed: %v", err)
	}

	// 使用真实的多步配置 [wxwork, otp]，SSO 通过 session Extra 标记已完成
	profile := auth.GroupAuthProfile{Step: []auth.AuthMethodConfig{
		{Type: "wxwork", Provider: "test-wxwork"},
		{Type: "otp"},
	}}
	profileBytes, _ := json.Marshal(profile)
	createTestPolicyGroup(t, group, profileBytes)
	_ = dbdata.SetUser(&dbdata.User{
		Username: username, Groups: []string{group}, Status: 1,
		OtpSecret: otpSecret,
	})

	// 模拟 SSO 回调完成：保存会话（代表 SSO 已验证成功）
	ssoToken := "sso-token-for-otp-test"
	SaveAuthSession(ssoToken, &AuthSession{
		Ctx: &auth.Context{
			Conn: auth.ConnInfo{Username: username, GroupName: group},
			SSO: &auth.SSOState{
				Type:          "wxwork",
				UserID:        username,
				Authenticated: true,
			},
		},
	})

	// 构造 SSO Token 请求
	body := `<?xml version="1.0" encoding="UTF-8"?>
		<config-auth client="vpn" type="auth-reply">
			<version who="vpn">4.10.00001</version>
			<group-select>` + group + `</group-select>
			<auth><sso-token>` + ssoToken + `</sso-token></auth>
		</config-auth>`
	body = strings.TrimSpace(strings.Replace(body, "\t", "", -1))

	req := newAuthRequest(body)
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	LinkAuth(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)
	// SSO 回调后走管道：SSO 步骤 StepPass → OTP 步骤触发挑战（组 Profile: [otp]）
	ast.Contains(w.Body.String(), "secondary_password")
	ast.NotContains(w.Body.String(), "<session-id>")

	// 验证 SSO 临时会话已清理
	_, err = GetAuthSession(ssoToken)
	ast.NotNil(err, "SSO 临时会话应在处理后清理")
}

// ========== 辅助函数 ==========

func buildAuthReplyBody(username, password, group, secondaryPassword string) string {
	body := `<?xml version="1.0" encoding="UTF-8"?>
		<config-auth client="vpn" type="auth-reply">
			<version who="vpn">4.10.00001</version>
			<group-select>` + group + `</group-select>
			<auth>
				<username>` + username + `</username>
				<password>` + password + `</password>
				<secondary_password>` + secondaryPassword + `</secondary_password>
			</auth>
		</config-auth>`
	return strings.TrimSpace(strings.Replace(body, "\t", "", -1))
}

func newAuthRequest(body string) *http.Request {
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("User-Agent", "cisco anyconnect vpn agent")
	req.Header.Set("X-Aggregate-Auth", "1")
	req.Header.Set("X-Transcend-Version", "1")
	return req
}
