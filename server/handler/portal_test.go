package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wsczx/remlink/admin"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// 密码强度校验（纯函数，无需 setup）
// ============================================================

func TestValidatePasswordStrength(t *testing.T) {
	ast := assert.New(t)

	t.Run("ValidPassword", func(t *testing.T) {
		ast.Nil(utils.CheckPasswordPolicy("abcd1234"))
		ast.Nil(utils.CheckPasswordPolicy("ABCD1234"))
		ast.Nil(utils.CheckPasswordPolicy("a1b2c3d4"))
		ast.Nil(utils.CheckPasswordPolicy("Password1"))
	})

	t.Run("TooShort", func(t *testing.T) {
		err := utils.CheckPasswordPolicy("abc1234") // 7 位
		ast.NotNil(err)
		ast.Contains(err.Error(), "不能少于 8 位")
	})

	t.Run("NoDigit", func(t *testing.T) {
		err := utils.CheckPasswordPolicy("abcdefgh")
		ast.NotNil(err)
		ast.Contains(err.Error(), "字母和数字")
	})

	t.Run("NoLetter", func(t *testing.T) {
		err := utils.CheckPasswordPolicy("12345678")
		ast.NotNil(err)
		ast.Contains(err.Error(), "字母和数字")
	})

	t.Run("ChineseChars", func(t *testing.T) {
		// 中文字符不算字母
		err := utils.CheckPasswordPolicy("中文密码1234")
		ast.NotNil(err)
		ast.Contains(err.Error(), "字母和数字")
	})
}

// ============================================================
// Portal 登录
// ============================================================

// 创建 Portal 登录所需的测试数据
func createPortalLoginSetup(t *testing.T, username, password, groupName string) {
	ast := assert.New(t)

	// 创建策略
	pt := &dbdata.Policy{
		Name:      "plcy-" + groupName,
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	err := dbdata.SetPolicy(pt)
	ast.Nil(err)

	// 创建组（仅 local 认证）
	g := &dbdata.Group{
		Name:        groupName,
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	}
	err = dbdata.SetGroup(g)
	ast.Nil(err)

	// 创建用户
	hashedPwd, err := utils.PasswordHash(password)
	ast.Nil(err)
	u := &dbdata.User{
		Username:   username,
		PinCode:    hashedPwd,
		Groups:     []string{groupName},
		Status:     1,
		DisableOtp: true,
	}
	err = dbdata.SetUser(u)
	ast.Nil(err)
}

func TestPortalLogin_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableUserPortal = true })

	createPortalLoginSetup(t, "testuser", "testpass123", "default")
	ast := assert.New(t)

	body := `{"username":"testuser","password":"testpass123"}`
	req := httptest.NewRequest("POST", "/portal/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalLogin(w, req)

	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	ast.Nil(err)
	ast.Equal(float64(0), resp["code"])

	data := resp["data"].(map[string]interface{})
	ast.Equal("pass", data["status"])
	ast.NotEmpty(data["token"])
}

func TestPortalLogin_WrongPassword(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableUserPortal = true })

	createPortalLoginSetup(t, "testuser", "testpass123", "default")
	ast := assert.New(t)

	body := `{"username":"testuser","password":"wrongpassword"}`
	req := httptest.NewRequest("POST", "/portal/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalLogin(w, req)

	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalLogin_UserNotFound(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableUserPortal = true })

	createPortalLoginSetup(t, "testuser", "testpass123", "default")
	ast := assert.New(t)

	body := `{"username":"nonexistent","password":"testpass123"}`
	req := httptest.NewRequest("POST", "/portal/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalLogin(w, req)

	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalLogin_Disabled(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableUserPortal: false})

	body := `{"username":"test","password":"test"}`
	req := httptest.NewRequest("POST", "/portal/login", strings.NewReader(body))
	w := httptest.NewRecorder()

	PortalLogin(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusNotFound, w.Code)
}

// ============================================================
// Portal 修改密码
// ============================================================

// 创建可修改密码的测试用户和相关策略/组，返回 JWT token
func createPortalPwdUser(t *testing.T, username, password string) (*dbdata.User, string) {
	ast := assert.New(t)

	// 确保策略和组存在
	pt := &dbdata.Policy{
		Name:      "plcy-pwd",
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	_ = dbdata.SetPolicy(pt)

	g := &dbdata.Group{
		Name:        "default",
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	}
	_ = dbdata.SetGroup(g)

	hashedPwd, err := utils.PasswordHash(password)
	ast.Nil(err)

	u := &dbdata.User{
		Username:   username,
		PinCode:    hashedPwd,
		Groups:     []string{"default"},
		Status:     1,
		DisableOtp: true,
	}
	err = dbdata.SetUser(u)
	ast.Nil(err)

	token, err := portalIssueToken(u)
	ast.Nil(err)
	return u, token
}

func TestPortalChangePassword_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	_, token := createPortalPwdUser(t, "testuser", "oldpass123")
	ast := assert.New(t)

	body := `{"old_password":"oldpass123","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: portalCookieName, Value: token})
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(w.Body).Decode(&resp)
	ast.Nil(err)
	ast.Equal(float64(0), resp["code"])

	// 验证新密码可以登录
	loginBody := `{"username":"testuser","password":"newpass123"}`
	loginReq := httptest.NewRequest("POST", "/portal/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	PortalLogin(loginW, loginReq)

	var loginResp map[string]interface{}
	json.NewDecoder(loginW.Body).Decode(&loginResp)
	ast.Equal(float64(0), loginResp["code"])
}

func TestPortalChangePassword_WrongOldPassword(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	_, token := createPortalPwdUser(t, "testuser", "correctpass1")
	ast := assert.New(t)

	body := `{"old_password":"wrongoldpass","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: portalCookieName, Value: token})
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
	ast.Contains(resp["msg"], "旧密码错误")
}

func TestPortalChangePassword_WeakNewPassword(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	_, token := createPortalPwdUser(t, "testuser", "oldpass123")
	ast := assert.New(t)

	// 纯数字，不包含字母
	body := `{"old_password":"oldpass123","new_password":"12345678"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: portalCookieName, Value: token})
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalChangePassword_TooShort(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	_, token := createPortalPwdUser(t, "testuser", "oldpass123")
	ast := assert.New(t)

	// 仅 6 位
	body := `{"old_password":"oldpass123","new_password":"abc123"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: portalCookieName, Value: token})
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalChangePassword_Unauthorized(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableUserPortal = true })

	body := `{"old_password":"old","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusUnauthorized, w.Code)
}

func TestPortalChangePassword_ExternalUser(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	ast := assert.New(t)

	// 确保默认组存在
	pt := &dbdata.Policy{
		Name:      "plcy-ext",
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	_ = dbdata.SetPolicy(pt)
	_ = dbdata.SetGroup(&dbdata.Group{
		Name:        "default",
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	})

	// 创建 LDAP 类型用户
	u := &dbdata.User{
		Username: "ldapuser",
		PinCode:  "notused",
		Type:     "ldap",
		Groups:   []string{"default"},
		Status:   1,
	}
	err := dbdata.SetUser(u)
	ast.Nil(err)

	token, err := portalIssueToken(u)
	ast.Nil(err)

	body := `{"old_password":"old","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/change_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: portalCookieName, Value: token})
	w := httptest.NewRecorder()

	PortalChangePassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
	ast.Contains(resp["msg"], "外部认证")
}

// ============================================================
// Portal 重置密码
// ============================================================

func TestPortalResetPassword_InvalidToken(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	ast := assert.New(t)

	body := `{"token":"invalid-token","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/reset_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalResetPassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalResetPassword_EmptyFields(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableUserPortal: true})

	ast := assert.New(t)

	// 空 token
	body := `{"token":"","new_password":"newpass123"}`
	req := httptest.NewRequest("POST", "/portal/reset_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalResetPassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.NotEqual(float64(0), resp["code"])
}

func TestPortalResetPassword_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	base.UpdateCfg(func(c *base.ServerConfig) {
		c.EnableUserPortal = true
		c.JwtSecret = "test-jwt-secret-for-portal-32b"
	})

	ast := assert.New(t)

	// 创建策略和组
	pt := &dbdata.Policy{
		Name:      "plcy-reset",
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	err := dbdata.SetPolicy(pt)
	ast.Nil(err)

	g := &dbdata.Group{
		Name:        "default",
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	}
	err = dbdata.SetGroup(g)
	ast.Nil(err)

	// 创建用户
	hashedPwd, _ := utils.PasswordHash("oldpass123")
	u := &dbdata.User{
		Username:   "resetuser",
		PinCode:    hashedPwd,
		Groups:     []string{"default"},
		Status:     1,
		DisableOtp: true,
	}
	err = dbdata.SetUser(u)
	ast.Nil(err)

	// 生成重置 token
	token, err := admin.SetJwtData(map[string]interface{}{
		"purpose": "portal_reset_password",
		"user_id": float64(u.Id),
		"jti":     "test-jti-123",
	}, 9999999999)
	ast.Nil(err)

	// 重置密码
	body := `{"token":"` + token + `","new_password":"newpass456"}`
	req := httptest.NewRequest("POST", "/portal/reset_password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	PortalResetPassword(w, req)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal(float64(0), resp["code"])

	// 验证新密码可以登录
	loginBody := `{"username":"resetuser","password":"newpass456"}`
	loginReq := httptest.NewRequest("POST", "/portal/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	PortalLogin(loginW, loginReq)

	var loginResp map[string]interface{}
	json.NewDecoder(loginW.Body).Decode(&loginResp)
	ast.Equal(float64(0), loginResp["code"], "should login with new password")
}

// ============================================================
// Portal 登出
// ============================================================

func TestPortalLogout(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableUserPortal: true})

	req := httptest.NewRequest("POST", "/portal/logout", nil)
	w := httptest.NewRecorder()

	PortalLogout(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)

	// 检查 Set-Cookie 清除了 portal_session
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == portalCookieName && c.MaxAge < 0 {
			found = true
		}
	}
	ast.True(found, "should clear portal_session cookie")
}
