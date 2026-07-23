package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// 创建 WebAuth 测试会话，返回 state（即 sessionID）
func createWebAuthSession(_ *testing.T, groupName string) string {
	state := GenerateSessionID()

	pending := &AuthSession{
		Ctx: &auth.Context{
			Conn: auth.ConnInfo{GroupName: groupName},
		},
		UserActLog: &dbdata.UserActLog{
			GroupName: groupName,
		},
	}
	SaveAuthSession(state, pending)
	return state
}

func TestWebAuthSPLogin_Valid(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableWebAuth = true })

	state := createWebAuthSession(t, "default")

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/sp/login?state="+state, nil)
	w := httptest.NewRecorder()

	WebAuthSPLogin(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	ast.Contains(location, "/ui/#/web-auth?state=")
	ast.Contains(location, state)
}

func TestWebAuthSPLogin_InvalidState(t *testing.T) {
	base.Test()

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/sp/login?state=nonexistent", nil)
	w := httptest.NewRecorder()

	WebAuthSPLogin(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusBadRequest, w.Code)
}

func TestWebAuthSPLogin_EmptyState(t *testing.T) {
	base.Test()

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/sp/login", nil)
	w := httptest.NewRecorder()

	WebAuthSPLogin(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusBadRequest, w.Code)
}

func TestWebAuthStart_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()
	base.UpdateCfg(func(c *base.ServerConfig) { c.EnableWebAuth = true })

	// 创建组
	pt := &dbdata.Policy{
		Name:      "plcy-web",
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	err := dbdata.SetPolicy(pt)
	assert.New(t).Nil(err)

	g := &dbdata.Group{
		Name:        "webauth-group",
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	}
	err = dbdata.SetGroup(g)
	assert.New(t).Nil(err)

	state := createWebAuthSession(t, "webauth-group")

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/start?state="+state, nil)
	w := httptest.NewRecorder()

	WebAuthStart(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("select_group", resp["status"])
	ast.NotNil(resp["groups"], "should return group list")
}

func TestWebAuthStart_EmptyState(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableWebAuth: true})

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/start", nil)
	w := httptest.NewRecorder()

	WebAuthStart(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthStart_InvalidState(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableWebAuth: true})

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/start?state=expired-session", nil)
	w := httptest.NewRecorder()

	WebAuthStart(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthStart_Disabled(t *testing.T) {
	base.Test()
	base.SetCfgForTest(&base.ServerConfig{EnableWebAuth: false})

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/start?state=any", nil)
	w := httptest.NewRecorder()

	WebAuthStart(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusNotFound, w.Code)
}

func TestWebAuthSelectGroup_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	ast := assert.New(t)

	// 创建策略和组
	pt := &dbdata.Policy{
		Name:      "plcy-sel",
		ClientDns: []dbdata.ValData{{Val: "8.8.8.8"}},
		Status:    1,
	}
	err := dbdata.SetPolicy(pt)
	ast.Nil(err)

	g := &dbdata.Group{
		Name:        "select-group",
		Status:      1,
		PolicyId:    pt.Id,
		AuthProfile: json.RawMessage(`{"step":[{"type":"local"}]}`),
	}
	err = dbdata.SetGroup(g)
	ast.Nil(err)

	state := createWebAuthSession(t, "select-group")

	body := `{"group":"select-group","username":"testuser"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/select-group?state="+state, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthSelectGroup(w, req)

	ast.Equal(http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("credentials", resp["status"], "should return credentials for local auth first step")
	ast.Equal("请输入登录凭据", resp["hint"])
}

func TestWebAuthSelectGroup_InvalidState(t *testing.T) {
	base.Test()

	body := `{"group":"any","username":"test"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/select-group?state=expired", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthSelectGroup(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthSelectGroup_EmptyState(t *testing.T) {
	base.Test()

	body := `{"group":"any"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/select-group", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthSelectGroup(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthSelectGroup_GroupNotFound(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	state := createWebAuthSession(t, "default")

	body := `{"group":"nonexistent-group","username":"test"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/select-group?state="+state, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthSelectGroup(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthSelectGroup_EmptyBody(t *testing.T) {
	base.Test()

	body := ``
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/select-group?state=any", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthSelectGroup(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthStep_InvalidState(t *testing.T) {
	base.Test()

	body := `{"username":"test","password":"test"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/step?state=expired", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthStep(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthStep_EmptyState(t *testing.T) {
	base.Test()

	body := `{"username":"test","password":"test"}`
	req := httptest.NewRequest("POST", "/+CSCOE+/web-auth/step", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	WebAuthStep(w, req)

	ast := assert.New(t)
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	ast.Equal("error", resp["status"])
}

func TestWebAuthComplete_InvalidState(t *testing.T) {
	base.Test()

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/complete?state=expired", nil)
	w := httptest.NewRecorder()

	WebAuthComplete(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusBadRequest, w.Code)
}

func TestWebAuthComplete_EmptyState(t *testing.T) {
	base.Test()

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/complete", nil)
	w := httptest.NewRecorder()

	WebAuthComplete(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusBadRequest, w.Code)
}

func TestWebAuthComplete_Success(t *testing.T) {
	base.Test()
	preIpData(t)
	defer closeIpdata()

	state := createWebAuthSession(t, "default")

	// 标记认证完成
	sess, err := GetAuthSession(state)
	assert.New(t).Nil(err)
	sess.Ctx.GetSSO().WebAuthCompleted = true
	SaveAuthSession(state, sess)

	req := httptest.NewRequest("GET", "/+CSCOE+/web-auth/complete?state="+state, nil)
	w := httptest.NewRecorder()

	WebAuthComplete(w, req)

	ast := assert.New(t)
	ast.Equal(http.StatusFound, w.Code)

	// 应该 302 到 saml_ac_login.html
	location := w.Header().Get("Location")
	ast.Contains(location, "saml_ac_login.html")

	// 验证设置了 acSamlv2Token Cookie（token 存在 Cookie 而非 URL 中）
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "acSamlv2Token" && c.Value != "" {
			found = true
			break
		}
	}
	ast.True(found, "should set acSamlv2Token cookie")
}
