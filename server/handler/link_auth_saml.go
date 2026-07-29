// SSO OAuth 认证端点：企业微信 / 飞书扫码登录。
package handler

import (
	"encoding/base64"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"

	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
)

const ssoStatePrefixLen = 32 // SSO state 随机串长度

// 统一 SSO 登录入口：生成 state、创建 pending 会话、拼 OAuth URL 并跳转。
// callbackPath 为固定回调路径前缀（如 "WXAuth"、"FeishuAuth"），会自动拼接 "/callback"。
// buildURL 接收完整的 redirectUri 和 state，返回目标 OAuth 授权地址。
func startSSO(w http.ResponseWriter, r *http.Request, tgname, ssoType, callbackPath string,
	buildURL func(redirectUri, state string) string) {

	state := utils.RandomRunes(ssoStatePrefixLen)
	pending := &AuthSession{
		Ctx: &auth.Context{
			Conn: auth.ConnInfo{GroupName: tgname},
			SSO: &auth.SSOState{
				Type:     ssoType,
				From:     r.URL.Query().Get("from"),
				ClientIP: r.RemoteAddr,
			},
		},
	}
	SaveAuthSession(state, pending)

	redirectUri := fmt.Sprintf("%s/%s/callback", getServerAddr(r), callbackPath)
	http.Redirect(w, r, buildURL(redirectUri, state), http.StatusFound)
}

// SAML 服务提供商登录入口（根据 ssotype 分发到企微/飞书 OAuth）
func SAMLSPLogin(w http.ResponseWriter, r *http.Request) {
	tgname := r.URL.Query().Get("tgname")
	if tgname == "" {
		base.Error("缺少组名参数")
		http.Error(w, "缺少组名参数", http.StatusBadRequest)
		return
	}

	// 校验该组的认证配置确实包含请求的 SSO 类型
	groupData := &dbdata.Group{}
	if err := dbdata.One("Name", tgname, groupData); err != nil {
		base.Error("组不存在:", tgname)
		http.Error(w, "组不存在", http.StatusBadRequest)
		return
	}

	ssotype := r.URL.Query().Get("ssotype")

	if ssotype == "feishu" {
		if !dbdata.HasAuthType(groupData.AuthProfile, "feishu") {
			base.Error("组未配置飞书认证:", tgname)
			http.Error(w, "组未配置飞书认证", http.StatusBadRequest)
			return
		}
		feishuConfig, err := dbdata.GetAuthFeishu(tgname)
		if err != nil {
			base.Error("获取飞书配置失败", err)
			http.Error(w, "获取飞书配置失败", http.StatusInternalServerError)
			return
		}
		startSSO(w, r, tgname, "feishu", "FeishuAuth", func(redirectUri, state string) string {
			return fmt.Sprintf("https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=%s&redirect_uri=%s&state=%s",
				feishuConfig.AppID, url.QueryEscape(redirectUri), url.QueryEscape(state))
		})
		return
	}

	// 默认企微
	if !dbdata.HasAuthType(groupData.AuthProfile, "wxwork") {
		base.Error("组未配置企微认证:", tgname)
		http.Error(w, "组未配置企微认证", http.StatusBadRequest)
		return
	}
	wxworkConfig, err := dbdata.GetAuthWework(tgname)
	if err != nil {
		base.Error("获取企微配置失败", err)
		http.Error(w, "获取企微配置失败", http.StatusInternalServerError)
		return
	}

	startSSO(w, r, tgname, "wxwork", "WXAuth", func(redirectUri, state string) string {
		return fmt.Sprintf("https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=%s&agentid=%s&redirect_uri=%s&state=%s",
			wxworkConfig.CorpID, wxworkConfig.AgentID, url.QueryEscape(redirectUri), url.QueryEscape(state))
	})
}

// 企业微信 OAuth2 回调
func WXAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		base.Error("企微认证回调缺少参数")
		http.Error(w, "缺少认证参数", http.StatusBadRequest)
		return
	}

	// 校验 state 是否由本服务签发
	pending, err := GetAuthSession(state)
	if err != nil {
		base.Error("非法的 SSO state:", state[:min(16, len(state))], ", err:", err)
		SAMLError(w, fmt.Errorf("认证会话已过期或无效"))
		return
	}
	// 已被标记为已认证的 state 说明此前使用过，拒绝重放
	if pending.Ctx.SSO == nil || pending.Ctx.SSO.Authenticated {
		base.Error("SSO state 已被消费（疑似重放）:", state[:min(16, len(state))])
		SAMLError(w, fmt.Errorf("认证会话已过期或无效"))
		return
	}
	// 发起登录与回调须来自同一客户端 IP，否则拒绝冒用
	if pending.Ctx.SSO.ClientIP != "" {
		want, _, _ := net.SplitHostPort(pending.Ctx.SSO.ClientIP)
		got, _, _ := net.SplitHostPort(r.RemoteAddr)
		if want != "" && got != "" && want != got {
			base.Error("SSO state 来源 IP 不匹配:", want, got)
			SAMLError(w, fmt.Errorf("认证会话来源异常"))
			return
		}
	}
	// 消费 pending，避免同一 state 被重复使用
	SessStore.Delete(state)
	groupname := pending.Ctx.Conn.GroupName
	if groupname == "" {
		base.Error("SSO pending 会话缺少组名")
		SAMLError(w, fmt.Errorf("认证会话数据异常"))
		return
	}

	wxworkConfig, err := dbdata.GetAuthWework(groupname)
	if err != nil {
		base.Error("获取企微配置失败", err)
		SAMLError(w, err)
		return
	}

	userID, err := wxworkConfig.GetWeworkUser(code)
	if err != nil {
		base.Error("用户信息获取失败", err)
		SAMLError(w, err)
		return
	}

	// 部门过滤：在回调阶段完成校验，避免后续管道绕过
	allowedDepts := wxworkConfig.ParseDepartments()
	if len(allowedDepts) > 0 {
		ok, err := wxworkConfig.CheckUserDepartment(userID, allowedDepts)
		if err != nil {
			base.Error("验证部门失败", err)
			SAMLError(w, err)
			return
		}
		if !ok {
			base.Error("用户不在允许的部门范围内:", userID)
			SAMLError(w, fmt.Errorf("用户不在允许的部门范围内"))
			return
		}
	}

	// 用户ID拒绝清单：在回调阶段完成校验，避免后续管道绕过
	blockedUserIDs := wxworkConfig.ParseBlockedUserIDs()
	if len(blockedUserIDs) > 0 && wxworkConfig.CheckUserID(userID, blockedUserIDs) {
		base.Error("用户在被拒绝的用户ID列表中:", userID)
		SAMLError(w, fmt.Errorf("用户在被拒绝的用户ID列表中"))
		return
	}

	// 创建完整 SSO 会话（覆盖 pending 状态）
	if portalSSOLogin(w, r, pending, "wxwork", userID) {
		return
	}

	// 创建完整 SSO 会话（覆盖 pending 状态）
	samlSession := &AuthSession{
		Ctx: &auth.Context{
			Conn: auth.ConnInfo{GroupName: groupname, Username: userID},
			SSO: &auth.SSOState{
				Type:          "wxwork",
				Authenticated: true,
				UserID:        userID,
			},
		},
	}
	SaveAuthSession(state, samlSession)

	// 设置 Cookie（Base64 编码 state）
	encodeState := base64.StdEncoding.EncodeToString([]byte(state))
	SetCookie(w, "acSamlv2Token", encodeState, 0)

	http.Redirect(w, r, "/+CSCOE+/saml_ac_login.html", http.StatusFound)
}

// SAML 断言消费者端点（sso-v2-login-final）
func SAMLACLogin(w http.ResponseWriter, r *http.Request) {
	encodedToken, err := GetCookie(r, "acSamlv2Token")
	if err != nil || encodedToken == "" {
		base.Error("认证信息丢失,获取Cookie失败")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("认证失败：无法获取认证信息"))
		return
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		base.Error("Cookie解码失败", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token := string(tokenBytes)

	if isAnyConnectInternalBrowser(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(samlSuccessHTML))
		return
	}
	// WebAuth认证成功后直接跳转到门户
	isWebAuth := false
	if samlSession, err := GetAuthSession(token); err == nil {
		if samlSession.Ctx != nil && samlSession.Ctx.SSO != nil && samlSession.Ctx.SSO.WebAuthCompleted {
			isWebAuth = true
		}
	}

	returnURL := r.URL.Query().Get("return")
	if returnURL == "" {
		if isWebAuth {
			returnURL = fmt.Sprintf("%s/ui/#/portal", getServerAddr(r))
		} else {
			returnURL = fmt.Sprintf("%s/+CSCOE+/saml/sp/done", getServerAddr(r))
		}
	}

	localAPIURL := fmt.Sprintf("http://localhost:29786/api/sso/%s?return=%s",
		url.QueryEscape(token),
		url.QueryEscape(returnURL))
	http.Redirect(w, r, localAPIURL, http.StatusFound)
}

// SAML 认证完成页面
func SAMLDone(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(samlSuccessHTML))
}

// 企业微信域名验证端点（对应 wxwork 认证源配置的 verify_file_content）
func SAMLTest(w http.ResponseWriter, r *http.Request) {
	content, ok := wxworkVerifyFileByPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write([]byte(content))
}

// 根据请求路径匹配启用的 wxwork 认证源的验证文件
func wxworkVerifyFileByPath(path string) (string, bool) {
	for _, name := range dbdata.ProviderNamesByType("wxwork") {
		cfg, err := dbdata.ResolveProviderConfig(name, "wxwork")
		if err != nil {
			continue
		}
		fn, _ := cfg["verify_file_name"].(string)
		fc, _ := cfg["verify_file_content"].(string)
		if fn != "" && path == "/"+fn {
			return fc, true
		}
	}
	return "", false
}

// 飞书 OAuth 登录入口已合并到 SAMLSPLogin（按 ssotype 参数分发），
// 无需单独的登录端点。回调端点 FeishuAuthCallback 保持不变。

// 飞书 OAuth2 回调
func FeishuAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		base.Error("飞书认证回调缺少参数")
		http.Error(w, "缺少认证参数", http.StatusBadRequest)
		return
	}

	// 校验 state 是否由本服务签发
	pending, err := GetAuthSession(state)
	if err != nil {
		base.Error("非法的 SSO state:", state[:min(16, len(state))], ", err:", err)
		SAMLError(w, fmt.Errorf("认证会话已过期或无效"))
		return
	}
	// 已被标记为已认证的 state 说明此前使用过，拒绝重放
	if pending.Ctx.SSO == nil || pending.Ctx.SSO.Authenticated {
		base.Error("SSO state 已被消费（疑似重放）:", state[:min(16, len(state))])
		SAMLError(w, fmt.Errorf("认证会话已过期或无效"))
		return
	}
	// 发起登录与回调须来自同一客户端 IP，否则拒绝冒用
	if pending.Ctx.SSO.ClientIP != "" {
		want, _, _ := net.SplitHostPort(pending.Ctx.SSO.ClientIP)
		got, _, _ := net.SplitHostPort(r.RemoteAddr)
		if want != "" && got != "" && want != got {
			base.Error("SSO state 来源 IP 不匹配:", want, got)
			SAMLError(w, fmt.Errorf("认证会话来源异常"))
			return
		}
	}
	// 避免同一 state 被重复使用
	SessStore.Delete(state)
	groupname := pending.Ctx.Conn.GroupName
	if groupname == "" {
		base.Error("SSO pending 会话缺少组名")
		SAMLError(w, fmt.Errorf("认证会话数据异常"))
		return
	}

	feishuConfig, err := dbdata.GetAuthFeishu(groupname)
	if err != nil {
		base.Error("获取飞书配置失败", err)
		SAMLError(w, err)
		return
	}

	userID, err := feishuConfig.GetFeishuUser(code)
	if err != nil {
		base.Error("飞书用户信息获取失败", err)
		SAMLError(w, err)
		return
	}

	// 部门过滤：在回调阶段完成校验，避免后续管道绕过
	allowedDepts := feishuConfig.ParseDepartments()
	if len(allowedDepts) > 0 {
		accessToken, err := feishuConfig.GetAppAccessToken()
		if err != nil {
			base.Error("获取飞书 access_token 失败", err)
			SAMLError(w, err)
			return
		}
		ok, err := feishuConfig.CheckUserDepartment(accessToken, userID, allowedDepts)
		if err != nil {
			base.Error("验证部门失败", err)
			SAMLError(w, err)
			return
		}
		if !ok {
			base.Error("用户不在允许的部门范围内:", userID)
			SAMLError(w, fmt.Errorf("用户不在允许的部门范围内"))
			return
		}
	}

	// 创建完整 SSO 会话（覆盖 pending 状态）
	if portalSSOLogin(w, r, pending, "feishu", userID) {
		return
	}

	// 创建完整 SSO 会话（覆盖 pending 状态）
	samlSession := &AuthSession{
		Ctx: &auth.Context{
			Conn: auth.ConnInfo{GroupName: groupname, Username: userID},
			SSO: &auth.SSOState{
				Type:          "feishu",
				Authenticated: true,
				UserID:        userID,
			},
		},
	}
	SaveAuthSession(state, samlSession)

	// 设置 Cookie（Base64 编码 state）
	encodeState := base64.StdEncoding.EncodeToString([]byte(state))
	SetCookie(w, "acSamlv2Token", encodeState, 0)

	http.Redirect(w, r, "/+CSCOE+/saml_ac_login.html", http.StatusFound)
}

// SAML 认证失败页面
func SAMLError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	errMsg := html.EscapeString(err.Error())
	errorPage := `
<!DOCTYPE html>
<html>
<head>
    <title>认证失败</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 15px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            text-align: center;
        }
        .icon {
            font-size: 56px;
            color: #f44336; 
            margin-bottom: 24px;
        }
        h1 {
            color: #303133;
            font-size: 24px;
            margin-bottom: 15px;
        }
        .error-message {
            color: #e6a23c;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .detail {
            color: #606266;
            font-size: 15px;
            margin-bottom: 25px;
        }
        .note {
            color: #909399;
            font-size: 13px;
            margin-top: 30px;
            border-top: 1px solid #e4e7ed;
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">❌</div>
        <h1>认证失败</h1>
        <div class="error-message">` + errMsg + `</div>
        <p class="detail">请确认您所在的部门是否在允许的范围内，或联系管理员解决。</p>
        <div class="note">
            提示：由于浏览器安全限制，网页可能无法自动关闭。<br>
            请手动关闭此页面并返回 AnyConnect 客户端。
        </div>
    </div>
</body>
</html>`
	w.Write([]byte(errorPage))
}
