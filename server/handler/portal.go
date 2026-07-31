package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"github.com/wsczx/remlink/admin"
	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/auth/authsrv"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/notify"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/wsczx/remlink/sessdata"
	"github.com/xlzd/gotp"
)

const portalCookieName = "portal_session"

func PortalHome(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/#/portal", http.StatusFound)
}

func PortalLogin(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	resp := portalStartAuth(w, req.Username, req.Password, r)
	if resp.Code != 0 {
		portalError(w, resp.Msg)
		return
	}
	portalOK(w, resp.Data)
}

func PortalVerify(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	resp := portalResumeAuth(w, req.SessionID, req.Code, r)
	if resp.Code != 0 {
		portalError(w, resp.Msg)
		return
	}
	portalOK(w, resp.Data)
}

// 发送短信验证码
func PortalSmsSend(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal || !notify.IsSmsConfigured() {
		portalError(w, "短信登录未启用")
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Phone == "" {
		portalError(w, "请输入手机号")
		return
	}

	// 查找手机号对应的本地用户
	user := &dbdata.User{}
	if err := dbdata.One("Phone", req.Phone, user); err != nil || user.Status != 1 {
		portalError(w, "手机号未注册或账号异常")
		return
	}

	// 发送验证码
	_, err := authsrv.SendSmsCode(req.Phone)
	if err != nil {
		base.Warn("Portal短信登录发送失败:", err)
		portalError(w, "验证码发送失败，请稍后重试")
		return
	}

	portalOK(w, map[string]any{
		"message":    "验证码已发送",
		"phone_tail": req.Phone[len(req.Phone)-4:],
	})
}

// 验证短信验证码并登录
func PortalSmsVerify(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal || !notify.IsSmsConfigured() {
		portalError(w, "短信登录未启用")
		return
	}
	var req struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<12)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Phone == "" || req.Code == "" {
		portalError(w, "参数错误")
		return
	}

	// 防暴力破解
	if !lockManager.Check(req.Phone, r.RemoteAddr) {
		portalError(w, "验证过于频繁，请稍后重试")
		return
	}

	// 验证短信验证码
	_, err := authsrv.VerifySmsCode(req.Phone, req.Code)
	if err != nil {
		lockManager.Fail(req.Phone, r.RemoteAddr)
		portalError(w, err.Error())
		return
	}

	// 查找用户
	user := &dbdata.User{}
	if err := dbdata.One("Phone", req.Phone, user); err != nil || user.Status != 1 {
		portalError(w, "用户不存在或已禁用")
		return
	}

	lockManager.Success(req.Phone, r.RemoteAddr)
	resp := portalIssueLoginResponse(w, r, user, "短信验证码登录成功")
	if resp.Code != 0 {
		portalError(w, resp.Msg)
		return
	}
	portalOK(w, resp.Data)
}

func PortalSSO(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	ssoType := r.URL.Query().Get("type")
	if ssoType != "wxwork" && ssoType != "feishu" {
		http.Error(w, "不支持的第三方登录类型", http.StatusBadRequest)
		return
	}
	group, err := portalSSOGroup(ssoType)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := fmt.Sprintf("/+CSCOE+/saml/sp/login?tgname=%s&ssotype=%s&from=portal",
		url.QueryEscape(group), url.QueryEscape(ssoType))
	http.Redirect(w, r, target, http.StatusFound)
}

func PortalMe(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}
	portalOK(w, portalUserInfo(user, r))
}

func PortalChangePassword(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalError(w, "外部认证用户请到对应身份源修改密码")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		portalError(w, "新旧密码不能为空")
		return
	}
	if err := utils.CheckPasswordPolicy(req.NewPassword); err != nil {
		portalError(w, err.Error())
		return
	}
	if err := portalCheckLocalPassword(user, req.OldPassword); err != nil {
		portalError(w, "旧密码错误")
		return
	}

	hashed, err := utils.PasswordHash(req.NewPassword)
	if err != nil {
		base.Error("用户门户密码哈希失败:", err)
		portalError(w, "修改密码失败")
		return
	}
	if _, err := dbdata.GetXdb().Where("username = ?", user.Username).Cols("pin_code", "change_pwd").
		Update(&dbdata.User{PinCode: hashed, ForcePwd: false}); err != nil {
		base.Error("用户门户修改密码失败:", err)
		portalError(w, "修改密码失败")
		return
	}
	portalOK(w, map[string]string{"message": "密码修改成功"})
}

// 处理门户首次登录强制改密提交（POST /portal/api/force_change_password）。
// 复用登录时创建的认证会话（challenge 会话，token 字段即 session_id），更新密码并清除 ForcePwd 后
// 续跑认证管道：若用户启用 OTP 则继续 OTP 二次认证，否则直接签发门户登录令牌。
func PortalForceChangePassword(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
		Confirm     string `json:"new_password_confirm"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		portalError(w, "参数不能为空")
		return
	}
	if req.NewPassword != req.Confirm {
		portalError(w, "两次输入的密码不一致")
		return
	}
	if err := utils.CheckPasswordPolicy(req.NewPassword); err != nil {
		portalError(w, err.Error())
		return
	}

	sess, err := GetAuthSession(req.Token)
	if err != nil || sess.Ctx == nil {
		portalError(w, "改密会话已过期，请重新登录")
		return
	}
	username := sess.Ctx.Conn.Username
	if username == "" {
		portalError(w, "改密会话数据异常")
		return
	}
	user := &dbdata.User{}
	if err := dbdata.One("Username", username, user); err != nil || user.Status != 1 {
		portalError(w, "用户不存在或已停用")
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalError(w, "外部认证用户请到对应身份源修改密码")
		return
	}
	if !user.ForcePwd {
		portalError(w, "无需修改密码或会话已失效")
		return
	}

	hashed, err := utils.PasswordHash(req.NewPassword)
	if err != nil {
		base.Error("用户门户强制改密哈希失败:", err)
		portalError(w, "修改密码失败")
		return
	}
	if _, err := dbdata.GetXdb().Where("username = ?", username).Cols("pin_code", "change_pwd").
		Update(&dbdata.User{PinCode: hashed, ForcePwd: false}); err != nil {
		base.Error("用户门户强制改密失败:", err)
		portalError(w, "修改密码失败")
		return
	}
	// 内存对象同步，避免签发令牌时读到过期的 ForcePwd 标记
	user.PinCode = hashed
	user.ForcePwd = false

	// 以数据库为准重载用户信息，续跑管道（forcepwd 步见 ForcePwd=false 通过，继续后续 otp 等步骤）
	authsrv.ReloadUserInfo(sess.Ctx)
	sess.Ctx.Conn.RemoteAddr = r.RemoteAddr
	result := authsrv.Resume(sess.Ctx, auth.PipelineState{
		StepIdx:     sess.Ctx.StepIdx(),
		PassedSteps: sess.Ctx.PassedSteps(),
	})
	switch result.Result {
	case auth.StepPass:
		SessStore.Delete(req.Token)
		portalUser, err := portalResolveUser(username, result.GroupName, user, true)
		if err != nil {
			portalError(w, err.Error())
			return
		}
		lockManager.Success(username, r.RemoteAddr)
		resp := portalIssueLoginResponse(w, r, portalUser, "首次登录修改密码成功")
		if resp.Code != 0 {
			portalError(w, resp.Msg)
			return
		}
		portalOK(w, resp.Data)
	case auth.StepPending:
		sess.Ctx.SetStepIdx(result.State.StepIdx)
		sess.Ctx.SetPassedSteps(result.State.PassedSteps)
		SaveAuthSession(req.Token, sess)
		portalOK(w, portalChallengeResponse(req.Token, result, sess.Ctx).Data)
	case auth.StepFail:
		if result.Err != nil {
			base.Warn("用户门户强制改密后续认证失败:", result.Err)
		}
		lockManager.Fail(username, r.RemoteAddr)
		if base.GetCfg().DisplayError && result.Err != nil {
			portalError(w, result.Err.Error())
			return
		}
		portalError(w, "修改密码失败")
	}
}

func PortalLogout(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	portalOK(w, map[string]string{"message": "已退出"})
}

// 返回登录页品牌与认证方式开关，供门户、WebAuth、管理后台登录页在未登录时渲染。
func PortalLoginConfig(w http.ResponseWriter, r *http.Request) {
	brand := dbdata.SettingPortalBrand{}
	_ = dbdata.SettingGet(&brand)
	portalOK(w, map[string]any{
		"title":            brand.Title,
		"logo":             brand.Logo,
		"favicon":          brand.Favicon,
		"desc":             brand.Desc,
		"footer":           brand.Footer,
		"features_enabled": brand.FeaturesEnabled,
		"features":         brand.Features,
		"issuer":           base.GetCfg().Issuer,
		"sso_types":        portalEnabledSSOTypes(),
		"sms_enabled":      notify.IsSmsConfigured(),
	})
}

// 返回门户支持且至少存在一个组已配置的 SSO 类型。
func portalEnabledSSOTypes() []string {
	supported := []string{"wxwork", "feishu", "dingtalk"}
	types := make([]string, 0, len(supported))
	for _, t := range supported {
		if _, err := portalSSOGroup(t); err == nil {
			types = append(types, t)
		}
	}
	return types
}

var portalForgotLimiter = struct {
	mu   sync.Mutex
	next map[string]time.Time
}{next: make(map[string]time.Time)}

var portalResetTokens = struct {
	mu     sync.Mutex
	used   map[string]int64 // jti -> used_at unix
	inited bool
}{used: make(map[string]int64)}

func portalInitResetTokens() {
	portalResetTokens.mu.Lock()
	if portalResetTokens.inited {
		portalResetTokens.mu.Unlock()
		return
	}
	portalResetTokens.inited = true
	portalResetTokens.mu.Unlock()

	data := dbdata.SettingPortalResetTokens{}
	if err := dbdata.SettingGet(&data); err == nil && data.Tokens != nil {
		portalResetTokens.mu.Lock()
		now := time.Now().Unix()
		for jti, ts := range data.Tokens {
			if now-ts < 900 {
				portalResetTokens.used[jti] = ts
			}
		}
		portalResetTokens.mu.Unlock()
	}
}

func portalIsTokenUsed(jti string) bool {
	portalInitResetTokens()
	portalResetTokens.mu.Lock()
	defer portalResetTokens.mu.Unlock()
	_, ok := portalResetTokens.used[jti]
	return ok
}

// 返回 true 表示 token 已经被消费过。
func portalTryMarkToken(jti string) bool {
	portalInitResetTokens()
	portalResetTokens.mu.Lock()
	defer portalResetTokens.mu.Unlock()

	if _, ok := portalResetTokens.used[jti]; ok {
		return true
	}

	now := time.Now().Unix()
	portalResetTokens.used[jti] = now

	cutoff := now - 900
	clean := make(map[string]int64, len(portalResetTokens.used))
	for j, ts := range portalResetTokens.used {
		if ts >= cutoff {
			clean[j] = ts
		}
	}
	portalResetTokens.used = clean
	if err := dbdata.SettingSave(&dbdata.SettingPortalResetTokens{Tokens: clean}); err != nil {
		base.Error("用户门户保存重置token状态失败:", err)
	}
	return false
}

func PortalForgotPassword(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Email == "" {
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}

	limiterKey := host + ":" + req.Username
	now := time.Now()
	portalForgotLimiter.mu.Lock()
	if t, ok := portalForgotLimiter.next[limiterKey]; ok && now.Before(t) {
		portalForgotLimiter.mu.Unlock()
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}
	portalForgotLimiter.next[limiterKey] = now.Add(60 * time.Second)
	for k, t := range portalForgotLimiter.next {
		if now.After(t) {
			delete(portalForgotLimiter.next, k)
		}
	}
	portalForgotLimiter.mu.Unlock()

	user := &dbdata.User{}
	err = dbdata.One("Username", req.Username, user)
	if err != nil || user.Status != 1 {
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}
	if user.Email != req.Email {
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}

	jti := fmt.Sprintf("%d_%d", user.Id, time.Now().UnixNano())
	token, err := admin.SetJwtData(map[string]any{
		"purpose": "portal_reset_password",
		"user_id": user.Id,
		"jti":     jti,
	}, time.Now().Unix()+900)
	if err != nil {
		base.Error("用户门户生成重置token失败:", err)
		portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
		return
	}

	resetURL := getServerAddr(r) + "/ui/#/portal?reset_token=" + url.QueryEscape(token)
	htmlBody := fmt.Sprintf(`<html><body>
<h2>RemLink 密码重置</h2>
<p>您好 %s，</p>
<p>请点击下方链接重置您的密码（15 分钟内有效）：</p>
<p><a href="%s">%s</a></p>
	<p>如果您未发起此请求，请忽略此邮件。</p>
	</body></html>`, html.EscapeString(user.Username), html.EscapeString(resetURL), html.EscapeString(resetURL))

	smtpCfg := &dbdata.SettingSmtp{}
	if err := dbdata.SettingGet(smtpCfg); err != nil || smtpCfg.Host == "" {
		base.Warn("用户门户SMTP未配置，跳过发送重置邮件:", user.Username)
	} else {
		go func() {
			if err := notify.GetNotify().SendEmail(notify.Message{
				Subject: "RemLink 密码重置",
				To:      user.Email,
				Body:    htmlBody,
			}); err != nil {
				base.Error("用户门户发送重置邮件失败:", user.Username, err)
			}
		}()
	}

	portalOK(w, map[string]string{"message": "如果账号匹配，重置邮件已发送"})
}

func PortalResetPasswordVerify(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		portalOK(w, map[string]any{"valid": false})
		return
	}

	data, err := admin.GetJwtData(token)
	if err != nil {
		portalOK(w, map[string]any{"valid": false})
		return
	}

	purpose, _ := data["purpose"].(string)
	if purpose != "portal_reset_password" {
		portalOK(w, map[string]any{"valid": false})
		return
	}

	jti, _ := data["jti"].(string)
	if jti == "" || portalIsTokenUsed(jti) {
		portalOK(w, map[string]any{"valid": false})
		return
	}

	userId, _ := data["user_id"].(float64)
	user := &dbdata.User{}
	if err := dbdata.One("Id", int(userId), user); err != nil || user.Status != 1 {
		portalOK(w, map[string]any{"valid": false})
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalOK(w, map[string]any{"valid": false})
		return
	}

	portalOK(w, map[string]any{
		"valid": true,
	})
}

func PortalResetPassword(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		portalError(w, "参数不能为空")
		return
	}
	if err := utils.CheckPasswordPolicy(req.NewPassword); err != nil {
		portalError(w, err.Error())
		return
	}

	data, err := admin.GetJwtData(req.Token)
	if err != nil {
		portalError(w, "重置链接已过期，请重新申请")
		return
	}
	purpose, _ := data["purpose"].(string)
	if purpose != "portal_reset_password" {
		portalError(w, "无效的重置链接")
		return
	}

	jti, _ := data["jti"].(string)
	if jti == "" {
		portalError(w, "无效的重置链接")
		return
	}

	userId, _ := data["user_id"].(float64)
	user := &dbdata.User{}
	if err := dbdata.One("Id", int(userId), user); err != nil || user.Status != 1 {
		portalError(w, "用户不存在或已停用")
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalError(w, "外部认证用户请到对应身份源修改密码")
		return
	}

	hashed, err := utils.PasswordHash(req.NewPassword)
	if err != nil {
		base.Error("用户门户重置密码哈希失败:", err)
		portalError(w, "重置密码失败")
		return
	}

	if portalTryMarkToken(jti) {
		portalError(w, "重置链接已失效，请重新申请")
		return
	}

	// 重置密码清除强制改密标记
	if _, err := dbdata.GetXdb().Where("username = ?", user.Username).Cols("pin_code", "change_pwd").
		Update(&dbdata.User{PinCode: hashed, ForcePwd: false}); err != nil {
		base.Error("用户门户重置密码失败:", err)
		portalError(w, "重置密码失败")
		return
	}

	portalOK(w, map[string]string{"message": "密码重置成功，请使用新密码登录"})
}

type portalAuthResponse struct {
	Code int
	Msg  string
	Data map[string]any
}

func portalStartAuth(w http.ResponseWriter, username, password string, r *http.Request) portalAuthResponse {
	if username == "" || len(password) < 1 {
		return portalAuthError("用户名或密码错误")
	}

	// 防暴力破解：检查锁定状态
	if !lockManager.Check(username, r.RemoteAddr) {
		return portalAuthError("账号已被锁定，请稍后重试")
	}

	user, userExists, err := portalLoadUser(username)
	if err != nil {
		return portalAuthError(err.Error())
	}
	// 未同步用户走外部认证流程（LDAP/RADIUS）
	if !userExists {
		user = &dbdata.User{Username: username}
	}

	var lastErr error
	for _, group := range portalCandidateGroups(user, userExists) {
		ctx := &auth.Context{
			Conn: auth.ConnInfo{
				Username:   username,
				Password:   password,
				GroupName:  group,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
			},
			PortalLogin: true,
		}
		result := authsrv.Authenticate(ctx)
		switch result.Result {
		case auth.StepPass:
			portalUser, err := portalResolveUser(username, group, user, userExists)
			if err != nil {
				return portalAuthError(err.Error())
			}
			lockManager.Success(username, r.RemoteAddr)
			return portalIssueLoginResponse(w, r, portalUser, ctx.LogInfo())
		case auth.StepPending:
			sessionID := portalSaveChallengeSession(result, ctx)
			return portalChallengeResponse(sessionID, result, ctx)
		case auth.StepFail:
			if result.Err != nil {
				lastErr = result.Err
				base.Warn("用户门户认证失败:", username, group, result.Err)
			}
		}
	}
	lockManager.Fail(username, r.RemoteAddr)
	if lastErr != nil && base.GetCfg().DisplayError {
		return portalAuthError(lastErr.Error())
	}
	return portalAuthError("用户名或密码错误")
}

func portalResumeAuth(w http.ResponseWriter, sessionID, code string, r *http.Request) portalAuthResponse {
	if sessionID == "" || code == "" {
		return portalAuthError("参数不能为空")
	}
	sess, err := GetAuthSession(sessionID)
	if err != nil || sess.Ctx == nil {
		return portalAuthError("认证会话已过期，请重新登录")
	}

	username := sess.Ctx.Conn.Username
	ctx := sess.Ctx
	if ctx == nil {
		ctx = &auth.Context{
			Conn: auth.ConnInfo{
				Username:   sess.Ctx.Conn.Username,
				Password:   sess.Ctx.Conn.Password,
				GroupName:  sess.Ctx.Conn.GroupName,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
			},
			PortalLogin: true,
		}
		sess.Ctx = ctx
	} else {
		ctx.Conn.RemoteAddr = r.RemoteAddr
	}
	// 注入挑战响应码（OTP / RADIUS / SMS 复用同一 code 字段）
	ctx.GetOTP().Code = code
	ctx.GetRADIUS().ChallengeCode = code
	ctx.GetSMS().Code = code

	state := auth.PipelineState{
		StepIdx:     sess.Ctx.StepIdx(),
		PassedSteps: sess.Ctx.PassedSteps(),
	}
	result := authsrv.Resume(ctx, state)
	switch result.Result {
	case auth.StepPass:
		SessStore.Delete(sessionID)
		user, userExists, err := portalLoadUser(result.Username)
		if err != nil {
			return portalAuthError(err.Error())
		}
		portalUser, err := portalResolveUser(result.Username, result.GroupName, user, userExists)
		if err != nil {
			return portalAuthError(err.Error())
		}
		lockManager.Success(username, r.RemoteAddr)
		return portalIssueLoginResponse(w, r, portalUser, ctx.LogInfo())
	case auth.StepPending:
		sess.Ctx.SetStepIdx(result.State.StepIdx)
		sess.Ctx.SetPassedSteps(result.State.PassedSteps)
		SaveAuthSession(sessionID, sess)
		return portalChallengeResponse(sessionID, result, ctx)
	case auth.StepFail:
		if result.Err != nil {
			base.Warn("用户门户二次认证失败:", result.Err)
		}
		lockManager.Fail(username, r.RemoteAddr)
		if base.GetCfg().DisplayError && result.Err != nil {
			return portalAuthError(result.Err.Error())
		}
	}
	return portalAuthError("验证失败")
}

func portalSaveChallengeSession(result *auth.PipelineResult, ctx *auth.Context) string {
	sessionID := GenerateSessionID()
	if ctx == nil {
		ctx = &auth.Context{}
	}
	ctx.PortalLogin = true
	ctx.SetStepIdx(result.State.StepIdx)
	ctx.SetPassedSteps(result.State.PassedSteps)
	SaveAuthSession(sessionID, &AuthSession{
		Ctx: ctx,
	})
	return sessionID
}

func portalChallengeResponse(sessionID string, result *auth.PipelineResult, ctx *auth.Context) portalAuthResponse {
	challengeType := "verify"
	message := "请输入验证码"
	if result.Challenge != nil {
		switch result.Challenge.Type {
		case auth.ChallengeOTP:
			challengeType = "otp"
			message = "请输入 6 位动态验证码"
		case auth.ChallengeRADIUS:
			challengeType = "radius"
			message = "请输入二次验证码"
			if ctx != nil && ctx.RADIUS != nil && ctx.RADIUS.ChallengeMsg != "" {
				message = ctx.RADIUS.ChallengeMsg
			}
		case auth.ChallengeSMS:
			challengeType = "sms"
			message = "请输入短信验证码"
		case auth.ChallengeSSO:
			challengeType = "sso"
			message = "请完成第三方登录"
		case auth.ChallengeForcePwd:
			// 复用前端既有 change_pwd 分支：以 session_id 充当 token 字段，前端无需改动
			return portalAuthResponse{Data: map[string]any{
				"status":   "change_pwd",
				"token":    sessionID,
				"username": ctx.Conn.Username,
				"message":  "首次登录需修改密码后才能继续使用",
			}}
		}
	}
	return portalAuthResponse{Data: map[string]any{
		"status":     challengeType,
		"session_id": sessionID,
		"message":    message,
	}}
}

func portalIssueLoginResponse(w http.ResponseWriter, r *http.Request, user *dbdata.User, logInfo string) portalAuthResponse {
	// 写入用户活动日志
	groupName := ""
	if len(user.Groups) > 0 {
		groupName = user.Groups[0]
	}
	if logInfo == "" {
		logInfo = "门户登录成功"
	}
	dbdata.UserActLogIns.Add(dbdata.UserActLog{
		Username:   user.Username,
		GroupName:  groupName,
		RemoteAddr: r.RemoteAddr,
		Status:     dbdata.UserAuthSuccess,
		Info:       logInfo,
	}, r.UserAgent(), true)

	token, err := portalIssueToken(user)
	if err != nil {
		return portalAuthError("登录失败")
	}
	if w != nil {
		http.SetCookie(w, &http.Cookie{
			Name:     portalCookieName,
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			SameSite: http.SameSiteLaxMode,
		})
	}
	return portalAuthResponse{Data: map[string]any{
		"status": "pass",
		"token":  token,
		"user":   portalUserInfo(user, r),
	}}
}

func portalAuthError(msg string) portalAuthResponse {
	return portalAuthResponse{Code: 1, Msg: msg}
}

func portalLoadUser(username string) (*dbdata.User, bool, error) {
	user := &dbdata.User{}
	if err := dbdata.One("Username", username, user); err != nil {
		if dbdata.CheckErrNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("用户查询失败")
	}
	switch user.Status {
	case 1:
		return user, true, nil
	case 2:
		return nil, true, fmt.Errorf("用户已过期")
	default:
		return nil, true, fmt.Errorf("用户不存在或已停用")
	}
}

func portalCandidateGroups(user *dbdata.User, userExists bool) []string {
	groups, err := dbdata.GetAllGroups()
	if err != nil {
		base.Error("用户门户获取用户组失败:", err)
		return nil
	}

	// 构建组名到 auth profile 的映射
	groupMap := make(map[string]json.RawMessage, len(groups))
	for _, g := range groups {
		groupMap[g.Name] = g.AuthProfile
	}

	candidateNames := user.Groups
	if !userExists || len(candidateNames) == 0 {
		// 未注册用户或用户未分配组：汇总所有支持 ldap/radius 的组
		candidateNames = make([]string, 0, len(groups))
		for _, g := range groups {
			candidateNames = append(candidateNames, g.Name)
		}
	}

	// 按用户类型过滤：仅返回 AuthProfile 匹配的组
	names := make([]string, 0, len(candidateNames))
	for _, name := range candidateNames {
		profile := groupMap[name]
		switch user.Type {
		case "ldap":
			if dbdata.HasAuthType(profile, "ldap") {
				names = append(names, name)
			}
		case "radius":
			if dbdata.HasAuthType(profile, "radius") {
				names = append(names, name)
			}
		default:
			// 未同步用户只尝试有外部认证的组
			if !userExists {
				if dbdata.HasAuthType(profile, "ldap") || dbdata.HasAuthType(profile, "radius") {
					names = append(names, name)
				}
			} else {
				// 本地用户仅保留含 local 步骤的组，避免给密码登录用户弹出 SSO 等挑战
				if dbdata.HasAuthType(profile, "local") {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func portalResolveUser(username, group string, user *dbdata.User, userExists bool) (*dbdata.User, error) {
	if userExists {
		return user, nil
	}
	return &dbdata.User{
		Type:     "external",
		Username: username,
		Groups:   []string{group},
		Status:   1,
	}, nil
}

func portalSSOGroup(ssoType string) (string, error) {
	groups, err := dbdata.GetAllGroups()
	if err != nil {
		return "", fmt.Errorf("获取用户组失败")
	}
	for _, group := range groups {
		if dbdata.HasAuthType(group.AuthProfile, ssoType) {
			return group.Name, nil
		}
	}
	return "", fmt.Errorf("未找到可用的第三方登录配置")
}

func portalSSOLogin(w http.ResponseWriter, r *http.Request, pending *AuthSession, ssoType, username string) bool {
	if pending == nil || pending.Ctx == nil {
		return false
	}
	if pending.Ctx.SSO == nil || pending.Ctx.SSO.From != "portal" {
		return false
	}
	if pending.SessionID != "" {
		defer SessStore.Delete(pending.SessionID)
	}
	user := &dbdata.User{}
	userExists := true
	if err := dbdata.One("Username", username, user); err != nil {
		if dbdata.CheckErrNotFound(err) {
			userExists = false
			user = &dbdata.User{Username: username, Type: "external", Status: 1}
		} else {
			SAMLError(w, fmt.Errorf("用户查询失败"))
			return true
		}
	}
	if userExists && user.Status != 1 {
		SAMLError(w, fmt.Errorf("用户不存在或已停用"))
		return true
	}
	group := pending.Ctx.Conn.GroupName
	if group == "" {
		SAMLError(w, fmt.Errorf("认证会话数据异常"))
		return true
	}
	ctx := &auth.Context{
		Conn: auth.ConnInfo{
			Username:   username,
			GroupName:  group,
			RemoteAddr: r.RemoteAddr,
			UserAgent:  r.UserAgent(),
		},
		PortalLogin: true,
		SSO: &auth.SSOState{
			Type:          ssoType,
			Authenticated: true,
			UserID:        username,
		},
	}
	authsrv.LoadUserInfo(ctx)
	result := authsrv.Authenticate(ctx)
	switch result.Result {
	case auth.StepPass:
		_ = portalIssueLoginResponse(w, r, user, ctx.LogInfo())
		http.Redirect(w, r, "/ui/#/portal", http.StatusFound)
	case auth.StepPending:
		sessionID := portalSaveChallengeSession(result, ctx)
		http.Redirect(w, r, "/ui/#/portal?session_id="+url.QueryEscape(sessionID)+"&challenge=otp", http.StatusFound)
	default:
		if result.Err != nil {
			SAMLError(w, result.Err)
		} else {
			SAMLError(w, fmt.Errorf("第三方登录失败"))
		}
	}
	return true
}

func portalCheckLocalPassword(user *dbdata.User, password string) error {
	if password == "" || !dbdata.VerifyPassword(password, user.PinCode) {
		return fmt.Errorf("密码错误")
	}
	return nil
}

func portalIssueToken(user *dbdata.User) (string, error) {
	return admin.SetJwtData(map[string]any{
		"portal_user_id": user.Id,
		"portal_user":    user.Username,
		"portal_type":    user.Type,
		"portal_groups":  user.Groups,
	}, time.Now().Unix()+3600*3)
}

func portalCurrentUser(r *http.Request) (*dbdata.User, bool) {
	cookie, err := r.Cookie(portalCookieName)
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	data, err := admin.GetJwtData(cookie.Value)
	if err != nil {
		return nil, false
	}
	username, ok := data["portal_user"].(string)
	if !ok || username == "" {
		return nil, false
	}
	user := &dbdata.User{}
	if err := dbdata.One("Username", username, user); err == nil {
		return user, user.Status == 1
	}

	userType, _ := data["portal_type"].(string)
	if userType == "local" || userType == "ldap" {
		base.Warn("本地用户已删除但仍持有有效 JWT:", username)
		return nil, false
	}

	groupNames, _ := data["portal_groups"].([]any)
	groups := make([]string, 0, len(groupNames))
	for _, group := range groupNames {
		if name, ok := group.(string); ok && name != "" {
			groups = append(groups, name)
		}
	}
	if username == "" || len(groups) == 0 {
		return nil, false
	}
	return &dbdata.User{
		Type:     userType,
		Username: username,
		Groups:   groups,
		Status:   1,
	}, true
}

func portalUserInfo(user *dbdata.User, r *http.Request) map[string]any {
	cfg := base.GetCfg()
	serverAddr := cfg.ServerAddr
	if r != nil {
		serverAddr = getServerAddr(r)
	}
	result := map[string]any{
		"id":                  user.Id,
		"username":            user.Username,
		"name":                user.Nickname,
		"email":               user.Email,
		"groups":              user.Groups,
		"type":                user.Type,
		"status":              user.Status,
		"limittime":           user.LimitTime,
		"mtu":                 user.Mtu,
		"disable_otp":         user.DisableOtp,
		"otp_enabled":         user.OtpSecret != "" && !user.DisableOtp,
		"can_change_password": user.Type == "" || user.Type == "local",
		"created_at":          user.CreatedAt.Unix(),
		"server_addr":         serverAddr,
		"issuer":              cfg.Issuer,
		"groups_detail":       portalGroupsDetail(user.Groups, user.PolicyId),
		"user_policy":         portalPolicyInfo(user.PolicyId),
		"traffic_used":        user.TrafficUsed,
		"traffic_reset_at":    user.TrafficResetAt,
	}

	dash := dbdata.SettingPortalDashboard{}
	if err := dbdata.SettingGet(&dash); err != nil {
		if dbdata.CheckErrNotFound(err) {
			// 默认值
			dash.ClientDownloadHtml = base.DefaultDownloadHtml
		}
	}
	result["dashboard"] = map[string]any{
		"announcement_enabled": dash.AnnouncementEnabled,
		"announcement":         dash.Announcement,
		"announcement_level":   dash.AnnouncementLevel,
		"quick_links_enabled":  dash.QuickLinksEnabled,
		"quick_links":          dash.QuickLinks,
		"cards_visible":        dash.CardsVisible,
		"theme_color":          dash.ThemeColor,
		"custom_css":           dash.CustomCss,
		"client_guide":         dash.ClientGuide,
		"client_guide_enabled": dash.ClientGuideEnabled,
		"client_download_html": dash.ClientDownloadHtml,
	}
	return result
}
func portalGroupsDetail(groupNames []string, userPolicyId int) []map[string]any {
	allGroups, err := dbdata.GetAllGroups()
	if err != nil {
		return nil
	}
	groupMap := make(map[string]dbdata.Group, len(allGroups))
	for _, g := range allGroups {
		groupMap[g.Name] = g
	}

	result := make([]map[string]any, 0, len(groupNames))
	for _, gname := range groupNames {
		g, ok := groupMap[gname]
		if !ok {
			continue
		}
		info := map[string]any{
			"name":       g.Name,
			"note":       g.Note,
			"auth_types": portalAuthTypeLabels(g.AuthProfile),
			"dns":        portalDnsList(g.SplitDns),
			"status":     g.Status,
		}
		if userPolicyId == 0 && g.PolicyId > 0 {
			info["policy"] = portalPolicyInfo(g.PolicyId)
		}
		result = append(result, info)
	}
	return result
}

func portalAuthTypeLabels(raw json.RawMessage) []string {
	profile, err := auth.ParseAuthProfile(raw)
	if err != nil {
		return nil
	}
	labelMap := map[string]string{
		"local":    "本地密码",
		"ldap":     "LDAP",
		"radius":   "RADIUS",
		"cert":     "TLS证书",
		"otp":      "动态验证码",
		"wxwork":   "企微",
		"feishu":   "飞书",
		"dingtalk": "钉钉",
	}
	labels := make([]string, 0, len(profile.Step))
	for _, step := range profile.Step {
		label, ok := labelMap[step.Type]
		if !ok {
			label = step.Type
		}
		labels = append(labels, label)
	}
	return labels
}

func portalDnsList(splitDns []dbdata.ValData) []string {
	vals := make([]string, 0, len(splitDns))
	for _, d := range splitDns {
		if d.Val != "" {
			vals = append(vals, d.Val)
		}
	}
	return vals
}

func portalPolicyInfo(policyId int) map[string]any {
	if policyId <= 0 {
		return nil
	}
	var policy dbdata.Policy
	if err := dbdata.One("Id", policyId, &policy); err != nil {
		return nil
	}
	return map[string]any{
		"id":               policy.Id,
		"name":             policy.Name,
		"note":             policy.Note,
		"allow_lan":        policy.AllowLan,
		"bandwidth":        policy.Bandwidth,
		"bandwidth_up":     policy.BandwidthUp,
		"traffic_quota":    policy.TrafficQuota,
		"traffic_reset":    policy.TrafficReset,
		"route_include":    len(policy.RouteInclude),
		"route_exclude":    len(policy.RouteExclude),
		"ds_include_count": len(policy.DsIncludeDomains),
		"ds_exclude_count": len(policy.DsExcludeDomains),
		"acl_count":        len(policy.LinkAcl),
	}
}

func PortalMyGroups(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}
	portalOK(w, portalGroupsDetail(user.Groups, user.PolicyId))
}

func PortalOTPStatus(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}
	if user.OtpSecret == "" {
		portalOK(w, map[string]any{
			"enabled": false,
		})
		return
	}
	// 已设置 OTP 时返回状态及密钥，方便用户绑定多设备
	qrBase64, _ := portalGenerateOtpQr(user.Email, user.OtpSecret)
	portalOK(w, map[string]any{
		"enabled":   true,
		"disabled":  user.DisableOtp,
		"secret":    user.OtpSecret,
		"qr_base64": qrBase64,
	})
}

func PortalOTPRegenerate(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}
	if user.Type != "" && user.Type != "local" {
		portalError(w, "外部认证用户不支持自助重置二次验证")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}
	if req.Password == "" {
		portalError(w, "请输入当前密码确认")
		return
	}
	if err := portalCheckLocalPassword(user, req.Password); err != nil {
		portalError(w, "密码错误")
		return
	}

	secret := gotp.RandomSecret(32)
	if err := dbdata.Update("Id", user.Id, &dbdata.User{OtpSecret: secret, DisableOtp: false}); err != nil {
		base.Error("用户门户重置 OTP 失败:", err)
		portalError(w, "重置失败")
		return
	}
	qrBase64, _ := portalGenerateOtpQr(user.Email, secret)
	portalOK(w, map[string]any{
		"secret":    secret,
		"qr_base64": qrBase64,
	})
}

func portalGenerateOtpQr(email, secret string) (string, error) {
	issuer := url.QueryEscape(base.GetCfg().Issuer)
	qrstr := fmt.Sprintf("otpauth://totp/%s:%s?issuer=%s&secret=%s", issuer, email, issuer, secret)
	qr, err := qrcode.New(qrstr, qrcode.High)
	if err != nil {
		return "", err
	}
	png, err := qr.PNG(256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(png), nil
}

// 返回当前用户的所有客户端证书（不含私钥）
func PortalCertList(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}

	certs, err := dbdata.GetClientCertsByUsername(user.Username)
	if err != nil {
		portalError(w, "获取证书列表失败")
		return
	}

	type certItem struct {
		Id                   int       `json:"id"`
		Groupname            string    `json:"groupname"`
		Status               int       `json:"status"`
		StatusText           string    `json:"status_text"`
		IsCSRBased           bool      `json:"is_csr_based"`
		SerialNumber         string    `json:"serial_number"`
		NotAfter             time.Time `json:"not_after"`
		CreatedAt            time.Time `json:"created_at"`
		DeviceBindingEnabled bool      `json:"device_binding_enabled"`
		MaxDevices           int       `json:"max_devices"`
		DeviceCount          int       `json:"device_count"`
	}

	items := make([]certItem, 0, len(certs))
	for i := range certs {
		c := &certs[i]
		statusText := "有效"
		switch c.Status {
		case dbdata.CertStatusDisabled:
			statusText = "已禁用"
		case dbdata.CertStatusExpired:
			statusText = "已过期"
		}
		items = append(items, certItem{
			Id:                   c.Id,
			Groupname:            c.Groupname,
			Status:               c.Status,
			StatusText:           statusText,
			IsCSRBased:           c.IsCSRBased,
			SerialNumber:         c.SerialNumber,
			NotAfter:             c.NotAfter,
			CreatedAt:            c.CreatedAt,
			DeviceBindingEnabled: c.DeviceBindingEnabled,
			MaxDevices:           c.MaxDevices,
			DeviceCount:          len(c.DeviceId),
		})
	}
	portalOK(w, items)
}

// 下载当前用户的 P12 客户端证书（POST，密码在请求体中）
func PortalCertDownload(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}

	var req struct {
		Groupname string `json:"groupname"`
		Password  string `json:"password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		portalError(w, "参数错误")
		return
	}

	if req.Groupname == "" {
		portalError(w, "用户组不能为空")
		return
	}
	if req.Password == "" {
		portalError(w, "P12加密密码不能为空")
		return
	}

	// 安全校验：确保证书属于当前用户
	cert, err := dbdata.GetClientCert(user.Username, req.Groupname)
	if err != nil {
		if dbdata.CheckErrNotFound(err) {
			portalError(w, "未找到该证书")
		} else {
			portalError(w, "获取证书失败")
		}
		return
	}

	// CSR 模式直接返回 PEM 证书
	if cert.IsCSRBased {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.cer", user.Username))
		w.Write([]byte(cert.Certificate))
		return
	}

	// 生成 P12
	p12Data, err := dbdata.GenerateClientP12FromDB(user.Username, req.Groupname, req.Password)
	if err != nil {
		portalError(w, fmt.Sprintf("证书下载失败: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.p12", user.Username))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(p12Data)))
	w.Write(p12Data)
}

// 返回当前用户的在线设备列表
func PortalDevices(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}

	sessions := sessdata.GetOnlineSess("username", user.Username, false)
	type deviceItem struct {
		Token            string `json:"token"`
		Ip               string `json:"ip"`
		MacAddr          string `json:"mac_addr"`
		RemoteAddr       string `json:"remote_addr"`
		Transport        string `json:"transport"`
		Client           string `json:"client"`
		DeviceType       string `json:"device_type"`
		PlatformVersion  string `json:"platform_version"`
		BandwidthUp      string `json:"bandwidth_up"`
		BandwidthDown    string `json:"bandwidth_down"`
		BandwidthUpAll   string `json:"bandwidth_up_all"`
		BandwidthDownAll string `json:"bandwidth_down_all"`
		LastLogin        string `json:"last_login"`
	}
	items := make([]deviceItem, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, deviceItem{
			Token:            s.Token,
			Ip:               s.Ip.String(),
			MacAddr:          s.MacAddr,
			RemoteAddr:       s.RemoteAddr,
			Transport:        s.TransportProtocol,
			Client:           s.Client,
			DeviceType:       s.DeviceType,
			PlatformVersion:  s.PlatformVersion,
			BandwidthUp:      s.BandwidthUp,
			BandwidthDown:    s.BandwidthDown,
			BandwidthUpAll:   s.BandwidthUpAll,
			BandwidthDownAll: s.BandwidthDownAll,
			LastLogin:        s.LastLogin.Format("2006-01-02 15:04:05"),
		})
	}
	portalOK(w, items)
}

// 踢下线指定设备
func PortalDeviceOffline(w http.ResponseWriter, r *http.Request) {
	if !base.GetCfg().EnableUserPortal {
		http.NotFound(w, r)
		return
	}
	user, ok := portalCurrentUser(r)
	if !ok {
		portalUnauthorized(w)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		portalError(w, "参数错误")
		return
	}

	// 校验该 session 属于当前用户
	sessions := sessdata.GetOnlineSess("username", user.Username, false)
	found := false
	for _, s := range sessions {
		if s.Token == req.Token {
			found = true
			break
		}
	}
	if !found {
		portalError(w, "设备不存在或已离线")
		return
	}

	sessdata.CloseSess(req.Token, dbdata.UserLogoutClient)
	portalOK(w, map[string]string{"message": "已断开该设备连接"})
}

func portalOK(w http.ResponseWriter, data any) {
	portalJSON(w, http.StatusOK, map[string]any{
		"code": 0,
		"msg":  "ok",
		"data": data,
	})
}

func portalError(w http.ResponseWriter, msg string) {
	portalJSON(w, http.StatusOK, map[string]any{
		"code": 1,
		"msg":  msg,
	})
}

func portalUnauthorized(w http.ResponseWriter) {
	portalJSON(w, http.StatusUnauthorized, map[string]any{
		"code": 401,
		"msg":  "请先登录",
	})
}

func portalJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
