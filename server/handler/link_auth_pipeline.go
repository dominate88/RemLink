// 认证管道交互层，将 auth.PipelineResult 映射为 HTTP 响应。

package handler

import (
	"net/http"
	"strings"

	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/auth/authsrv"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// 认证阶段名前缀，用于过滤错误信息
var stepNamePrefixes = []string{
	"cert:", "local:", "ldap:", "radius:", "otp:", "wxwork:", "feishu:", "saml:", "admin:",
}

// 认证失败时，将错误信息映射为用户可读的文案。
func stripStepPrefix(msg string) string {
	for _, p := range stepNamePrefixes {
		if strings.HasPrefix(msg, p) {
			return msg[len(p):]
		}
	}
	return msg
}

// 认证失败时，根据错误类型返回面向用户的错误信息。
func authFailMessage(err error) string {
	if err == nil {
		return "认证失败"
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "cert:"):
		return "客户端证书认证失败，请检查客户端证书"
	case strings.HasPrefix(msg, "wxwork:"), strings.HasPrefix(msg, "feishu:"):
		return "单点登录认证失败"
	case strings.HasPrefix(msg, "otp:"):
		return "动态码验证失败"
	default:
		// local/ldap/radius 等凭据认证：统一文案，避免用户枚举
		return "用户名或密码错误"
	}
}

// 从 ClientRequest 构建认证上下文（首次认证用）。
func newAuthContext(cr *ClientRequest, r *http.Request) *auth.Context {
	return &auth.Context{
		Conn: auth.ConnInfo{
			Username:    cr.Auth.Username,
			Password:    cr.Auth.Password,
			GroupName:   cr.GroupSelect,
			RemoteAddr:  r.RemoteAddr,
			UserAgent:   cr.UserAgent,
			MacAddr:     cr.MacAddressList.MacAddress,
			DeviceID:    cr.DeviceId.UniqueIdGlobal,
			DeviceType:  cr.DeviceId.DeviceType,
			PlatformVer: cr.DeviceId.PlatformVersion,
			TLS:         r.TLS,
		},
	}
}

// 从已保存的认证会话恢复管道执行。
// 调用前需将当前请求的密码/OTP 码写入 ctx。
func resumeAuthSession(w http.ResponseWriter, r *http.Request,
	sess *AuthSession) {

	ctx := sess.Ctx
	// TLS 需从当前请求重新注入
	ctx.Conn.TLS = r.TLS
	ctx.Conn.RemoteAddr = r.RemoteAddr
	// 重新加载用户信息，用户在断点期间可能已改密或清除强制改密标记
	authsrv.ReloadUserInfo(ctx)

	state := auth.PipelineState{
		StepIdx:     sess.Ctx.StepIdx(),
		PassedSteps: sess.Ctx.PassedSteps(),
	}
	result := authsrv.Resume(ctx, state)
	handlePipelineResult(w, r, result, sess)
}

// 将管道执行结果映射为 HTTP 响应。
func handlePipelineResult(w http.ResponseWriter, r *http.Request,
	result *auth.PipelineResult, sessionData *AuthSession) {

	ctx := sessionData.Ctx

	// 管道恢复场景：StepPass/StepFail 后清除旧认证会话
	if sessionData.SessionID != "" && result.Result != auth.StepPending {
		AuthSessionManager.Delete(sessionData.SessionID)
		DeleteCookie(w, "auth-session-id")
	}

	switch result.Result {
	case auth.StepPass:
		sessionData.UserActLog.Username = result.Username
		sessionData.UserActLog.GroupName = result.GroupName
		sessionData.UserActLog.Info = result.Info
		if sessionData.UserActLog.Info == "" {
			sessionData.UserActLog.Info = "认证成功"
		}
		sessionData.UserActLog.Status = dbdata.UserAuthSuccess
		dbdata.UserActLogIns.Add(*sessionData.UserActLog, ctx.Conn.UserAgent)

		ctx.Conn.Username = result.Username
		ctx.Conn.GroupName = result.GroupName
		lockManager.Success(result.Username, r.RemoteAddr)
		CreateSession(w, sessionData)

	case auth.StepFail:
		lockManager.Fail(ctx.Conn.Username, r.RemoteAddr)
		errMsg := "认证失败"
		if result.Err != nil {
			errMsg = result.Err.Error()
		}
		base.Warn("认证失败:", result.Err, r.RemoteAddr)
		sessionData.UserActLog.Info = errMsg
		sessionData.UserActLog.Status = dbdata.UserAuthFail
		dbdata.UserActLogIns.Add(*sessionData.UserActLog, ctx.Conn.UserAgent)

		w.WriteHeader(http.StatusOK)
		data := RequestData{
			Group:  ctx.Conn.GroupName,
			Groups: dbdata.GetGroupNamesNormal(),
			Error:  authFailMessage(result.Err),
		}
		if base.GetCfg().DisplayError && result.Err != nil {
			data.Error = stripStepPrefix(errMsg)
		}
		tplRequest(tpl_request, w, data)

	case auth.StepPending:
		handleChallengeResult(w, r, result, sessionData)
	}
}

// 处理 StepPending：保存/更新会话状态 + 按挑战类型返回模板。
func handleChallengeResult(w http.ResponseWriter, r *http.Request,
	result *auth.PipelineResult, sessionData *AuthSession) {

	challenge := result.Challenge
	if challenge == nil {
		base.Error("StepPending 但无 Challenge 信息")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ctx := sessionData.Ctx
	isResume := sessionData.SessionID != ""
	retry := result.IsChallengeRetry() // 挑战码错误，计入锁定计数

	// 保存断点信息到 Ctx，供下次 Resume 恢复
	ctx.SetStepIdx(result.State.StepIdx)
	ctx.SetPassedSteps(result.State.PassedSteps)

	if isResume {
		// 恢复场景：更新已有会话
		AuthSessionManager.Save(sessionData.SessionID, sessionData)
	} else {
		// 首次认证：创建新会话
		sid := GenerateSessionID()
		AuthSessionManager.Save(sid, sessionData)
		SetCookie(w, "auth-session-id", sid, 0)
	}
	// 清除强制改密标记
	sessionData.ForcePwd = false

	// 按挑战类型返回模板
	switch challenge.Type {
	case auth.ChallengeOTP:
		if retry {
			// OTP 码错误，递增锁定计数
			lockManager.Fail(result.Username, r.RemoteAddr)
			w.WriteHeader(http.StatusOK)
			tplRequest(tpl_otp, w, RequestData{Error: "OTP 动态码错误，请重新输入"})
		} else {
			// 首次 OTP 挑战：前序密码已通过，重置计数器给 OTP 阶段独立计数窗口
			lockManager.Success(result.Username, r.RemoteAddr)
			w.WriteHeader(http.StatusOK)
			tplRequest(tpl_otp, w, RequestData{})
		}

	case auth.ChallengeRADIUS:
		msg := ""
		if ctx.RADIUS != nil {
			msg = ctx.RADIUS.ChallengeMsg
		}
		if retry {
			// 验证码错误，递增锁定计数
			if result.Username != "" {
				lockManager.Fail(result.Username, r.RemoteAddr)
			}
			if msg == "" {
				msg = "验证失败，请重新输入二次验证码"
			}
		} else {
			// 首次 RADIUS 挑战：前序凭据已通过，重置计数器（同 OTP）
			if result.Username != "" {
				lockManager.Success(result.Username, r.RemoteAddr)
			}
			if msg == "" {
				msg = "请输入二次验证码"
			}
		}
		w.WriteHeader(http.StatusOK)
		tplRequest(tpl_accept_challenge, w, RequestData{Error: msg, Group: result.GroupName})

	case auth.ChallengeSSO:
		// 手机端无法完成企微/飞书扫码，默认拒绝；开启 allow_mobile_sso 后放行
		if isMobileDevice(r) && !base.GetCfg().AllowMobileSSO {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ssoType, _ := challenge.Data["sso_type"].(string)
		browserMode := samlBrowserMode(r, ssoType, result.GroupName)
		data := RequestData{
			Group:       result.GroupName,
			Groups:      dbdata.GetGroupNamesNormal(),
			ServerAddr:  getServerAddr(r),
			BrowserMode: browserMode,
			SsoType:     ssoType,
		}
		w.WriteHeader(http.StatusOK)
		tplRequest(tpl_request_saml, w, data)

	case auth.ChallengeForcePwd:
		data := RequestData{
			Group:      result.GroupName,
			Groups:     dbdata.GetGroupNamesNormal(),
			ServerAddr: getServerAddr(r),
			State:      sessionData.SessionID,
		}
		sessionData.ForcePwd = true
		w.WriteHeader(http.StatusOK)
		tplRequest(tpl_request_force_pwd, w, data)

	default:
		w.WriteHeader(http.StatusOK)
		data := RequestData{Group: ctx.Conn.GroupName, Groups: dbdata.GetGroupNamesNormal()}
		tplRequest(tpl_request, w, data)
	}
}
