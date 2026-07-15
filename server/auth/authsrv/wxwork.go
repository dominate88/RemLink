package authsrv

import (
	"fmt"

	"github.com/wsczx/remlink/auth"
)

func init() {
	auth.Register("wxwork", func() auth.Authenticator {
		return &WXWorkAuth{}
	})
}

// WXWorkAuth 企业微信认证配置（嵌入共享 WXWorkConfig，API 方法由父类型提供）
type WXWorkAuth struct {
	auth.WXWorkConfig
}

func (a *WXWorkAuth) Name() string { return "wxwork" }

func (a *WXWorkAuth) Authenticate(ctx *auth.Context) (auth.StepResult, error) {
	if sso := ctx.SSO; sso != nil {
		// 路径 1：SSO 回调已完成，用户身份 + 部门在回调阶段校验。
		// handleSsoToken 从 SSO 会话恢复此标记，此处直接放行。
		if sso.Authenticated && sso.UserID != "" {
			ctx.Conn.Username = sso.UserID
			ctx.SetInfo("用户通过企业微信认证登录")
			return auth.StepPass, nil
		}

		// 路径 2：管道内 SSO 流程，通过 OAuth code 换取用户信息
		if sso.Code != "" {
			userID, err := a.GetWeworkUser(sso.Code)
			if err != nil {
				return auth.StepFail, fmt.Errorf("企业微信认证失败: %w", err)
			}

			allowedDepts := a.ParseDepartments()
			if len(allowedDepts) > 0 {
				accessToken, err := a.GetAccessToken()
				if err != nil {
					return auth.StepFail, fmt.Errorf("获取企微 access_token 失败: %w", err)
				}
				ok, err := a.CheckUserDepartment(accessToken, userID, allowedDepts)
				if err != nil {
					return auth.StepFail, fmt.Errorf("验证部门失败: %w", err)
				}
				if !ok {
					return auth.StepFail, fmt.Errorf("用户不在允许的部门范围内")
				}
			}

			ctx.Conn.Username = userID
			ctx.SetInfo("用户通过企业微信认证登录")
			return auth.StepPass, nil
		}
	}

	ctx.SetInfo("需要通过企业微信 SSO 认证")
	return auth.StepPending, nil
}

func (a *WXWorkAuth) Challenge() *auth.ChallengeInfo {
	return &auth.ChallengeInfo{
		Type:     auth.ChallengeSSO,
		Template: "saml",
		Data: map[string]any{
			"sso_type":            "wxwork",
			"use_default_browser": a.UseDefaultBrowser,
		},
	}
}
