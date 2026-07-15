// OTP 验证入口，通过 Cookie 恢复认证管道并执行 OTP 挑战。

package handler

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/wsczx/remlink/auth/authsrv"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/notify"
	"github.com/xlzd/gotp"
)

// OTP 验证入口（独立窗口模式），通过 Cookie 恢复 Pipeline
func LinkAuth_otp(w http.ResponseWriter, r *http.Request) {
	sessionID, err := GetCookie(r, "auth-session-id")
	if err != nil {
		http.Error(w, "会话已过期，请重新登录", http.StatusUnauthorized)
		return
	}

	sessionData, err := GetAuthSession(sessionID)
	if err != nil {
		http.Error(w, "会话已过期，请重新登录", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		base.Error(err)
		SessStore.Delete(sessionID)
		DeleteCookie(w, "auth-session-id")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	cr := &ClientRequest{}
	err = xml.Unmarshal(body, cr)
	if err != nil {
		base.Error(err)
		SessStore.Delete(sessionID)
		DeleteCookie(w, "auth-session-id")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	username := sessionData.Ctx.Conn.Username

	// 锁定状态判断
	if !lockManager.Check(username, r.RemoteAddr) {
		w.WriteHeader(http.StatusTooManyRequests)
		SessStore.Delete(sessionID)
		DeleteCookie(w, "auth-session-id")
		return
	}

	// 将 OTP 码注入 Context（挑战响应）
	if sp := cr.Auth.SecondaryPassword; sp != "" {
		sessionData.Ctx.GetOTP().Code = sp
		sessionData.Ctx.GetRADIUS().ChallengeCode = sp
	}
	sessionData.Ctx.Conn.TLS = r.TLS
	sessionData.Ctx.Conn.RemoteAddr = r.RemoteAddr

	resumeAuthSession(w, r, sessionData)
}

func init() {
	authsrv.SendOtpFunc = SendOtpToUser
}

// 生成 OTP 验证码并发送给用户（邮件/短信）
func SendOtpToUser(username string) error {
	user := &dbdata.User{}
	if err := dbdata.One("Username", username, user); err != nil {
		return fmt.Errorf("用户不存在: %v", err)
	}

	if user.OtpSecret == "" {
		return fmt.Errorf("用户未启用 OTP")
	}

	// 生成当前 TOTP 动态码
	otp := gotp.NewDefaultTOTP(user.OtpSecret).Now()

	n := notify.GetNotify()
	switch base.GetCfg().SendOtpType {
	case "mail":
		if user.Email == "" {
			return fmt.Errorf("用户邮箱为空")
		}
		return n.SendEmail(notify.Message{
			Subject: base.GetCfg().Issuer,
			To:      user.Email,
			Body:    fmt.Sprintf("您的 OTP 验证码是: %s，有效期60秒", otp),
		})
	case "phone":
		if user.Phone == "" {
			return fmt.Errorf("用户手机号为空")
		}
		return n.SendSms(notify.Message{
			To:     user.Phone,
			Params: map[string]string{"1": otp, "2": "1"},
		})
	default:
		return fmt.Errorf("未知的发送方式: %s", base.GetCfg().SendOtpType)
	}
}
