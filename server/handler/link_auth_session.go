// 认证会话管理：存储、CRUD、Cookie 操作。

package handler

import (
	"crypto/md5"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/wsczx/remlink/auth"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/wsczx/remlink/sessdata"
)

// SessionStore 临时认证会话存储
type SessionStore struct {
	sessions map[string]*AuthSession
	mu       sync.Mutex
	stopCh   chan struct{}
	stopOnce sync.Once
	started  bool
	stopped  bool
}

// 启动后台定期清理过期会话（每分钟扫描一次，TTL 5分钟）
func (s *SessionStore) StartCleanup() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.stopped = false
	s.stopCh = make(chan struct{})
	stopCh := s.stopCh
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.cleanExpired()
			case <-stopCh:
				return
			}
		}
	}()
}

// 清理过期的会话
func (s *SessionStore) cleanExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, session := range s.sessions {
		if now.Sub(session.CreatedAt) > 5*time.Minute {
			delete(s.sessions, id)
		}
	}
}

// 停止后台清理
func (s *SessionStore) StopCleanup() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.stopped = true
		s.started = false
		s.mu.Unlock()
		close(s.stopCh)
	})
}

// 保存会话
func (s *SessionStore) Save(id string, data *AuthSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = data
}

// 获取会话
func (s *SessionStore) Get(id string) (*AuthSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, ok := s.sessions[id]
	if !ok {
		return nil, fmt.Errorf("会话未找到")
	}
	return v, nil
}

// 删除会话
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

var SessStore = &SessionStore{
	sessions: make(map[string]*AuthSession),
	stopCh:   make(chan struct{}),
}
var lockManager = auth.GetLockManager()

// 认证流程的临时会话
// 步骤状态、用户信息、连接信息、Resume 断点均保存在 Ctx 内。
type AuthSession struct {
	SessionID  string             // 认证会话ID
	Ctx        *auth.Context      // 认证上下文
	UserActLog *dbdata.UserActLog // 审计日志
	ForcePwd   bool               // 强制改密会话
	CreatedAt  time.Time
}

// 保存认证会话
func SaveAuthSession(id string, session *AuthSession) {
	session.CreatedAt = time.Now()
	session.SessionID = id
	SessStore.Save(id, session)
}

// 获取认证会话
func GetAuthSession(id string) (*AuthSession, error) {
	session, err := SessStore.Get(id)
	if err != nil {
		return nil, err
	}
	if time.Since(session.CreatedAt) > 5*time.Minute {
		SessStore.Delete(id)
		return nil, fmt.Errorf("会话过期")
	}
	session.SessionID = id
	return session, nil
}

// 创建用户会话并返回认证完成 XML
func CreateSession(w http.ResponseWriter, authSession *AuthSession) {
	ua := authSession.UserActLog
	ctx := authSession.Ctx

	sess := sessdata.NewSession("")
	sess.Username = ctx.Conn.Username
	sess.Group = ctx.Conn.GroupName
	if ctx.UserInfo != nil {
		sess.LimitTime = ctx.UserInfo.LimitTime
	}
	oriMac := ctx.Conn.MacAddr
	sess.UniqueIdGlobal = ctx.Conn.DeviceID
	sess.UserAgent = ctx.Conn.UserAgent
	sess.DeviceType = ua.DeviceType
	sess.PlatformVersion = ua.PlatformVersion
	sess.RemoteAddr = ctx.Conn.RemoteAddr
	sess.UniqueMac = true
	macHw, err := net.ParseMAC(oriMac)
	if err != nil {
		var sum [16]byte
		if sess.UniqueIdGlobal != "" {
			sum = md5.Sum([]byte(sess.UniqueIdGlobal))
		} else {
			sum = md5.Sum([]byte(sess.Token))
			sess.UniqueMac = false
		}
		macHw = sum[0:5]
		macHw = append([]byte{0x02}, macHw...)
		sess.MacAddr = macHw.String()
	}
	sess.MacHw = macHw
	sess.MacAddr = macHw.String()

	other := &dbdata.SettingOther{}
	dbdata.SettingGet(other)
	profileHash, err := dbdata.GetProfileHash()
	if err != nil {
		base.Error(err)
		http.Error(w, "profile err", http.StatusInternalServerError)
		return
	}
	rd := RequestData{
		SessionId:    sess.Sid,
		SessionToken: sess.Sid + "@" + sess.Token,
		ProfileName:  base.GetCfg().ProfileName,
		ProfileHash:  profileHash,
		CertHash:     certHash.Load().(string),
	}
	if other.BannerEnable {
		rd.Banner = other.Banner
	}

	w.WriteHeader(http.StatusOK)
	tplRequest(tpl_complete, w, rd)
	base.Info("login", ctx.Conn.Username, ctx.Conn.UserAgent)
}

// 设置认证会话 Cookie
func SetCookie(w http.ResponseWriter, name, value string, maxAge int) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   maxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// 获取指定名称的 Cookie 值
func GetCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", fmt.Errorf("failed to get cookie: %v", err)
	}
	return cookie.Value, nil
}

// 删除认证会话 Cookie
func DeleteCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)
}

// 生成 32 位随机会话 ID
func GenerateSessionID() string {
	return utils.RandomRunes(32)
}
