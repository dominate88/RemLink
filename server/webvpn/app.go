package webvpn

import (
	"sync"
	"time"

	"github.com/wsczx/remlink/dbdata"
)

// 管理 WebVPN 应用配置的进程内缓存与授权判断
// 持久化仍由 dbdata 层负责；此处仅做查询缓存，避免每个请求都查库
type AppStore struct {
	mu     sync.RWMutex
	m      map[string]*dbdata.WebVpnApp
	expire time.Time
	ttl    time.Duration
}

// 构造应用缓存（TTL 60s 兜底，配置变更后主动失效）
func NewAppStore() *AppStore {
	return &AppStore{
		m:   make(map[string]*dbdata.WebVpnApp),
		ttl: 60 * time.Second,
	}
}

// 按子域名前缀（Name）查找应用，带进程内缓存
func (s *AppStore) GetByName(name string) (*dbdata.WebVpnApp, error) {
	s.mu.RLock()
	hit := s.m[name]
	fresh := time.Now().Before(s.expire)
	s.mu.RUnlock()
	if hit != nil && fresh {
		return hit, nil
	}

	a, err := dbdata.GetWebVpnAppByName(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.m[name] = a
	s.expire = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return a, nil
}

// 主动失效缓存（配置变更后调用）
func (s *AppStore) Invalidate() {
	s.mu.Lock()
	s.m = make(map[string]*dbdata.WebVpnApp)
	s.mu.Unlock()
}

// 返回某用户有权访问的启用中的应用（用户维度授权）
func (s *AppStore) AppsForUser(user *dbdata.User) ([]dbdata.WebVpnApp, error) {
	var all []dbdata.WebVpnApp
	if err := dbdata.Find(&all, -1, 0); err != nil {
		return nil, err
	}
	result := make([]dbdata.WebVpnApp, 0, len(all))
	for _, a := range all {
		if a.Status != 1 {
			continue
		}
		if !dbdata.WebVpnUserAllowed(&a, user) {
			continue
		}
		result = append(result, a)
	}
	return result, nil
}

// 判断用户是否有权访问某应用（用户维度 + 请求级来源 IP/路径）
// 具体 IP/路径校验由调用方在 proxy 阶段执行，这里只做用户维度兜底
func (s *AppStore) Authorized(app *dbdata.WebVpnApp, user *dbdata.User) bool {
	return dbdata.WebVpnUserAllowed(app, user)
}
