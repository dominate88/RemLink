package webvpn

import (
	"sync"

	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// WebVPN 子系统的中心对象，聚合所有子组件
// 通过 GetManager 获取单例，进程启动时调用 Start、退出时调用 Stop
type manager struct {
	apps    *AppStore
	session *AuthSessionManager
	audit   *AuditBatcher
	revoker *Revoker
}

var (
	once sync.Once
	mgr  *manager
)

// 返回 WebVPN 子系统单例（懒初始化）
func GetManager() *manager {
	once.Do(func() {
		mgr = &manager{
			apps:    NewAppStore(),
			session: NewSessionManager(),
			audit:   NewAuditBatcher(),
			revoker: NewRevoker(),
		}
	})
	return mgr
}

// 启动子系统：加载整用户踢出阈值到内存，并启动审计批处理。进程启动时调用一次
func (m *manager) Start() {
	dbdata.LoadWebVpnRevoke()
	m.audit.Start()
	base.Debug("WebVPN 子系统已启动")
}

// 停止子系统后台任务，等待在途审计落库。进程退出时调用
func (m *manager) Stop() {
	m.audit.Stop()
	base.Debug("WebVPN 子系统已停止")
}

// 返回应用配置存储，供 handler 查询/展示使用
func (m *manager) Apps() *AppStore { return m.apps }

// 返回会话管理器，供 handler 签发/校验/续期/吊销会话使用
func (m *manager) Session() *AuthSessionManager { return m.session }

// 返回审计批处理器，供 proxy 投递访问记录使用
func (m *manager) Audit() *AuditBatcher { return m.audit }

// 返回整用户踢出器，供管理后台调用
func (m *manager) Revoker() *Revoker { return m.revoker }
