package webvpn

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// 异步批量写入 WebVPN 访问审计：proxy 请求完成后投递一条记录到 channel
// 由后台 goroutine 定时（1s）批量写库，避免高频请求直写库
type AuditBatcher struct {
	queue   chan dbdata.WebVpnAudit
	quit    chan struct{}
	done    chan struct{}
	started atomic.Bool
	doneMu  sync.Mutex
}

// 构造审计批处理器
func NewAuditBatcher() *AuditBatcher {
	return &AuditBatcher{
		queue: make(chan dbdata.WebVpnAudit, 1000),
		quit:  make(chan struct{}),
	}
}

// 非阻塞投递审计记录：队列满则降级处理，审计不应影响代理主路径
// 普通记录（risk=0）直接丢弃；可疑/高危记录（risk>=1）降级为本地日志打印
// 避免突发高并发或 DB 写入慢时安全审计盲区
func (b *AuditBatcher) Log(rec dbdata.WebVpnAudit) {
	select {
	case b.queue <- rec:
	default:
		if rec.RiskLevel >= 1 {
			base.Warn("WebVPN 审计队列已满，降级本地记录:",
				rec.Username, rec.Method, rec.Host, rec.Path, rec.StatusCode, rec.RiskLevel)
		}
	}
}

// 启动后台批处理（进程启动调用一次）
func (b *AuditBatcher) Start() {
	if !b.started.CompareAndSwap(false, true) {
		return
	}
	b.doneMu.Lock()
	b.done = make(chan struct{})
	b.doneMu.Unlock()
	go b.batchWriter()
}

// 停止批处理并等待在途记录落库，避免在 DB 关闭后写入
func (b *AuditBatcher) Stop() {
	if !b.started.Load() {
		return
	}
	b.quit <- struct{}{}
	b.doneMu.Lock()
	done := b.done
	b.doneMu.Unlock()
	<-done
	b.started.Store(false)
}

func (b *AuditBatcher) batchWriter() {
	base.Debug("WebVPN 审计批处理已启动")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var batch []dbdata.WebVpnAudit
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := dbdata.AddBatchWebVpnAudit(batch); err != nil {
			base.Warn("WebVPN 审计批量写入失败:", err)
		}
		batch = nil
	}
	for {
		select {
		case rec := <-b.queue:
			batch = append(batch, rec)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.quit:
			flush()
			base.Debug("WebVPN 审计批处理已退出")
			close(b.done)
			return
		}
	}
}

// 依据响应状态码给出审计风险等级：0=正常 1=可疑 2=高危。
// 4xx 归为可疑，5xx 归为高危，其余正常。
func RiskOf(statusCode int) int8 {
	switch {
	case statusCode >= 500:
		return 2
	case statusCode >= 400:
		return 1
	default:
		return 0
	}
}
