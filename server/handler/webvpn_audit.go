package handler

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/dbdata"
)

// WebVPN 访问审计批处理：proxy 请求完成后投递一条记录到 channel，
// 由后台 goroutine 定时（1s）批量写入 DB，避免高频请求直写库。
var (
	webVpnAuditQueue = make(chan dbdata.WebVpnAudit, 1000)
	webVpnAuditQuit  = make(chan struct{})
	webVpnAuditDone  = make(chan struct{})
)

// 非阻塞投递：队列满则丢弃，审计不应影响代理主路径。
func webVpnAuditLog(rec dbdata.WebVpnAudit) {
	select {
	case webVpnAuditQueue <- rec:
	default:
		base.Warn("WebVPN 审计队列已满，丢弃一条记录")
	}
}

func webVpnAuditBatchWriter() {
	base.Info("WebVPN 审计批处理已启动")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var batch []dbdata.WebVpnAudit
	for {
		select {
		case rec := <-webVpnAuditQueue:
			batch = append(batch, rec)
			if len(batch) >= 100 {
				flushWebVpnAudit(batch)
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				flushWebVpnAudit(batch)
				batch = nil
			}
		case <-webVpnAuditQuit:
			if len(batch) > 0 {
				flushWebVpnAudit(batch)
			}
			base.Info("WebVPN 审计批处理已退出")
			close(webVpnAuditDone)
			return
		}
	}
}

func flushWebVpnAudit(batch []dbdata.WebVpnAudit) {
	if err := dbdata.AddBatchWebVpnAudit(batch); err != nil {
		base.Warn("WebVPN 审计批量写入失败:", err)
	}
}

// 审计批处理启动标志（程序启动时调用一次）
var (
	webVpnAuditStarted atomic.Bool
	webVpnAuditDoneMu  sync.Mutex
)

func webVpnAuditStart() {
	if !webVpnAuditStarted.CompareAndSwap(false, true) {
		return // 已启动，不重复拉起 goroutine
	}
	webVpnAuditDoneMu.Lock()
	webVpnAuditDone = make(chan struct{})
	webVpnAuditDoneMu.Unlock()
	go webVpnAuditBatchWriter()
}

// 停止审计批处理
func webVpnAuditStop() {
	// 仅当已启动时才发送退出信号，避免向无接收者的 channel 阻塞发送
	if !webVpnAuditStarted.Load() {
		return
	}
	webVpnAuditQuit <- struct{}{}
	webVpnAuditDoneMu.Lock()
	done := webVpnAuditDone
	webVpnAuditDoneMu.Unlock()
	<-done                          // 等待 writer flush 完毕，避免在 DB 关闭后写入
	webVpnAuditStarted.Store(false) // 允许后续重启（测试场景用）
}

// 依据响应状态码给出审计风险等级：0=正常 1=可疑 2=高危。
// 4xx（客户端被拒/未找到等异常访问）归为可疑，5xx（后端异常）归为高危，其余正常。
func webVpnAuditRisk(statusCode int) int8 {
	switch {
	case statusCode >= 500:
		return 2
	case statusCode >= 400:
		return 1
	default:
		return 0
	}
}
