package handler

import (
	"testing"
	"time"
)

// Start 重复调用只应启动一个协程，且不覆盖 stopCh
// 修复前：重复 Start 会覆盖 stopCh，旧协程收不到停止信号永久泄漏，Stop 的 wg.Wait 永久阻塞
func TestAuthSessionManagerStartIdempotent(t *testing.T) {
	m := NewAuthSessionManager()
	m.cleanupInterval = 10 * time.Millisecond

	m.Start()
	m.Start()
	m.Start()

	done := make(chan struct{})
	go func() {
		m.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 超时未返回：Start 重复调用导致协程泄漏")
	}
}

// 未 Start 直接 Stop 不应 panic
// 修复前：stopCh 为 nil，close(nil) 直接 panic
func TestAuthSessionManagerStopBeforeStart(t *testing.T) {
	m := NewAuthSessionManager()
	m.Stop()
}

// Stop 重复调用应安全
func TestAuthSessionManagerStopIdempotent(t *testing.T) {
	m := NewAuthSessionManager()
	m.cleanupInterval = 10 * time.Millisecond

	m.Start()
	m.Stop()
	m.Stop()
}

// Stop 后应可重新 Start
// 修复前：stopOnce + stopped 使 Stop 不可逆，重启后的清理协程永远不会启动
func TestAuthSessionManagerRestart(t *testing.T) {
	m := NewAuthSessionManager()
	m.ttl = 20 * time.Millisecond
	m.cleanupInterval = 10 * time.Millisecond

	m.Start()
	m.Stop()
	m.Start()
	defer m.Stop()

	m.Save("restart-id", &AuthSession{})
	if _, err := m.Get("restart-id"); err != nil {
		t.Fatalf("会话保存后应可读取: %v", err)
	}

	// 重启后清理协程应正常工作，过期会话被回收
	deadline := time.After(2 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.sessions)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("重启后清理协程未运行：过期会话未被回收")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// 过期会话读取应失败（TTL 校验在 Get 内）
func TestAuthSessionManagerGetExpired(t *testing.T) {
	m := NewAuthSessionManager()
	m.ttl = 10 * time.Millisecond

	m.Save("expire-id", &AuthSession{})
	if _, err := m.Get("expire-id"); err != nil {
		t.Fatalf("未过期会话应可读取: %v", err)
	}

	time.Sleep(30 * time.Millisecond)
	if _, err := m.Get("expire-id"); err == nil {
		t.Fatal("过期会话不应可读取")
	}
}
