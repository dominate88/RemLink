package auth

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wsczx/remlink/base"
	"github.com/stretchr/testify/assert"
)

// 重置单例以隔离测试
func resetLockManager() {
	lmOnce = sync.Once{}
	lm = nil
}

// 配置测试用的 config
func setupTestConfig() {
	base.SetCfgForTest(&base.ServerConfig{
		AntiBruteForce:                true,
		IPWhiteList:                   "192.168.90.1,172.16.0.0/24",
		IPBlackList:                   "10.0.0.1",
		MaxBanCount:                   5,
		BanResetTime:                  600,
		LockTime:                      300,
		MaxGlobalUserBanCount:         20,
		GlobalUserBanResetTime:        600,
		GlobalUserLockTime:            300,
		MaxGlobalIPBanCount:           40,
		GlobalIPBanResetTime:          1200,
		GlobalIPLockTime:              300,
		GlobalLockStateExpirationTime: 3600,
	})
}

func TestGetLockManager(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	t.Run("Singleton_Pattern", func(t *testing.T) {
		lm1 := GetLockManager()
		lm2 := GetLockManager()
		assert.Same(t, lm1, lm2, "GetLockManager应该返回同一个实例")
	})
}

func TestLockManager_RaceConditions(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("Concurrent_CheckAndUpdate", func(t *testing.T) {
		username := "raceuser"
		ipaddr := "192.168.1.10:12345"

		var wg sync.WaitGroup
		results := make([]bool, 20)

		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				if index%2 == 0 {
					results[index] = lm.Check(username, ipaddr)
				} else {
					lm.Fail(username, ipaddr)
				}
			}(i)
		}

		wg.Wait()

		finalResult := lm.Check(username, ipaddr)
		assert.False(t, finalResult, "高并发后应该被锁定")
	})

	t.Run("Concurrent_MultipleUsers", func(t *testing.T) {
		ipaddr := "192.168.1.11:12345"
		var wg sync.WaitGroup

		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(userIndex int) {
				defer wg.Done()
				username := fmt.Sprintf("user%d", userIndex)
				lm.Fail(username, ipaddr)
			}(i)
		}

		wg.Wait()

		result := lm.Check("newuser", ipaddr)
		assert.False(t, result, "多用户并发攻击后IP应该被全局锁定")
	})

	t.Run("Concurrent_CleanupAndUpdate", func(t *testing.T) {
		username := "cleanuprace"
		ipaddr := "192.168.1.12:12345"

		lm.Fail(username, ipaddr)

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			lm.cleanup()
		}()
		go func() {
			defer wg.Done()
			lm.Fail(username, ipaddr)
		}()
		wg.Wait()

		result := lm.Check(username, ipaddr)
		_ = result
	})
}

func TestCheckLocked(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("InitialState_AllowLogin", func(t *testing.T) {
		result := lm.Check("testuser", "192.168.1.1:12345")
		assert.True(t, result, "初始状态应该允许登录")
	})

	t.Run("LockedState_DenyLogin", func(t *testing.T) {
		username := "testuser"
		ipaddr := "192.168.1.1:12345"

		for i := 0; i < 5; i++ {
			lm.Fail(username, ipaddr)
		}

		result := lm.Check(username, ipaddr)
		assert.False(t, result, "5次失败后应该被锁定")
	})
}

func TestUpdateLoginStatus(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("FailureCount_Increment", func(t *testing.T) {
		username := "testuser"
		ipaddr := "192.168.1.1:12345"

		for i := 1; i <= 3; i++ {
			lm.Fail(username, ipaddr)

			lm.mu.Lock()
			ip, _, _ := net.SplitHostPort(ipaddr)
			userIPMap := lm.ipUserLocks[ip]
			state := userIPMap[username]
			assert.Equal(t, i, state.FailureCount, fmt.Sprintf("第%d次失败后计数应该为%d", i, i))
			lm.mu.Unlock()
		}
	})

	t.Run("SuccessLogin_ResetCount", func(t *testing.T) {
		username := "successuser"
		ipaddr := "192.168.1.2:12345"

		for i := 0; i < 3; i++ {
			lm.Fail(username, ipaddr)
		}

		lm.Success(username, ipaddr)

		lm.mu.Lock()
		ip, _, _ := net.SplitHostPort(ipaddr)
		userIPMap := lm.ipUserLocks[ip]
		state := userIPMap[username]
		assert.Equal(t, 0, state.FailureCount, "成功登录应该重置失败计数")
		lm.mu.Unlock()
	})
}

func TestUpdateLockState(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("LockedState_NoCountUpdate", func(t *testing.T) {
		username := "lockeduser"
		ipaddr := "192.168.1.2:12345"

		for i := 0; i < 5; i++ {
			lm.Fail(username, ipaddr)
		}

		lm.mu.Lock()
		ip, _, _ := net.SplitHostPort(ipaddr)
		userIPMap := lm.ipUserLocks[ip]
		state := userIPMap[username]
		originalCount := state.FailureCount
		originalLocked := state.Locked
		lm.mu.Unlock()

		lm.Fail(username, ipaddr)

		lm.mu.Lock()
		newState := lm.ipUserLocks[ip][username]
		assert.Equal(t, originalCount, newState.FailureCount, "已锁定状态的失败计数不应该改变")
		assert.Equal(t, originalLocked, newState.Locked, "锁定状态不应该改变")
		lm.mu.Unlock()
	})
}

func TestCheckGlobalIPLock(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("GlobalIP_Protection", func(t *testing.T) {
		ipaddr := "192.168.1.3:12345"
		ip, _, _ := net.SplitHostPort(ipaddr)

		for i := 0; i < 40; i++ {
			username := fmt.Sprintf("user%d", i)
			lm.Fail(username, ipaddr)
		}

		result := lm.isIPLocked(ip, time.Now())
		assert.True(t, result, "IP应该被全局锁定")
	})
}

func TestCheckGlobalUserLock(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("GlobalUser_Protection", func(t *testing.T) {
		username := "globaluser"

		for i := 0; i < 20; i++ {
			ipaddr := fmt.Sprintf("192.168.1.%d:12345", 100+i)
			lm.Fail(username, ipaddr)
		}

		result := lm.isUserLocked(username, time.Now())
		assert.True(t, result, "用户应该被全局锁定")
	})
}

func TestCheckUserIPLock(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("UserIP_Protection", func(t *testing.T) {
		username := "useripuser"
		ipaddr := "192.168.1.4:12345"
		ip, _, _ := net.SplitHostPort(ipaddr)

		for i := 0; i < 5; i++ {
			lm.Fail(username, ipaddr)
		}

		result := lm.isUserIPLocked(username, ip, time.Now())
		assert.True(t, result, "单用户IP应该被锁定")
	})
}

func TestInitIPList_IsInIPList(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("Whitelist_Functionality", func(t *testing.T) {
		lm.LoadIPList(IPWhiteList, base.GetCfg().IPWhiteList)

		result := lm.InList("192.168.90.1", IPWhiteList)
		assert.True(t, result, "192.168.90.1应该在白名单中")

		result2 := lm.InList("172.16.0.100", IPWhiteList)
		assert.True(t, result2, "172.16.0.100应该在CIDR范围内")
	})

	t.Run("Blacklist_Functionality", func(t *testing.T) {
		lm.LoadIPList(IPBlackList, base.GetCfg().IPBlackList)

		result := lm.InList("10.0.0.1", IPBlackList)
		assert.True(t, result, "10.0.0.1应该在黑名单中")
	})
}

func TestGetLocksInfo(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("EmptyState", func(t *testing.T) {
		locksInfo := lm.LockInfo()
		assert.Empty(t, locksInfo, "初始状态应该没有锁定信息")
	})

	t.Run("WithLocks", func(t *testing.T) {
		username := "testuser"
		ipaddr := "192.168.1.5:12345"

		for i := 0; i < 5; i++ {
			lm.Fail(username, ipaddr)
		}

		locksInfo := lm.LockInfo()
		assert.NotEmpty(t, locksInfo, "应该有锁定信息")
	})
}

func TestCleanupExpiredLocks(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("ExpiredLocks_Cleanup", func(t *testing.T) {
		username := "cleanupuser"
		ipaddr := "192.168.1.6:12345"

		lm.Fail(username, ipaddr)

		// 模拟过期
		lm.mu.Lock()
		ip, _, _ := net.SplitHostPort(ipaddr)
		userIPMap := lm.ipUserLocks[ip]
		state := userIPMap[username]
		state.LastAttempt = time.Now().Add(-7200 * time.Second)
		lm.mu.Unlock()

		lm.cleanup()

		lm.mu.Lock()
		_, exists := lm.ipUserLocks[ip]
		lm.mu.Unlock()
		assert.False(t, exists, "过期的锁定状态应该被清理")
	})
}

func TestCheckLockState(t *testing.T) {
	resetLockManager()
	base.Test()
	setupTestConfig()

	lm := GetLockManager()

	t.Run("TimeWindow_Reset", func(t *testing.T) {
		state := &LockState{
			FailureCount: 3,
			LastAttempt:  time.Now().Add(-700 * time.Second),
		}

		result := lm.checkState(state, time.Now(), 600)

		assert.False(t, result, "超过重置时间应该返回false")
		assert.Equal(t, 0, state.FailureCount, "失败计数应该被重置")
	})
}
