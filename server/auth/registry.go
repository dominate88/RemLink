package auth

import (
	"fmt"
	"sync"
)

// registry 认证器工厂注册表
var (
	registry   = make(map[string]func() Authenticator)
	registryMu sync.RWMutex
)

// 注册认证器工厂，各认证器在 init() 中调用。
func Register(name string, factory func() Authenticator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("auth: 重复注册 %q", name))
	}
	registry[name] = factory
}

// 获取指定名称的认证器工厂。
func GetFactory(name string) (func() Authenticator, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[name]
	return f, ok
}

// 检查认证器名称是否已注册。
func IsRegistered(name string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[name]
	return ok
}

// 返回所有已注册的认证器名称列表
func RegisteredNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}

// 检查认证器类型是否为 SSO（即实现 Challenger 且 Challenge 类型为 ChallengeSSO）。
func IsSSOType(name string) bool {
	factory, ok := GetFactory(name)
	if !ok {
		return false
	}
	c, ok := factory().(Challenger)
	if !ok {
		return false
	}
	info := c.Challenge()
	return info != nil && info.Type == ChallengeSSO
}
