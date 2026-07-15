package utils

import (
	"sync"

	cmap "github.com/orcaman/concurrent-map"
)

type IMaps interface {
	Set(key string, val interface{})
	Get(key string) (interface{}, bool)
	Del(key string)
	// Items 返回所有条目，用于清理等批量操作
	Items() map[string]interface{}
}

/**
 * 基础的Map结构
 *
 */
type BaseMap struct {
	m    map[string]interface{}
	mu   sync.Mutex
}

func (m *BaseMap) Set(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[key] = value
}
func (m *BaseMap) Get(key string) (interface{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.m[key]
	return v, ok
}
func (m *BaseMap) Del(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, key)
}
func (m *BaseMap) Items() map[string]interface{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]interface{}, len(m.m))
	for k, v := range m.m {
		result[k] = v
	}
	return result
}

/**
 * CMap 并发结构
 *
 */
type ConcurrentMap struct {
	m cmap.ConcurrentMap
}

func (m *ConcurrentMap) Set(key string, value interface{}) {
	m.m.Set(key, value)
}

func (m *ConcurrentMap) Get(key string) (interface{}, bool) {
	return m.m.Get(key)
}

func (m *ConcurrentMap) Del(key string) {
	m.m.Remove(key)
}

func (m *ConcurrentMap) Items() map[string]interface{} {
	return m.m.Items()
}

/**
 * Map 读写结构
 *
 */
type RWLockMap struct {
	m    map[string]interface{}
	lock sync.RWMutex
}

func (m *RWLockMap) Set(key string, value interface{}) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.m[key] = value
}

func (m *RWLockMap) Get(key string) (interface{}, bool) {
	m.lock.RLock()
	defer m.lock.RUnlock()
	v, ok := m.m[key]
	return v, ok
}

func (m *RWLockMap) Del(key string) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.m, key)
}

func (m *RWLockMap) Items() map[string]interface{} {
	m.lock.RLock()
	defer m.lock.RUnlock()
	result := make(map[string]interface{}, len(m.m))
	for k, v := range m.m {
		result[k] = v
	}
	return result
}

/**
 * sync.Map 结构
 *
 */
type SyncMap struct {
	m sync.Map
}

func (m *SyncMap) Set(key string, val interface{}) {
	m.m.Store(key, val)
}

func (m *SyncMap) Get(key string) (interface{}, bool) {
	return m.m.Load(key)
}

func (m *SyncMap) Del(key string) {
	m.m.Delete(key)
}

func (m *SyncMap) Items() map[string]interface{} {
	result := make(map[string]interface{})
	m.m.Range(func(k, v interface{}) bool {
		result[k.(string)] = v
		return true
	})
	return result
}

func NewMap(name string, len int) IMaps {
	switch name {
	case "cmap":
		return &ConcurrentMap{m: cmap.New()}
	case "rwmap":
		m := make(map[string]interface{}, len)
		return &RWLockMap{m: m}
	case "syncmap":
		return &SyncMap{}
	default:
		m := make(map[string]interface{}, len)
		return &BaseMap{m: m}
	}
}
