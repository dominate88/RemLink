package sessdata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wsczx/remlink/base"
	"github.com/miekg/dns"
)

// 管理 FakeDNS 和 FakeIP 功能
type FakeDNSManager struct {
	// FakeIP 池配置
	pool       *fakeIPPool
	active     map[string]*fakeIPEntry // fakeIP -> entry
	domainToIP map[string]string       // domain -> fakeIP
	ipToRealIP map[string]string       // fakeIP -> realIP
	mu         sync.RWMutex

	// DNS 缓存
	dnsCache   map[string]*dnsCache
	dnsCacheMu sync.RWMutex

	// 异步解析的域名去重(domain -> struct{}), 避免重复解析/竞态
	resolving sync.Map

	// 防火墙后端
	fw Firewall

	// 生命周期管理
	stopChan chan struct{}
	stopOnce sync.Once
	stopMu   sync.RWMutex
	wg       sync.WaitGroup
	stopped  atomic.Bool
}

type fakeIPEntry struct {
	Domain     string
	FakeIP     string
	LastAccess atomic.Int64
	RefreshAt  atomic.Int64 // 到期重新解析的时间点
}

func (e *fakeIPEntry) GetLastAccess() time.Time  { return time.Unix(0, e.LastAccess.Load()) }
func (e *fakeIPEntry) SetLastAccess(t time.Time) { e.LastAccess.Store(t.UnixNano()) }
func (e *fakeIPEntry) GetRefreshAt() time.Time {
	if v := e.RefreshAt.Load(); v != 0 {
		return time.Unix(0, v)
	}
	return time.Time{}
}
func (e *fakeIPEntry) SetRefreshAt(t time.Time)  { e.RefreshAt.Store(t.UnixNano()) }

type fakeIPPool struct {
	IPNet     *net.IPNet
	IpLongMin uint32
	IpLongMax uint32
	counter   atomic.Uint32
}

type dnsCache struct {
	RealIP   string
	TTL      uint32
	ExpireAt time.Time
}

// 全局单例
var GlobalFakeDNSManager *FakeDNSManager
var globalFakeDNSOnce sync.Once

const (
	DefaultFakeIPRange = "100.64.0.0/10"
)

// 最小重新解析间隔
const minRefreshInterval = 60 * time.Second

// 获取全局 FakeDNS 管理器单例
func GetFakeDNSManager() *FakeDNSManager {
	globalFakeDNSOnce.Do(func() {
		var err error
		GlobalFakeDNSManager, err = newFakeDNSManager(DefaultFakeIPRange)
		if err != nil {
			base.Error("Failed to initialize FakeDNS manager:", err)
			return
		}
		GlobalFakeDNSManager.Start()
		base.Info("Global FakeDNS manager initialized")
	})
	return GlobalFakeDNSManager
}

// 创建 FakeDNS 管理器
func newFakeDNSManager(ipRange string) (*FakeDNSManager, error) {
	m := &FakeDNSManager{
		active:     make(map[string]*fakeIPEntry),
		domainToIP: make(map[string]string),
		ipToRealIP: make(map[string]string),
		dnsCache:   make(map[string]*dnsCache),
		stopChan:   make(chan struct{}),
	}

	// 解析 IP 范围
	_, ipNet, err := net.ParseCIDR(ipRange)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range: %v", err)
	}

	ipLongMin := binary.BigEndian.Uint32(ipNet.IP)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	ipLongMax := (ipLongMin & mask) | (^mask)

	m.pool = &fakeIPPool{
		IPNet:     ipNet,
		IpLongMin: ipLongMin + 1,
		IpLongMax: ipLongMax - 1,
	}

	// 初始化防火墙后端
	m.fw = GetFirewall()
	if m.fw == nil {
		return nil, fmt.Errorf("failed to initialize firewall: firewall is nil")
	}

	// 创建防火墙链
	if err := m.fw.CreateChains(base.GetCfg().Ipv4CIDR, ipNet.String()); err != nil {
		return nil, err
	}

	base.Info("FakeDNS manager initialized:", ipRange)
	return m, nil
}

// 启动后台清理任务
func (m *FakeDNSManager) Start() {
	m.wg.Add(2)
	go m.cleanupFakeIPLoop()
	go m.cleanupDNSCacheLoop()
}

// 停止管理器
func (m *FakeDNSManager) Stop() {
	m.stopOnce.Do(func() {
		m.stopMu.Lock()
		m.stopped.Store(true)
		close(m.stopChan)
		m.stopMu.Unlock()
	})
	m.wg.Wait()
	if m.fw != nil {
		m.fw.CleanupFakeIP()
	}
}

// 为域名分配 FakeIP
func (m *FakeDNSManager) AcquireFakeIP(domain string) net.IP {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查是否已分配
	if fakeIP, exists := m.domainToIP[domain]; exists {
		if entry, ok := m.active[fakeIP]; ok {
			entry.SetLastAccess(time.Now())
			return net.ParseIP(fakeIP)
		}
	}

	// 分配新的 FakeIP
	counter := m.pool.counter.Add(1)
	ipLong := m.pool.IpLongMin + (counter % (m.pool.IpLongMax - m.pool.IpLongMin + 1))

	fakeIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(fakeIP, ipLong)

	fakeIPStr := fakeIP.String()
	entry := &fakeIPEntry{
		Domain: domain,
		FakeIP: fakeIPStr,
	}
	entry.SetLastAccess(time.Now())

	m.active[fakeIPStr] = entry
	m.domainToIP[domain] = fakeIPStr

	base.Debug("Allocated FakeIP:", domain, "->", fakeIPStr)
	return fakeIP
}

//  1. 查 fakeIP 对应的 realIP 和 domain
//  2. 刷新访问时间 LastAccess
//  3. 判断映射是否到期需要重新解析; 若需要, 立即把 RefreshAt 顺延一个
//     最小周期, 避免刷新完成前同一窗口内每个包都触发 RenewMapping
//
// 返回 realIP(空表示尚无映射)、domain(空表示 fakeIP 不在映射表)、needRefresh。
func (m *FakeDNSManager) LookupAndTouch(fakeIP string) (realIP, domain string, needRefresh bool) {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, ok := m.active[fakeIP]
	if !ok {
		return "", "", false
	}
	entry.SetLastAccess(now)
	domain = entry.Domain

	realIP = m.ipToRealIP[fakeIP]
	if realIP == "" {
		// 映射尚未就绪, 交给首解析路径处理
		return "", domain, false
	}

	refreshAt := entry.GetRefreshAt()
	if !refreshAt.IsZero() && now.After(refreshAt) {
		// 顺延一个最小周期, 防止刷新完成前每个包重复触发
		entry.SetRefreshAt(now.Add(minRefreshInterval))
		needRefresh = true
	}
	return realIP, domain, needRefresh
}

// 异步解析域名并将 fakeIP->realIP 映射写入并配置 NAT 规则
func (m *FakeDNSManager) ResolveAndMapping(fakeIP, domain, upstreamDNS string) {
	// 已有映射直接返回
	if m.GetRealIP(fakeIP) != "" {
		return
	}
	// 去重: 同一域名只允许一个在解析
	if _, loaded := m.resolving.LoadOrStore(domain, struct{}{}); loaded {
		return
	}

	m.stopMu.RLock()
	if m.stopped.Load() {
		m.stopMu.RUnlock()
		m.resolving.Delete(domain)
		return
	}
	m.wg.Add(1)
	m.stopMu.RUnlock()

	go func() {
		defer m.wg.Done()
		defer m.resolving.Delete(domain)

		realIP, ttl, err := m.resolveWithCache(domain, upstreamDNS)
		if err != nil {
			base.Debug("Failed to resolve domain:", domain, "error:", err)
			return
		}
		if err := m.AddMapping(fakeIP, realIP, domain); err != nil {
			base.Debug("Failed to add FakeIP mapping:", err)
			return
		}
		m.setRefreshAt(fakeIP, ttl)
		base.Debug("Resolved & mapped:", domain, "->", realIP)
	}()
}

// 映射到期时异步重新解析并替换 DNAT。
func (m *FakeDNSManager) RenewMapping(fakeIP, domain, upstreamDNS string) {
	if _, loaded := m.resolving.LoadOrStore(domain, struct{}{}); loaded {
		return
	}
	m.stopMu.RLock()
	if m.stopped.Load() {
		m.stopMu.RUnlock()
		m.resolving.Delete(domain)
		return
	}
	m.wg.Add(1)
	m.stopMu.RUnlock()

	go func() {
		defer m.wg.Done()
		defer m.resolving.Delete(domain)

		// 绕过缓存重新解析，配合 queryDNS 随机选更快节点
		realIP, ttl, err := m.ResolveDomain(domain, upstreamDNS)
		if err != nil {
			base.Debug("Refresh resolve failed:", domain, "error:", err)
			m.setRefreshAt(fakeIP, 0) // 0 经 max() 兜底为 minRefreshInterval, 稍后重试
			return
		}
		m.updateDNSCache(domain+"|"+upstreamDNS, realIP, ttl)
		if err := m.AddMapping(fakeIP, realIP, domain); err != nil {
			base.Debug("Refresh AddMapping failed:", err)
			return
		}
		m.setRefreshAt(fakeIP, ttl)
		base.Debug("Refreshed mapping:", domain, "->", realIP)
	}()
}

// 根据 FakeIP 获取真实 IP
func (m *FakeDNSManager) GetRealIP(fakeIP string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if realIP, exists := m.ipToRealIP[fakeIP]; exists {
		return realIP
	}
	return ""
}

// 根据 FakeIP 获取域名
func (m *FakeDNSManager) GetDomain(fakeIP string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, exists := m.active[fakeIP]; exists {
		return entry.Domain
	}
	return ""
}

// 判断 IP 是否在 FakeIP 池中
func (m *FakeDNSManager) IsFakeIP(ip net.IP) bool {
	if m.pool == nil {
		return false
	}
	return m.pool.IPNet.Contains(ip)
}

// 更新 FakeIP 访问时间
func (m *FakeDNSManager) UpdateAccess(fakeIP string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if entry, exists := m.active[fakeIP]; exists {
		entry.SetLastAccess(time.Now())
	}
}

// 添加 FakeIP -> RealIP 映射并创建防火墙规则
func (m *FakeDNSManager) AddMapping(fakeIP, realIP, domain string) error {
	m.mu.Lock()

	// fakeIP 已被清理,放弃添加
	if _, exists := m.active[fakeIP]; !exists {
		m.mu.Unlock()
		base.Debug("FakeIP already cleaned up, skip mapping:", fakeIP, domain)
		return fmt.Errorf("fakeIP %s already cleaned up", fakeIP)
	}

	// 检查是否已存在相同映射
	existing, exists := m.ipToRealIP[fakeIP]
	if exists && existing == realIP {
		m.mu.Unlock()
		return nil
	}

	// 记录旧映射
	var oldRealIP string
	if exists {
		oldRealIP = existing
	}

	// 添加新映射
	m.ipToRealIP[fakeIP] = realIP
	m.mu.Unlock()

	// 如果有旧映射,先删除旧的防火墙规则
	if oldRealIP != "" {
		if err := m.fw.DelNatRule(fakeIP, oldRealIP); err != nil {
			// 回滚到旧映射
			m.mu.Lock()
			m.ipToRealIP[fakeIP] = oldRealIP
			m.mu.Unlock()
			return err
		}
	}

	// 添加新的防火墙规则
	if err := m.fw.AddNatRule(fakeIP, realIP); err != nil {
		// 回滚: 有旧映射则恢复旧值，无旧映射则删除
		m.mu.Lock()
		if oldRealIP != "" {
			m.ipToRealIP[fakeIP] = oldRealIP
		} else {
			delete(m.ipToRealIP, fakeIP)
		}
		m.mu.Unlock()
		return err
	}
	base.Debug("Added FakeIP mapping:", fakeIP, "->", realIP, "for domain:", domain)
	return nil
}

// 删除 FakeIP -> RealIP 映射和防火墙规则
func (m *FakeDNSManager) RemoveMapping(fakeIP string) error {
	m.mu.Lock()
	realIP, exists := m.ipToRealIP[fakeIP]
	if !exists {
		m.mu.Unlock()
		return nil
	}
	delete(m.ipToRealIP, fakeIP)
	m.mu.Unlock()

	// 删除防火墙规则
	if err := m.fw.DelNatRule(fakeIP, realIP); err != nil {
		return err
	}

	base.Debug("Removed FakeIP mapping:", fakeIP, "->", realIP)
	return nil
}

// 带缓存的解析，同时返回 ttl
func (m *FakeDNSManager) resolveWithCache(domain, upstreamDNS string) (string, uint32, error) {
	cacheKey := domain + "|" + upstreamDNS
	m.dnsCacheMu.RLock()
	if entry, exists := m.dnsCache[cacheKey]; exists && time.Now().Before(entry.ExpireAt) {
		ip, ttl := entry.RealIP, entry.TTL
		m.dnsCacheMu.RUnlock()
		base.Debug("DNS cache hit:", domain, "->", ip)
		return ip, ttl, nil
	}
	m.dnsCacheMu.RUnlock()

	realIP, ttl, err := m.ResolveDomain(domain, upstreamDNS)
	if err != nil {
		return "", 0, err
	}
	m.updateDNSCache(cacheKey, realIP, ttl)
	return realIP, ttl, nil
}

func (m *FakeDNSManager) updateDNSCache(cacheKey, realIP string, ttl uint32) {
	cacheTTL := max(time.Duration(ttl)*time.Second, minRefreshInterval)
	m.dnsCacheMu.Lock()
	m.dnsCache[cacheKey] = &dnsCache{
		RealIP:   realIP,
		TTL:      ttl,
		ExpireAt: time.Now().Add(cacheTTL),
	}
	m.dnsCacheMu.Unlock()
}

// 根据 ttl 设置下次刷新时间
func (m *FakeDNSManager) setRefreshAt(fakeIP string, ttl uint32) {
	d := max(time.Duration(ttl)*time.Second, minRefreshInterval)
	m.mu.RLock()
	entry, ok := m.active[fakeIP]
	m.mu.RUnlock()
	if ok {
		entry.SetRefreshAt(time.Now().Add(d))
	}
}

var errDNSAuthoritative = errors.New("authoritative negative response")

// 带重试的 DNS 解析
func (m *FakeDNSManager) ResolveDomain(domain, upstreamDNS string) (string, uint32, error) {
	if upstreamDNS != "" && !strings.Contains(upstreamDNS, ":") {
		upstreamDNS = upstreamDNS + ":53"
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	const maxRetries = 2
	var lastErr error
	for i := range maxRetries {
		realIP, ttl, err := m.queryDNS(msg, upstreamDNS)
		if err == nil {
			return realIP, ttl, nil
		}
		// 无记录直接返回
		if errors.Is(err, errDNSAuthoritative) {
			return "", 0, err
		}
		lastErr = err
		if i < maxRetries-1 {
			base.Debug("DNS query failed, retrying:", upstreamDNS, "error:", err)
		}
	}
	return "", 0, fmt.Errorf("DNS query failed for %s after %d attempts: %v", domain, maxRetries, lastErr)
}

// 单次 DNS 查询
func (m *FakeDNSManager) queryDNS(msg *dns.Msg, server string) (string, uint32, error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	r, _, err := c.Exchange(msg, server)
	if err != nil {
		return "", 0, err // 网络错误/超时,可重试
	}
	// NXDOMAIN 或其他非成功，不重试
	if r.Rcode != dns.RcodeSuccess {
		return "", 0, fmt.Errorf("%w: rcode=%d", errDNSAuthoritative, r.Rcode)
	}
	// 收集所有 A 记录，随机选一条，避免 CDN 多 IP 时钉死第一个节点
	var ips []string
	var ttl uint32
	for _, ans := range r.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
			if ttl == 0 {
				ttl = a.Hdr.Ttl
			}
		}
	}
	if len(ips) == 0 {
		return "", 0, fmt.Errorf("%w: no IPv4 address in response", errDNSAuthoritative)
	}
	return ips[rand.Intn(len(ips))], ttl, nil
}

// 定期清理过期的 FakeIP
func (m *FakeDNSManager) cleanupFakeIPLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredFakeIPs()
		case <-m.stopChan:
			return
		}
	}
}

// 清理过期的 FakeIP 映射
func (m *FakeDNSManager) cleanupExpiredFakeIPs() {
	var toCleanup []string

	// 收集需要清理的 FakeIP
	m.mu.RLock()
	now := time.Now()
	for fakeIP, entry := range m.active {
		if now.Sub(entry.GetLastAccess()) > 2*time.Hour {
			toCleanup = append(toCleanup, fakeIP)
		}
	}
	m.mu.RUnlock()

	// 逐个清理
	for _, fakeIP := range toCleanup {
		m.mu.Lock()
		entry, exists := m.active[fakeIP]
		if !exists {
			m.mu.Unlock()
			continue
		}
		// 再次检查
		if time.Since(entry.GetLastAccess()) <= 2*time.Hour {
			m.mu.Unlock()
			continue
		}
		domain := entry.Domain
		delete(m.active, fakeIP)
		delete(m.domainToIP, domain)
		m.mu.Unlock()

		// 删除映射和防火墙规则
		if err := m.RemoveMapping(fakeIP); err != nil {
			base.Warn("Failed to remove FakeIP mapping:", err)
		}

		base.Debug("Cleaned up FakeIP:", fakeIP, "for domain:", domain)
	}
}

// 定期清理过期的 DNS 缓存
func (m *FakeDNSManager) cleanupDNSCacheLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.cleanupExpiredDNSCache()
		case <-m.stopChan:
			return
		}
	}
}

// 清理过期的 DNS 缓存
func (m *FakeDNSManager) cleanupExpiredDNSCache() {
	var expired []string

	// 收集过期的 DNS 缓存
	m.dnsCacheMu.RLock()
	now := time.Now()
	for key, entry := range m.dnsCache {
		if now.After(entry.ExpireAt) {
			expired = append(expired, key)
		}
	}
	m.dnsCacheMu.RUnlock()

	if len(expired) == 0 {
		return
	}

	// 批量删除
	m.dnsCacheMu.Lock()
	for _, key := range expired {
		// 再次检查
		if entry, exists := m.dnsCache[key]; exists {
			if time.Now().After(entry.ExpireAt) {
				delete(m.dnsCache, key)
				base.Debug("Cleaned expired DNS cache:", key)
			}
		}
	}
	m.dnsCacheMu.Unlock()
}

