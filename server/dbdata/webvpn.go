package dbdata

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"xorm.io/xorm"
)

var (
	errWebVpnEmptyName    = errors.New("应用名称不能为空")
	errWebVpnEmptyBackend = errors.New("后端地址不能为空")
	errWebVpnInvalidId    = errors.New("无效的 ID")
)

// 应用配置的进程内缓存，避免每个请求都查库。
// Set/Del 后通过 InvalidateWebVpnAppCache 主动失效；TTL 兜底防止遗漏。
var webVpnAppCache = struct {
	mu     sync.RWMutex
	m      map[string]*WebVpnApp
	expire time.Time
}{m: make(map[string]*WebVpnApp)}

const webVpnAppCacheTTL = 60 * time.Second

// 主动失效缓存（配置变更后调用）
func InvalidateWebVpnAppCache() {
	webVpnAppCache.mu.Lock()
	webVpnAppCache.m = make(map[string]*WebVpnApp)
	webVpnAppCache.mu.Unlock()
}

// WebVpnApp 表示一个 WebVPN 反向代理应用配置。
// 通过子域名 *.WebVpnDomain 访问：子域名 = Name，反代到 Backend。
type WebVpnApp struct {
	Id          int       `json:"id" xorm:"pk autoincr not null"`
	Name        string    `json:"name" xorm:"varchar(60) not null unique"` // 子域名前缀，也是应用唯一标识
	Note        string    `json:"note" xorm:"varchar(255)"`
	Backend     string    `json:"backend" xorm:"varchar(255)"`      // 后端地址，如 https://10.0.0.5:8080
	Users       []string  `json:"users" xorm:"Text"`                // 授权用户名白名单；空=全部用户（受 Groups 约束）
	Groups      []string  `json:"groups" xorm:"Text"`               // 授权用户组白名单；空=不限组
	AllowPath   []string  `json:"allow_path" xorm:"Text"`           // 路径前缀白名单；空=全部路径
	IpAllowList []string  `json:"ip_allow_list" xorm:"Text"`        // 客户端来源 IP 白名单（CIDR 或单 IP）；空=不限制
	HostRewrite string    `json:"host_rewrite" xorm:"varchar(255)"` // 反代时改写到后端的 Host（覆盖默认的后端地址）；空=用后端地址
	SkipVerify  bool      `json:"skip_verify" xorm:"Bool"`          // 后端为自签/内网证书时跳过 TLS 校验
	Status      int8      `json:"status" xorm:"Int"`                // 1=启用
	CreatedAt   time.Time `json:"created_at" xorm:"DateTime created"`
	UpdatedAt   time.Time `json:"updated_at" xorm:"DateTime updated"`
}

// 分页查询所有 WebVPN 应用；name 非空时按子域名/名称前缀模糊过滤
func WebVpnAppList(pageSize, page int, name string) ([]WebVpnApp, int, error) {
	var datas []WebVpnApp
	name = strings.TrimSpace(name)
	if name == "" {
		count := CountAll(&WebVpnApp{})
		err := Find(&datas, pageSize, page)
		return datas, count, err
	}
	like := "%" + escapeLike(name) + "%"
	count := FindWhereCount(&WebVpnApp{}, "name LIKE ? OR note LIKE ?", like, like)
	err := FindWhere(&datas, pageSize, page, "name LIKE ? OR note LIKE ?", like, like)
	return datas, count, err
}

// 新增或更新 WebVPN 应用
func SetWebVpnApp(a *WebVpnApp) error {
	if a.Name == "" {
		return errWebVpnEmptyName
	}
	if a.Backend == "" {
		return errWebVpnEmptyBackend
	}
	a.UpdatedAt = time.Now()
	var err error
	if a.Id > 0 {
		// 更新
		err = Set(a)
	} else {
		// 新增：默认启用
		if a.Status == 0 {
			a.Status = 1
		}
		err = Add(a)
	}
	if err == nil {
		InvalidateWebVpnAppCache()
	}
	return err
}

// 删除 WebVPN 应用
func DelWebVpnApp(id int) error {
	if id < 1 {
		return errWebVpnInvalidId
	}
	err := Del(&WebVpnApp{Id: id})
	if err == nil {
		InvalidateWebVpnAppCache()
	}
	return err
}

// 按子域名前缀（Name）查找应用，带进程内缓存
func GetWebVpnAppByName(name string) (*WebVpnApp, error) {
	webVpnAppCache.mu.RLock()
	hit := webVpnAppCache.m[name]
	fresh := time.Now().Before(webVpnAppCache.expire)
	webVpnAppCache.mu.RUnlock()
	if hit != nil && fresh {
		return hit, nil
	}

	a := &WebVpnApp{}
	if err := One("Name", name, a); err != nil {
		if CheckErrNotFound(err) {
			// 未命中也缓存空标记，避免穿透；用独立负缓存 key
			webVpnAppCache.mu.Lock()
			webVpnAppCache.m[name] = nil
			webVpnAppCache.expire = time.Now().Add(webVpnAppCacheTTL)
			webVpnAppCache.mu.Unlock()
		}
		return nil, err
	}

	webVpnAppCache.mu.Lock()
	webVpnAppCache.m[name] = a
	webVpnAppCache.expire = time.Now().Add(webVpnAppCacheTTL)
	webVpnAppCache.mu.Unlock()
	return a, nil
}

// 返回某用户有权访问的 WebVPN 应用（按用户名/用户组白名单过滤）。
// 仅做用户维度的授权判断（不含来源 IP、路径等请求级限制），用于门户"我的应用"展示。
func WebVpnAppsForUser(user *User) ([]WebVpnApp, error) {
	var all []WebVpnApp
	if err := Find(&all, -1, 0); err != nil {
		return nil, err
	}
	result := make([]WebVpnApp, 0, len(all))
	for _, a := range all {
		if a.Status != 1 {
			continue
		}
		if !webVpnUserAllowed(&a, user) {
			continue
		}
		result = append(result, a)
	}
	return result, nil
}

// 空白名单=全部放行；用户维度判断与 handler 层 webVpnAuthorized 保持一致。
func webVpnUserAllowed(a *WebVpnApp, user *User) bool {
	if len(a.Users) > 0 {
		if !contains(a.Users, user.Username) {
			return false
		}
	}
	if len(a.Groups) > 0 {
		hit := false
		for _, g := range user.Groups {
			if contains(a.Groups, g) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func contains(slice []string, target string) bool {
	return slices.Contains(slice, target)
}

// WebVPN 访问审计记录（每次代理请求落一条，异步批量写入）。
type WebVpnAudit struct {
	Id         int64     `json:"id" xorm:"pk autoincr not null"`
	Username   string    `json:"username" xorm:"varchar(60) not null"`
	GroupName  string    `json:"group_name" xorm:"varchar(60) not null default ''"`
	AppName    string    `json:"app_name" xorm:"varchar(60) not null"` // 子域名前缀（应用标识）
	Host       string    `json:"host" xorm:"varchar(255) not null"`    // 原始 Host 请求头
	Method     string    `json:"method" xorm:"varchar(16) not null"`   // GET/POST...
	Path       string    `json:"path" xorm:"varchar(1024) not null"`   // 请求路径（含 query）
	StatusCode int       `json:"status_code" xorm:"Int not null default 0"`
	BytesSent  int64     `json:"bytes_sent" xorm:"BigInt not null default 0"`
	BytesRecv  int64     `json:"bytes_recv" xorm:"BigInt not null default 0"`
	ClientIP   string    `json:"client_ip" xorm:"varchar(60) not null"`
	DurationMs int64     `json:"duration_ms" xorm:"BigInt not null default 0"`
	RiskLevel  int8      `json:"risk_level" xorm:"Int not null default 0"` // 0=正常 1=可疑 2=高危
	CreatedAt  time.Time `json:"created_at" xorm:"DateTime created"`
}

// 显式指定审计表名
func (WebVpnAudit) TableName() string { return "webvpn_audit" }

// 分页查询（支持按用户名/应用名/时间范围过滤）
func WebVpnAuditList(pageSize, page int, search WebVpnAuditSearch) ([]WebVpnAudit, int, error) {
	var datas []WebVpnAudit
	buildCond := func(s *xorm.Session) {
		if search.Username != "" {
			s.And("username = ?", search.Username)
		}
		if search.AppName != "" {
			s.And("app_name = ?", search.AppName)
		}
		if search.Method != "" {
			s.And("method = ?", search.Method)
		}
		if len(search.Date) == 2 && search.Date[0] != "" {
			s.And("created_at BETWEEN ? AND ?", search.Date[0], search.Date[1])
		}
	}
	countSession := xdb.Where("1=1")
	buildCond(countSession)
	count, err := countSession.Count(&WebVpnAudit{})
	if err != nil {
		return nil, 0, err
	}
	listSession := xdb.Where("1=1")
	buildCond(listSession)
	if err := listSession.OrderBy("id desc").Limit(pageSize, (page-1)*pageSize).Find(&datas); err != nil {
		return nil, 0, err
	}
	return datas, int(count), nil
}

// 审计查询条件
type WebVpnAuditSearch struct {
	Username string   `json:"username"`
	AppName  string   `json:"app_name"`
	Method   string   `json:"method"`
	Date     []string `json:"date"`
}

// 清理早于指定时间的审计记录
func ClearWebVpnAudit(ts string) (int64, error) {
	return xdb.Where("created_at < ?", ts).Delete(&WebVpnAudit{})
}

// 导出查询：按条件返回全部审计记录
func WebVpnAuditExportList(search WebVpnAuditSearch) ([]WebVpnAudit, error) {
	var datas []WebVpnAudit
	session := xdb.Where("1=1")
	if search.Username != "" {
		session.And("username = ?", search.Username)
	}
	if search.AppName != "" {
		session.And("app_name = ?", search.AppName)
	}
	if search.Method != "" {
		session.And("method = ?", search.Method)
	}
	if len(search.Date) == 2 && search.Date[0] != "" {
		session.And("created_at BETWEEN ? AND ?", search.Date[0], search.Date[1])
	}
	if err := session.OrderBy("id desc").Find(&datas); err != nil {
		return nil, err
	}
	return datas, nil
}

// 返回导出查询命中总数（用于上限校验）
func WebVpnAuditExportCount(search WebVpnAuditSearch) (int64, error) {
	session := xdb.Where("1=1")
	if search.Username != "" {
		session.And("username = ?", search.Username)
	}
	if search.AppName != "" {
		session.And("app_name = ?", search.AppName)
	}
	if search.Method != "" {
		session.And("method = ?", search.Method)
	}
	if len(search.Date) == 2 && search.Date[0] != "" {
		session.And("created_at BETWEEN ? AND ?", search.Date[0], search.Date[1])
	}
	return session.Count(&WebVpnAudit{})
}

// 批量写入审计记录
func AddBatchWebVpnAudit(datas []WebVpnAudit) error {
	if len(datas) == 0 {
		return nil
	}
	_, err := xdb.Insert(&datas)
	return err
}

// WebVPN 会话整用户踢出阈值：username -> 吊销时间戳（unix 秒）。
// 该时间戳之前签发的 WebVPN 会话一律视为已吊销，实现 O(1) 整用户下线。
var (
	webVpnRevokeBeforeMu sync.Mutex
	webVpnRevokeBefore   = map[string]int64{}
)

// 吊销指定用户的全部 WebVPN 会话（整用户下线）。
// 通过抬高吊销阈值实现：此后该用户签名时间早于阈值的会话都将被拒绝。
func WebVpnRevokeUser(username string) {
	if username == "" {
		return
	}
	webVpnRevokeBeforeMu.Lock()
	webVpnRevokeBefore[username] = time.Now().Unix()
	webVpnRevokeBeforeMu.Unlock()
}

// 返回指定用户的吊销阈值（0 表示未吊销）。
func WebVpnRevokeBeforeOf(username string) int64 {
	webVpnRevokeBeforeMu.Lock()
	defer webVpnRevokeBeforeMu.Unlock()
	return webVpnRevokeBefore[username]
}

// 清空全部吊销阈值（取消整用户下线状态）。
// 主要用于测试隔离与运维排障，生产环境应谨慎使用。
func WebVpnRevokeReset() {
	webVpnRevokeBeforeMu.Lock()
	webVpnRevokeBefore = map[string]int64{}
	webVpnRevokeBeforeMu.Unlock()
}
