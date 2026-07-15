package base

const (
	LinkModeTUN     = "tun"
	LinkModeTAP     = "tap"
	LinkModeMacvtap = "macvtap"
	LinkModeIpvtap  = "ipvtap"
)

const InitialSetupWarning = "检测到默认初始化配置，请修改系统名称，完成后此提示将自动消失"

type SystemWarning struct {
	Code       string `json:"code"`
	Level      string `json:"level"`
	Message    string `json:"message"`
	ActionPath string `json:"action_path,omitempty"`
}

type ServerConfig struct {
	// 基础信息
	ProfileName string `json:"profile_name" default:"profile"`
	Issuer      string `json:"issuer" default:"XX公司VPN"`
	AdminUser   string `json:"admin_user" default:"admin" restart:"true"`
	AdminPass   string `json:"admin_pass" default:"defaultPwd"`
	AdminOtp    string `json:"admin_otp"`
	JwtSecret   string `json:"jwt_secret"`
	AdminTemp   bool   `json:"admin_temp"`

	// 服务监听
	ServerAddr        string `json:"server_addr" default:":443" restart:"true"`
	ServerDTLS        bool   `json:"server_dtls" restart:"true"`
	ServerDTLSAddr    string `json:"server_dtls_addr" default:":443" restart:"true"`
	AdvertiseDTLSAddr string `json:"advertise_dtls_addr"`
	AdminAddr         string `json:"admin_addr" default:":8800" restart:"true"`
	ProxyProtocol     bool   `json:"proxy_protocol" restart:"true"`
	FilesPath         string `json:"files_path" default:"./conf/files"`

	// 数据库
	DbType   string `json:"db_type" default:"sqlite3" restart:"true"`
	DbSource string `json:"db_source" default:"./conf/remlink.db" restart:"true"`
	ShowSQL  bool   `json:"show_sql"`

	// 虚拟网络
	LinkMode       string `json:"link_mode" default:"tun" restart:"true"`
	Ipv4Master     string `json:"ipv4_master" default:"eth0" restart:"true"`
	Ipv4CIDR       string `json:"ipv4_cidr" default:"192.168.90.0/24" restart:"true"`
	Ipv4Gateway    string `json:"ipv4_gateway" default:"192.168.90.1" restart:"true"`
	Ipv4Start      string `json:"ipv4_start" default:"192.168.90.100" restart:"true"`
	Ipv4End        string `json:"ipv4_end" default:"192.168.90.200" restart:"true"`
	IpLease        int    `json:"ip_lease" default:"86400"`
	GlobalNat      bool   `json:"global_nat" default:"true" restart:"true"`
	FirewallDriver string `json:"firewall_driver" default:"auto" restart:"true"`

	// 连接控制
	MaxClient       int    `json:"max_client" default:"200"`
	MaxUserClient   int    `json:"max_user_client" default:"3"`
	DefaultGroup    string `json:"default_group" default:"one"`
	CstpKeepalive   int    `json:"cstp_keepalive" default:"3"`
	CstpDpd         int    `json:"cstp_dpd" default:"20"`
	MobileKeepalive int    `json:"mobile_keepalive" default:"4"`
	MobileDpd       int    `json:"mobile_dpd" default:"60"`
	Mtu             int    `json:"mtu" default:"1460"`
	DefaultDomain   string `json:"default_domain" default:"example.com"`
	IdleTimeout     int    `json:"idle_timeout"`
	SessionTimeout  int    `json:"session_timeout" default:"3600"`
	Compression     bool   `json:"compression"`
	NoCompressLimit int    `json:"no_compress_limit" default:"256"`

	// 日志/调试
	LogPath       string `json:"log_path"`
	LogLevel      string `json:"log_level" default:"info"`
	HttpServerLog bool   `json:"http_server_log"`
	Pprof         bool   `json:"pprof" default:"false"`
	AuditInterval int    `json:"audit_interval" default:"600"`

	// 安全/认证
	DisplayError       bool   `json:"display_error"`
	ExcludeExportIp    bool   `json:"exclude_export_ip" default:"true"`
	SendOtp            bool   `json:"send_otp"`
	SendOtpType        string `json:"send_otp_type"`
	EncryptionPassword bool   `json:"encryption_password" default:"true"`

	// 防暴破
	AntiBruteForce bool   `json:"anti_brute_force" default:"true"`
	IPWhiteList    string `json:"ip_whitelist" default:"192.168.90.1,172.16.0.0/24"`
	IPBlackList    string `json:"ip_blacklist"`

	// 锁定策略
	MaxBanCount                   int `json:"max_ban_score" default:"5"`
	BanResetTime                  int `json:"ban_reset_time" default:"600"`
	LockTime                      int `json:"lock_time" default:"300"`
	MaxGlobalUserBanCount         int `json:"max_global_user_ban_count" default:"20"`
	GlobalUserBanResetTime        int `json:"global_user_ban_reset_time" default:"600"`
	GlobalUserLockTime            int `json:"global_user_lock_time" default:"300"`
	MaxGlobalIPBanCount           int `json:"max_global_ip_ban_count" default:"40"`
	GlobalIPBanResetTime          int `json:"global_ip_ban_reset_time" default:"1200"`
	GlobalIPLockTime              int `json:"global_ip_lock_time" default:"300"`
	GlobalLockStateExpirationTime int `json:"global_lock_state_expiration_time" default:"3600"`

	// 企微/LDAP
	WexinWorkVerifyFileName    string `json:"weixin_work_verify_file_name"`
	WexinWorkVerifyFileContent string `json:"weixin_work_verify_file_content"`
	SyncLdapUsers              bool   `json:"sync_ldap_users"`
	SyncWxworkUsers            bool   `json:"sync_wxwork_users"`
	SyncFeishuUsers            bool   `json:"sync_feishu_users"`

	// 门户设置
	EnableUserPortal   bool   `json:"enable_user_portal"`
	EnableWebAuth      bool   `json:"enable_web_auth"`
	WebAuthBrowserMode string `json:"web_auth_browser_mode" default:"external"`

	// 高级功能可见性
	ShowFakeDNS bool `json:"show_fakedns" default:"false"`
}

type configMeta struct {
	usage     string
	group     string
	sensitive bool
	hidden    bool
	readonly  bool
	multiline bool
	options   map[string]string // 可选项: 显示名 -> 值
}

var configMetas = map[string]configMeta{
	"profile_name": {usage: "profile name(用于区分不同服务端的配置)", group: "基础信息"},
	"issuer":       {usage: "系统名称", group: "基础信息"},
	"admin_user":   {usage: "管理用户名", group: "基础信息"},
	"admin_pass":   {usage: "管理用户密码", group: "基础信息", sensitive: true, hidden: true},
	"admin_otp":    {usage: "管理用户OTP两步验证密钥,可在安全设置页面扫码绑定", group: "基础信息", sensitive: true, hidden: true},
	"jwt_secret":   {usage: "JWT密钥", group: "基础信息", sensitive: true},
	"admin_temp":   {usage: "管理员仍在使用首次生成或重置后的临时密码", group: "基础信息", hidden: true},

	"server_addr":         {usage: "TCP服务监听地址(任意端口)", group: "服务监听"},
	"server_dtls":         {usage: "开启DTLS", group: "服务监听"},
	"server_dtls_addr":    {usage: "DTLS监听地址(任意端口)", group: "服务监听"},
	"advertise_dtls_addr": {usage: "DTLS对外映射端口(为空则与server_dtls_addr相同)", group: "服务监听"},
	"admin_addr":          {usage: "后台服务监听地址", group: "服务监听"},
	"proxy_protocol":      {usage: "TCP代理协议", group: "服务监听"},
	"files_path":          {usage: "外部下载文件路径", group: "服务监听"},

	"db_type":   {usage: "数据库类型 [sqlite3 mysql postgres mssql]", group: "数据库", readonly: true},
	"db_source": {usage: "数据库source", group: "数据库", readonly: true},
	"show_sql":  {usage: "显示sql语句，用于调试", group: "数据库"},

	"link_mode":       {usage: "虚拟网络类型", group: "虚拟网络", options: map[string]string{"TUN": "tun", "TAP": "tap", "MACVTAP": "macvtap", "IPVTAP": "ipvtap"}},
	"ipv4_master":     {usage: "ipv4主网卡名称", group: "虚拟网络"},
	"ipv4_cidr":       {usage: "ip地址网段", group: "虚拟网络"},
	"ipv4_gateway":    {usage: "ipv4_gateway", group: "虚拟网络"},
	"ipv4_start":      {usage: "IPV4开始地址", group: "虚拟网络"},
	"ipv4_end":        {usage: "IPV4结束", group: "虚拟网络"},
	"ip_lease":        {usage: "IP租期(秒)", group: "虚拟网络"},
	"global_nat":      {usage: "是否自动添加全局NAT", group: "虚拟网络"},
	"firewall_driver": {usage: "防火墙后端", group: "虚拟网络", options: map[string]string{"自动选择": "auto", "nftables": "nftables", "iptables": "iptables"}},

	"max_client":        {usage: "最大用户连接", group: "连接控制"},
	"max_user_client":   {usage: "最大单用户连接", group: "连接控制"},
	"default_group":     {usage: "默认用户组", group: "连接控制"},
	"cstp_keepalive":    {usage: "keepalive时间(秒)", group: "连接控制"},
	"cstp_dpd":          {usage: "死链接检测时间(秒)", group: "连接控制"},
	"mobile_keepalive":  {usage: "移动端keepalive接检测时间(秒)", group: "连接控制"},
	"mobile_dpd":        {usage: "移动端死链接检测时间(秒)", group: "连接控制"},
	"mtu":               {usage: "最大传输单元MTU", group: "连接控制"},
	"default_domain":    {usage: "客户端dns的默认搜索域", group: "连接控制"},
	"idle_timeout":      {usage: "空闲链接超时时间(秒)-超时后断开链接，0关闭此功能", group: "连接控制"},
	"session_timeout":   {usage: "session过期时间(秒)-用于断线重连，0永不过期", group: "连接控制"},
	"compression":       {usage: "启用压缩", group: "连接控制"},
	"no_compress_limit": {usage: "低于及等于多少字节不压缩", group: "连接控制"},

	"log_path":        {usage: "日志文件路径,默认标准输出", group: "日志/调试"},
	"log_level":       {usage: "日志等级", group: "日志/调试", options: map[string]string{"Trace": "trace", "Debug": "debug", "Info": "info", "Warn": "warn", "Error": "error"}},
	"http_server_log": {usage: "开启go标准库http.Server的日志", group: "日志/调试"},
	"pprof":           {usage: "开启pprof", group: "日志/调试"},
	"audit_interval":  {usage: "审计去重间隔(秒),-1关闭", group: "日志/调试"},

	"display_error":       {usage: "客户端显示详细错误信息(线上环境慎开启)", group: "安全/认证"},
	"exclude_export_ip":   {usage: "排除出口ip路由(出口ip不加密传输)", group: "安全/认证"},
	"send_otp":            {usage: "是否发送OTP", group: "安全/认证"},
	"send_otp_type":       {usage: "发送OTP方式", group: "安全/认证", options: map[string]string{"邮件": "mail", "短信": "phone"}},
	"encryption_password": {usage: "用户密码是否加密保存", group: "安全/认证"},

	"anti_brute_force": {usage: "是否开启防爆功能", group: "防暴破"},
	"ip_whitelist":     {usage: "IP白名单", group: "防暴破", multiline: true},
	"ip_blacklist":     {usage: "IP黑名单", group: "防暴破", multiline: true},

	"max_ban_score":                     {usage: "单位时间内最大尝试次数，0为关闭该功能", group: "锁定策略"},
	"ban_reset_time":                    {usage: "设置单位时间(秒)，超过则重置计数", group: "锁定策略"},
	"lock_time":                         {usage: "超过最大尝试次数后的锁定时长(秒)", group: "锁定策略"},
	"max_global_user_ban_count":         {usage: "全局用户单位时间内最大尝试次数，0为关闭该功能", group: "锁定策略"},
	"global_user_ban_reset_time":        {usage: "全局用户设置单位时间(秒)", group: "锁定策略"},
	"global_user_lock_time":             {usage: "全局用户锁定时间(秒)", group: "锁定策略"},
	"max_global_ip_ban_count":           {usage: "全局IP单位时间内最大尝试次数，0为关闭该功能", group: "锁定策略"},
	"global_ip_ban_reset_time":          {usage: "全局IP设置单位时间(秒)", group: "锁定策略"},
	"global_ip_lock_time":               {usage: "全局IP锁定时间(秒)", group: "锁定策略"},
	"global_lock_state_expiration_time": {usage: "全局锁定状态的保存生命周期(秒),超过则删除记录", group: "锁定策略"},

	"weixin_work_verify_file_name":    {usage: "企微验证文件名", group: "企微/LDAP"},
	"weixin_work_verify_file_content": {usage: "企微验证文件内容", group: "企微/LDAP"},
	"sync_ldap_users":                 {usage: "是否自动同步LDAP用户", group: "企微/LDAP"},
	"sync_wxwork_users":               {usage: "是否自动同步企微用户", group: "企微/LDAP"},
	"sync_feishu_users":               {usage: "是否自动同步飞书用户", group: "企微/LDAP"},

	"enable_user_portal":    {usage: "开启用户门户，浏览器访问 VPN 服务地址时进入用户自助页面", group: "门户设置"},
	"enable_web_auth":       {usage: "开启 Web 认证模式，客户端登录改为浏览器认证流程", group: "门户设置"},
	"web_auth_browser_mode": {usage: "Web 认证浏览器模式", group: "门户设置", options: map[string]string{"内置": "internal", "系统": "external"}},

	"show_fakedns": {usage: "在管理界面显示 FakeDNS 功能入口", group: "高级功能可见性"},
}

const DefaultProfileXML = `<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile xmlns="http://schemas.xmlsoap.org/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                   xsi:schemaLocation="http://schemas.xmlsoap.org/encoding/ AnyConnectProfile.xsd">
    <ClientInitialization>
        <UseStartBeforeLogon>false</UseStartBeforeLogon>
        <AutoConnectOnStart>true</AutoConnectOnStart>
        <StrictCertificateTrust>false</StrictCertificateTrust>
        <RestrictPreferenceCaching>false</RestrictPreferenceCaching>
        <RestrictTunnelProtocols>IPSec</RestrictTunnelProtocols>
        <BypassDownloader>true</BypassDownloader>
        <AutoUpdate>false</AutoUpdate>
        <LocalLanAccess>true</LocalLanAccess>
        <WindowsVPNEstablishment>AllowRemoteUsers</WindowsVPNEstablishment>
        <LinuxVPNEstablishment>AllowRemoteUsers</LinuxVPNEstablishment>
        <CertEnrollmentPin>pinAllowed</CertEnrollmentPin>
        <CertificateStore>User</CertificateStore>
        <AutomaticCertSelection>true</AutomaticCertSelection>
    </ClientInitialization>
    <ServerList>
        <HostEntry>
            <HostName>RemLink</HostName>
            <HostAddress>https://remlink.example.com</HostAddress>
        </HostEntry>
    </ServerList>
</AnyConnectProfile>
`

// 客户端下载页默认 HTML
const DefaultDownloadHtml = `<div style="background:#fff;border:1px solid #edf1f7;border-left:3px solid #0078d4;border-radius:6px;padding:10px 14px;margin-bottom:8px">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<span style="font-size:13px;font-weight:600;color:#303133">Windows 客户端</span>
<span style="font-size:11px;color:#909399">Win 7 及以上</span>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/files/remlink-windows-amd64.exe" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">x64 安装包</a>
<a href="/files/remlink-windows-arm64.exe" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">ARM64 安装包</a>
</div>
</div>

<div style="background:#fff;border:1px solid #edf1f7;border-left:3px solid #555;border-radius:6px;padding:10px 14px;margin-bottom:8px">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<span style="font-size:13px;font-weight:600;color:#303133">macOS 客户端</span>
<span style="font-size:11px;color:#909399">macOS 10.13+</span>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/files/remlink-macos-amd64.dmg" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">Intel 芯片</a>
<a href="/files/remlink-macos-arm64.dmg" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">Apple 芯片</a>
</div>
</div>

<div style="background:#fff;border:1px solid #edf1f7;border-left:3px solid #f15a24;border-radius:6px;padding:10px 14px;margin-bottom:8px">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<span style="font-size:13px;font-weight:600;color:#303133">Linux 客户端</span>
<span style="font-size:11px;color:#909399">主流发行版</span>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/files/remlink-linux-amd64.tar.gz" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">x64 安装包</a>
<a href="/files/remlink-linux-arm64.tar.gz" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">ARM64 安装包</a>
</div>
</div>

<div style="background:#fff;border:1px solid #edf1f7;border-left:3px solid #3ddc84;border-radius:6px;padding:10px 14px;margin-bottom:8px">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<span style="font-size:13px;font-weight:600;color:#303133">Android 客户端</span>
<span style="font-size:11px;color:#909399">Android 5.0+</span>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="/files/remlink-android.apk" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">APK 安装包</a>
</div>
</div>

<div style="background:#fff;border:1px solid #edf1f7;border-left:3px solid #000;border-radius:6px;padding:10px 14px">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
<span style="font-size:13px;font-weight:600;color:#303133">iOS 客户端</span>
<span style="font-size:11px;color:#909399">iPhone / iPad</span>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<a href="https://apps.apple.com/app/cisco-anyconnect/id1135064690" target="_blank" style="padding:4px 12px;background:#ecf5ff;color:#409EFF;border:1px solid #d6e4ff;border-radius:4px;font-size:12px;text-decoration:none;font-weight:500">App Store</a>
</div>
</div>`
