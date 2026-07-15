// 全局配置，基于 atomic.Pointer[ServerConfig] 无锁并发读写

package base

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"

	"github.com/wsczx/remlink/pkg/mask"
	"github.com/wsczx/remlink/pkg/utils"
)

type ConfigManager struct {
	cfgPtr atomic.Pointer[ServerConfig]
}

var defaultConfigManager = NewConfigManager()

var (
	configFields      = buildConfigFields()
	configFieldByName = buildConfigFieldByName(configFields)
)

func NewConfigManager() *ConfigManager {
	m := &ConfigManager{}
	m.cfgPtr.Store(&ServerConfig{})
	return m
}

func (m *ConfigManager) Get() *ServerConfig { return m.cfgPtr.Load() }

func (m *ConfigManager) Update(fn func(cfg *ServerConfig)) {
	for {
		old := m.cfgPtr.Load()
		newCfg := *old
		fn(&newCfg)
		if m.cfgPtr.CompareAndSwap(old, &newCfg) {
			return
		}
	}
}

func (m *ConfigManager) InitDirs() {
	cfg := m.Get()
	dirs := []string{
		filepath.Join(cfg.FilesPath, ".keep"),
	}
	if cfg.DbType == "sqlite3" {
		dirs = append(dirs, cfg.DbSource)
	}
	if cfg.LogPath != "" {
		dirs = append(dirs, cfg.LogPath)
	}
	for _, p := range dirs {
		CreateDir(filepath.Dir(p))
	}
}

func (m *ConfigManager) Complete(cfg *ServerConfig) {
	if cfg.JwtSecret == "" {
		cfg.JwtSecret = NewJwtSecret()
	}

	newAdminPass := ""
	if cfg.AdminPass == "" {
		plainPass, err := GenerateRandomPassword(16)
		if err != nil {
			Error("生成管理员随机密码失败:", err)
		} else {
			hash, hashErr := utils.PasswordHash(plainPass)
			if hashErr != nil {
				Error("生成管理员密码哈希失败:", hashErr)
			} else {
				cfg.AdminPass = hash
				cfg.AdminTemp = true
				newAdminPass = plainPass
			}
		}
	}

	if cfg.AdvertiseDTLSAddr == "" {
		cfg.AdvertiseDTLSAddr = cfg.ServerDTLSAddr
	}

	if newAdminPass != "" {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "  RemLink 首次启动 — 管理员账号信息\n")
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "  用户名:      %s\n", cfg.AdminUser)
		fmt.Fprintf(os.Stderr, "  初始密码:    %s\n", newAdminPass)
		fmt.Fprintf(os.Stderr, "  管理后台:    https://<服务器IP>%s\n", cfg.AdminAddr)
		fmt.Fprintf(os.Stderr, "========================================\n")
		fmt.Fprintf(os.Stderr, "  ⚠ 请立即登录修改密码！\n")
		fmt.Fprintf(os.Stderr, "  忘记密码时请停止服务后执行: remlink --reset-admin-password\n")
		fmt.Fprintf(os.Stderr, "========================================\n\n")
	}
}
func (m *ConfigManager) completeDerived(cfg *ServerConfig) {
	if cfg.AdvertiseDTLSAddr == "" {
		cfg.AdvertiseDTLSAddr = cfg.ServerDTLSAddr
	}
}

func (m *ConfigManager) ResetAdminPassword() string {
	plainPass, err := GenerateRandomPassword(16)
	if err != nil {
		Error("重置管理员密码失败（随机数不可用）:", err)
		return ""
	}
	hash, err := utils.PasswordHash(plainPass)
	if err != nil {
		Error("重置管理员密码失败（哈希）:", err)
		return ""
	}
	m.Update(func(c *ServerConfig) {
		c.AdminPass = hash
		c.AdminTemp = true
	})
	return plainPass
}

func (m *ConfigManager) DisableAdminOtp() {
	m.Update(func(c *ServerConfig) {
		c.AdminOtp = ""
	})
}

func (m *ConfigManager) EnableFakeDNS() {
	m.Update(func(c *ServerConfig) {
		c.ShowFakeDNS = true
	})
}

func (m *ConfigManager) applyDefaults(cfg *ServerConfig, skipSet map[string]bool) {
	ref := reflect.ValueOf(cfg)
	s := ref.Elem()
	typ := s.Type()
	for i := 0; i < s.NumField(); i++ {
		field := s.Field(i)
		tag := typ.Field(i).Tag
		name := tag.Get("json")
		dv := tag.Get("default")
		if dv == "" {
			continue
		}
		if skipSet[name] {
			continue
		}

		switch field.Kind() {
		case reflect.String:
			if field.String() != "" {
				continue
			}
			if dv == "defaultPwd" {
				continue
			}
			field.SetString(dv)
		case reflect.Int:
			if field.Int() != 0 {
				continue
			}
			var iv int64
			if _, e := fmt.Sscan(dv, &iv); e == nil {
				field.SetInt(iv)
			}
		case reflect.Bool:
			if field.Bool() {
				continue
			}
			field.SetBool(dv == "true")
		default:
			Warn("applyDefaults: unsupported field type", name, field.Kind().String())
		}
	}
}

func (m *ConfigManager) loadDbConfig(cfg *ServerConfig) {
	type dbCfg struct {
		DbType   string `json:"db_type"`
		DbSource string `json:"db_source"`
	}
	dbPath := filepath.Join("conf", "db.json")
	b, err := os.ReadFile(dbPath)
	if err == nil {
		var d dbCfg
		if jsonErr := json.Unmarshal(b, &d); jsonErr == nil {
			if d.DbType != "" {
				cfg.DbType = d.DbType
			}
			if d.DbSource != "" {
				cfg.DbSource = d.DbSource
			}
		} else {
			Warn("db.json 解析失败, 将使用默认配置:", jsonErr)
		}
		return
	}

	if cfg.DbType == "" {
		cfg.DbType = "sqlite3"
	}
	if cfg.DbSource == "" {
		cfg.DbSource = "./conf/remlink.db"
	}
	d := dbCfg{DbType: cfg.DbType, DbSource: cfg.DbSource}
	if data, err := json.MarshalIndent(d, "", "  "); err == nil {
		CreateDir("conf")
		if err := os.WriteFile(dbPath, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "[Warn] 写入 %s 失败: %v\n", dbPath, err)
		}
	}
}

func (m *ConfigManager) initCfg() {
	cfg := &ServerConfig{}

	ref := reflect.ValueOf(cfg).Elem()
	typ := ref.Type()

	explicitSet := make(map[string]bool)

	for i := 0; i < ref.NumField(); i++ {
		name := typ.Field(i).Tag.Get("json")
		value := ref.Field(i)
		switch value.Kind() {
		case reflect.String:
			value.SetString(linkViper.GetString(name))
		case reflect.Int:
			value.SetInt(int64(linkViper.GetInt(name)))
		case reflect.Bool:
			value.SetBool(linkViper.GetBool(name))
		}
		if linkViper.IsSet(name) {
			explicitSet[name] = true
		}
	}

	m.loadDbConfig(cfg)
	m.applyDefaults(cfg, explicitSet)

	m.cfgPtr.Store(cfg)
	m.InitDirs()
}

func (m *ConfigManager) fields() []configFieldMeta {
	return configFields
}

func (m *ConfigManager) field(name string) (configFieldMeta, bool) {
	field, ok := configFieldByName[name]
	return field, ok
}

func (m *ConfigManager) Meta() []map[string]any {
	cfg := m.Get()
	ref := reflect.ValueOf(cfg).Elem()

	var items []map[string]any
	for _, field := range m.fields() {
		if field.hidden {
			continue
		}
		val := ref.Field(field.index).Interface()

		// show_fakedns 为 false 时不在设置页显示，用户只能通过命令行重新开启
		if field.name == "show_fakedns" && val == false {
			continue
		}
		if field.sensitive {
			val = mask.Placeholder
		}

		item := map[string]interface{}{
			"name":      field.name,
			"usage":     field.usage,
			"type":      field.typ,
			"group":     field.group,
			"restart":   field.restart,
			"sensitive": field.sensitive,
			"readonly":  field.readonly,
			"multiline": field.multiline,
			"data":      val,
		}
		if field.options != nil {
			item["options"] = field.options
		}
		items = append(items, item)
	}
	return items
}

func (m *ConfigManager) SetField(name string, data any) (restart bool, err error) {
	field, found := m.field(name)
	if !found {
		return false, fmt.Errorf("未知配置项: %s", name)
	}
	if field.hidden {
		return false, fmt.Errorf("隐藏字段 %s 不能通过此 API 修改", name)
	}
	if field.readonly {
		return false, fmt.Errorf("只读字段 %s 不能通过此 API 修改", name)
	}
	if field.sensitive && fmt.Sprint(data) == mask.Placeholder {
		return false, fmt.Errorf("敏感配置 %s 未修改, 不能使用占位符", name)
	}
	restart = field.restart

	for {
		old := m.cfgPtr.Load()
		newCfg := *old
		value := reflect.ValueOf(&newCfg).Elem().Field(field.index)
		if err := setReflectValue(value, data); err != nil {
			return false, fmt.Errorf("设置配置项 %s 失败: %w", name, err)
		}

		m.completeDerived(&newCfg)
		if m.cfgPtr.CompareAndSwap(old, &newCfg) {
			if name == "log_level" {
				baseLevel.Store(int32(logLevel2Int(newCfg.LogLevel)))
			}
			if name == "log_path" {
				ReinitLog()
			}
			return restart, nil
		}
	}
}

func (m *ConfigManager) IsSensitive(name string) bool {
	field, found := m.field(name)
	return found && field.sensitive
}

func (m *ConfigManager) LoadPersisted(incoming ServerConfig) {
	m.Update(func(c *ServerConfig) {
		dbType, dbSource := c.DbType, c.DbSource
		jw, ap, ao := c.JwtSecret, c.AdminPass, c.AdminOtp
		*c = incoming
		c.DbType = dbType
		c.DbSource = dbSource
		if incoming.JwtSecret == "" {
			c.JwtSecret = jw
		}
		if incoming.AdminPass == "" {
			c.AdminPass = ap
		}
		if incoming.AdminOtp == "" {
			c.AdminOtp = ao
		}
		if c.AdminPass == "" || c.JwtSecret == "" {
			m.Complete(c)
		} else {
			m.completeDerived(c)
		}
	})
	m.InitDirs()
	// 重新应用日志路径
	ReinitLog()
}

func (m *ConfigManager) Warnings() []SystemWarning {
	cfg := m.Get()
	var warnings []SystemWarning
	if strings.Contains(cfg.Issuer, "XX公司") {
		warnings = append(warnings, SystemWarning{
			Code:       "initial_setup",
			Level:      "warning",
			Message:    InitialSetupWarning,
			ActionPath: "/admin/set/soft",
		})
	}
	if cfg.AdminTemp {
		warnings = append(warnings, SystemWarning{
			Code:       "admin_temp_password",
			Level:      "error",
			Message:    "管理员仍在使用首次生成或命令重置后的临时密码，请在系统设置 > 安全设置中立即修改管理员密码",
			ActionPath: "/admin/set/security",
		})
	}
	if cfg.GlobalNat {
		if _, err := net.InterfaceByName(cfg.Ipv4Master); err != nil {
			ifaces := utils.GetPhysicalInterfaces()
			msg := "NAT配置错误：主网卡未正确配置，NAT转发规则无法生效，请在软件配置中修改 ipv4_master"
			if len(ifaces) > 0 {
				msg += fmt.Sprintf("（可用物理网卡: %s）", strings.Join(ifaces, ", "))
			}
			warnings = append(warnings, SystemWarning{
				Code:       "nat_interface_missing",
				Level:      "error",
				Message:    msg,
				ActionPath: "/admin/set/soft",
			})
		}
	}
	return warnings
}

func (m *ConfigManager) SetForTest(cfg *ServerConfig) { m.cfgPtr.Store(cfg) }

type configFieldMeta struct {
	index     int
	name      string
	usage     string
	typ       string
	group     string
	restart   bool
	sensitive bool
	hidden    bool
	readonly  bool
	multiline bool
	options   map[string]string
}

func valueType(kind reflect.Kind) string {
	switch kind {
	case reflect.Int:
		return "int"
	case reflect.Bool:
		return "bool"
	default:
		return "string"
	}
}

func buildConfigFields() []configFieldMeta {
	typ := reflect.TypeOf(ServerConfig{})
	fields := make([]configFieldMeta, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, buildFieldMeta(typ.Field(i), i))
	}
	return fields
}

func buildConfigFieldByName(fields []configFieldMeta) map[string]configFieldMeta {
	result := make(map[string]configFieldMeta, len(fields))
	for _, field := range fields {
		result[field.name] = field
	}
	return result
}

func buildFieldMeta(field reflect.StructField, index int) configFieldMeta {
	tag := field.Tag
	name := tag.Get("json")
	meta := configMetas[name]
	return configFieldMeta{
		index:     index,
		name:      name,
		usage:     meta.usage,
		typ:       valueType(field.Type.Kind()),
		group:     meta.group,
		restart:   tag.Get("restart") == "true",
		sensitive: meta.sensitive,
		hidden:    meta.hidden,
		readonly:  meta.readonly,
		multiline: meta.multiline,
		options:   meta.options,
	}
}

func setReflectValue(value reflect.Value, data any) error {
	switch value.Kind() {
	case reflect.String:
		value.SetString(fmt.Sprint(data))
	case reflect.Int:
		switch v := data.(type) {
		case float64:
			value.SetInt(int64(v))
		case int:
			value.SetInt(int64(v))
		default:
			var iv int64
			if _, err := fmt.Sscan(fmt.Sprint(data), &iv); err != nil {
				return err
			}
			value.SetInt(iv)
		}
	case reflect.Bool:
		switch v := data.(type) {
		case bool:
			value.SetBool(v)
		default:
			value.SetBool(fmt.Sprint(data) == "true")
		}
	default:
		return fmt.Errorf("不支持的配置类型")
	}
	return nil
}

func initCfg() { defaultConfigManager.initCfg() }

// 返回当前配置快照。
func GetCfg() *ServerConfig { return defaultConfigManager.Get() }

// 基于当前配置副本执行修改并原子替换。
func UpdateCfg(fn func(cfg *ServerConfig)) { defaultConfigManager.Update(fn) }

func InitConfigDirs() { defaultConfigManager.InitDirs() }

// 补齐运行必需的派生配置。
func CompleteConfig(cfg *ServerConfig) { defaultConfigManager.Complete(cfg) }

// 重置管理员密码，返回明文密码。
func ResetAdminPassword() string { return defaultConfigManager.ResetAdminPassword() }

// 清空管理员 OTP 密钥。
func DisableAdminOtp() { defaultConfigManager.DisableAdminOtp() }

// 开启 FakeDNS 功能可见性。
func EnableFakeDNS() { defaultConfigManager.EnableFakeDNS() }

// 返回前端配置表单元数据。
func GetConfigMeta() []map[string]any { return defaultConfigManager.Meta() }

// 修改单个配置项，返回是否需要重启。
func SetConfigField(name string, data any) (restart bool, err error) {
	return defaultConfigManager.SetField(name, data)
}

// 判断配置项是否敏感。
func IsFieldSensitive(name string) bool { return defaultConfigManager.IsSensitive(name) }

// 用数据库配置覆盖当前配置。
func LoadPersistedConfig(incoming ServerConfig) { defaultConfigManager.LoadPersisted(incoming) }

// 返回当前配置触发的系统警告。
func GetSystemWarnings() []SystemWarning { return defaultConfigManager.Warnings() }

// 替换全局配置，仅用于测试。
func SetCfgForTest(cfg *ServerConfig) { defaultConfigManager.SetForTest(cfg) }

// 使用系统随机源生成密码。
func GenerateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", fmt.Errorf("crypto/rand 读取失败: %w", err)
		}
		b[i] = charset[n.Int64()]
	}
	return string(b), nil
}

func CreateDir(dir string) {
	if dir == "" || dir == "." {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		fmt.Fprintln(os.Stderr, "create dir err:", err)
	}
}

func NewJwtSecret() string {
	jwtSecret, err := utils.RandSecret(40, 60)
	if err != nil {
		Error("生成JWT密钥失败:", err)
	}
	return strings.Trim(jwtSecret, "=")
}
