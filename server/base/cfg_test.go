package base

import (
	"reflect"
	"sync"
	"testing"
)

func TestInitStoresNonNullPointer(t *testing.T) {
	cfg := GetCfg()
	if cfg == nil {
		t.Fatal("GetCfg() returned nil after init")
	}
}

func TestGetCfgReturnsConsistentSnapshot(t *testing.T) {
	cfg := &ServerConfig{
		MaxClient:     42,
		MaxUserClient: 7,
		Compression:   true,
	}
	SetCfgForTest(cfg)

	got := GetCfg()
	if got.MaxClient != 42 {
		t.Errorf("MaxClient = %d, want 42", got.MaxClient)
	}
	if got.MaxUserClient != 7 {
		t.Errorf("MaxUserClient = %d, want 7", got.MaxUserClient)
	}
	if !got.Compression {
		t.Error("Compression = false, want true")
	}
}

func TestSetCfgForTestPreservesAllFields(t *testing.T) {
	cfg := &ServerConfig{
		MaxClient:     100,
		MaxUserClient: 3,
		Compression:   true,
		Mtu:           1400,
	}
	SetCfgForTest(cfg)

	got := GetCfg()
	if got.MaxClient != 100 || got.MaxUserClient != 3 || !got.Compression || got.Mtu != 1400 {
		t.Error("config not preserved after SetCfgForTest")
	}
}

func TestConcurrentReadSafety(t *testing.T) {
	SetCfgForTest(&ServerConfig{MaxClient: 10})

	var wg sync.WaitGroup
	n := 1000
	wg.Add(n)

	for range n {
		go func() {
			defer wg.Done()
			_ = GetCfg().MaxClient
			_ = GetCfg().Compression
			_ = GetCfg().Mtu
		}()
	}
	wg.Wait()
}

func TestConcurrentReadWriteSafety(t *testing.T) {
	SetCfgForTest(&ServerConfig{MaxClient: 10})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 10000 {
			_ = GetCfg().MaxClient
		}
	}()

	go func() {
		defer wg.Done()
		for i := range 1000 {
			cfg := &ServerConfig{MaxClient: i}
			SetCfgForTest(cfg)
		}
	}()

	wg.Wait()
}

func TestUpdateCfg(t *testing.T) {
	SetCfgForTest(&ServerConfig{MaxClient: 10, Mtu: 1400})

	UpdateCfg(func(cfg *ServerConfig) {
		cfg.MaxClient = 99
		cfg.Compression = true
	})

	got := GetCfg()
	if got.MaxClient != 99 {
		t.Errorf("MaxClient = %d, want 99", got.MaxClient)
	}
	if got.Mtu != 1400 {
		t.Errorf("Mtu = %d, want 1400 (should be preserved)", got.Mtu)
	}
	if !got.Compression {
		t.Error("Compression should be true after UpdateCfg")
	}
}

func TestSetConfigField(t *testing.T) {
	SetCfgForTest(&ServerConfig{MaxClient: 10})

	restart, err := SetConfigField("max_client", 99)
	if err != nil {
		t.Fatalf("SetConfigField failed: %v", err)
	}
	if restart {
		t.Log("max_client triggers restart (expected)")
	}

	if GetCfg().MaxClient != 99 {
		t.Errorf("MaxClient = %d, want 99", GetCfg().MaxClient)
	}
}

// TestSetConfigFieldFloat64 锁定回归：前端经 JSON→any 传入的数字是 float64，
// 大数值（>=1e6，如 no_compress_limit 设 1MB）不能被 fmt 转成科学计数法导致解析失败。
func TestSetConfigFieldFloat64(t *testing.T) {
	SetCfgForTest(&ServerConfig{NoCompressLimit: 0})

	_, err := SetConfigField("no_compress_limit", float64(1048576))
	if err != nil {
		t.Fatalf("SetConfigField failed: %v", err)
	}
	if GetCfg().NoCompressLimit != 1048576 {
		t.Errorf("NoCompressLimit = %d, want 1048576", GetCfg().NoCompressLimit)
	}
}

func TestSetConfigFieldBool(t *testing.T) {
	SetCfgForTest(&ServerConfig{Compression: false})

	_, err := SetConfigField("compression", true)
	if err != nil {
		t.Fatalf("SetConfigField failed: %v", err)
	}
	if !GetCfg().Compression {
		t.Error("Compression should be true")
	}
}

func TestSetConfigFieldString(t *testing.T) {
	SetCfgForTest(&ServerConfig{LogLevel: "info"})

	_, err := SetConfigField("log_level", "debug")
	if err != nil {
		t.Fatalf("SetConfigField failed: %v", err)
	}
	if GetCfg().LogLevel != "debug" {
		t.Errorf("LogLevel = %s, want debug", GetCfg().LogLevel)
	}
}

func TestSetConfigFieldUnknown(t *testing.T) {
	_, err := SetConfigField("nonexistent_field", 123)
	if err == nil {
		t.Error("expected error for unknown field")
	}
}

func TestSetConfigFieldRejectsHiddenAndReadonly(t *testing.T) {
	if _, err := SetConfigField("admin_pass", "secret"); err == nil {
		t.Error("expected error for hidden field")
	}
	if _, err := SetConfigField("db_type", "mysql"); err == nil {
		t.Error("expected error for readonly field")
	}
}

func TestGetConfigMetaHidesAndMasksFields(t *testing.T) {
	SetCfgForTest(&ServerConfig{
		AdminPass: "hashed-password",
		JwtSecret: "jwt-secret",
	})

	var foundAdminPass bool
	var foundJwtSecret bool
	for _, item := range GetConfigMeta() {
		switch item["name"] {
		case "admin_pass":
			foundAdminPass = true
		case "jwt_secret":
			foundJwtSecret = true
			if item["data"] != "******" {
				t.Errorf("jwt_secret should be masked, got %v", item["data"])
			}
			if item["sensitive"] != true {
				t.Error("jwt_secret should be marked sensitive")
			}
		}
	}
	if foundAdminPass {
		t.Error("admin_pass should be hidden from config meta")
	}
	if !foundJwtSecret {
		t.Error("jwt_secret should be present in config meta")
	}
}

func TestGetSystemWarningsInitialSetup(t *testing.T) {
	SetCfgForTest(&ServerConfig{Issuer: "XX公司VPN"})
	warnings := GetSystemWarnings()
	if len(warnings) == 0 || warnings[0].Code != "initial_setup" || warnings[0].Message != InitialSetupWarning {
		t.Error("default issuer should trigger initial setup warning")
	}

	SetCfgForTest(&ServerConfig{Issuer: "Custom Corp"})
	for _, warning := range GetSystemWarnings() {
		if warning.Code == "initial_setup" {
			t.Error("custom config should not trigger initial setup warning")
		}
	}
}

func TestIsFieldSensitive(t *testing.T) {
	if !IsFieldSensitive("admin_pass") {
		t.Error("admin_pass should be sensitive")
	}
	if !IsFieldSensitive("jwt_secret") {
		t.Error("jwt_secret should be sensitive")
	}
	if IsFieldSensitive("max_client") {
		t.Error("max_client should NOT be sensitive")
	}
}

func TestConfigMetasCoverServerConfig(t *testing.T) {
	typ := reflect.TypeFor[ServerConfig]()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Tag.Get("json")
		if _, ok := configMetas[name]; !ok {
			t.Errorf("configMetas missing field %q", name)
		}
	}
}

// TestLoadPersistedPriority 锁定 LoadPersisted 的配置来源优先级：
// db.json(db_type/db_source) > 命令行/环境变量(explicitSet) > DB 持久化(incoming) > 启动期 flag 值(敏感字段, DB 为空时回退)
func TestLoadPersistedPriority(t *testing.T) {
	initLog() // 真实启动流程中 LoadPersisted 前 logger 已就绪
	m := NewConfigManager()
	// 模拟启动期：flag 设置了 max_client；db.json 提供了 db_type/db_source
	m.cfgPtr.Store(&ServerConfig{
		MaxClient: 5,            // 来自命令行 flag
		DbType:    "sqlite3",    // 来自 db.json
		DbSource:  "remlink.db", // 无父目录，避免测试创建目录
		AdminPass: "startup-pass",
		JwtSecret: "startup-jwt",
	})
	m.explicitSet = map[string]bool{"max_client": true}

	// 数据库持久化配置（与启动期不同，用于验证优先级）
	incoming := ServerConfig{
		MaxClient: 100,
		DbType:    "mysql",
		DbSource:  "/var/remlink.db",
		AdminPass: "db-pass",
		JwtSecret: "db-jwt",
	}

	m.LoadPersisted(incoming)

	got := m.Get()
	if got.MaxClient != 5 {
		t.Errorf("MaxClient = %d, want 5 (命令行 flag 应优先于 DB)", got.MaxClient)
	}
	if got.DbType != "sqlite3" {
		t.Errorf("DbType = %s, want sqlite3 (db.json 应优先于 DB)", got.DbType)
	}
	if got.DbSource != "remlink.db" {
		t.Errorf("DbSource = %s, want remlink.db (db.json 应优先于 DB)", got.DbSource)
	}
	if got.AdminPass != "db-pass" {
		t.Errorf("AdminPass = %s, want db-pass (DB 有值时应优先)", got.AdminPass)
	}
	if got.JwtSecret != "db-jwt" {
		t.Errorf("JwtSecret = %s, want db-jwt (DB 有值时应优先)", got.JwtSecret)
	}
}
