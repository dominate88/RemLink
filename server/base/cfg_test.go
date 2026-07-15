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

	for i := 0; i < n; i++ {
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
		for i := 0; i < 10000; i++ {
			_ = GetCfg().MaxClient
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
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
	typ := reflect.TypeOf(ServerConfig{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Tag.Get("json")
		if _, ok := configMetas[name]; !ok {
			t.Errorf("configMetas missing field %q", name)
		}
	}
}
