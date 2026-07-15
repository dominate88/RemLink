package dbdata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/wsczx/remlink/base"
	"xorm.io/xorm"
)

const backupFileDir = "./conf/backup"
const currentBackupVersion = 1
const restoreBatchSize = 500

type backupTable struct {
	Name  string // 表名
	Label string // 中文名称
	Group string // "business" / "log" / "stats"
	Model any    // 结构体实例，如 User{}
}

func (t backupTable) newSlicePtr() any {
	return reflect.New(reflect.SliceOf(reflect.TypeOf(t.Model))).Interface()
}

func (t backupTable) newPtr() any {
	return reflect.New(reflect.TypeOf(t.Model)).Interface()
}

var backupTables = []backupTable{
	{"user", "用户", "business", User{}},
	{"group", "用户组", "business", Group{}},
	{"setting", "系统设置", "business", Setting{}},
	{"policy", "用户策略", "business", Policy{}},
	{"client_cert_data", "客户端证书", "business", ClientCertData{}},
	{"ip_map", "IP-MAC绑定", "business", IpMap{}},
	{"password_reset", "密码重置令牌", "business", PasswordReset{}},
	{"provider", "认证源", "business", Provider{}},
	{"user_act_log", "用户活动日志", "log", UserActLog{}},
	{"access_audit", "访问审计", "log", AccessAudit{}},
	{"admin_op_log", "管理员操作日志", "log", AdminOpLog{}},
	{"stats_online", "在线人数统计", "stats", StatsOnline{}},
	{"stats_network", "网络流量统计", "stats", StatsNetwork{}},
	{"stats_cpu", "CPU使用率统计", "stats", StatsCpu{}},
	{"stats_mem", "内存使用率统计", "stats", StatsMem{}},
}

var backupTableByName = func() map[string]backupTable {
	m := make(map[string]backupTable, len(backupTables))
	for _, t := range backupTables {
		m[t.Name] = t
	}
	return m
}()

type BackupData struct {
	Version   int                        `json:"version"`
	Type      string                     `json:"type"` // "config" | "full"
	CreatedAt string                     `json:"created_at"`
	DbType    string                     `json:"db_type"`
	DbSource  string                     `json:"db_source"`
	Config    *base.ServerConfig         `json:"config,omitempty"`
	Tables    map[string]json.RawMessage `json:"tables,omitempty"`
	TLSCert   *SettingTLSCert            `json:"tls_cert,omitempty"`
	ClientCA  *SettingClientCA           `json:"client_ca,omitempty"`
}

type TableSizeInfo struct {
	Table string `json:"table"`
	Name  string `json:"name"`
	Rows  int64  `json:"rows"`
	Group string `json:"group"`
}

type BackupFileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	Type    string `json:"type"`
}

func AllTableNames() []string {
	names := make([]string, len(backupTables))
	for i, t := range backupTables {
		names[i] = t.Name
	}
	sort.Strings(names)
	return names
}

func GetTableSizes() []TableSizeInfo {
	result := make([]TableSizeInfo, 0, len(backupTables))
	for _, t := range backupTables {
		result = append(result, TableSizeInfo{
			Table: t.Name,
			Name:  t.Label,
			Rows:  tableCount(t.Name),
			Group: t.Group,
		})
	}
	return result
}

func tableCount(name string) int64 {
	bt, ok := backupTableByName[name]
	if !ok {
		return 0
	}
	n, err := xdb.Count(bt.newPtr())
	if err != nil {
		base.Error("tableCount:", name, err)
		return 0
	}
	return n
}

type dbConfig struct {
	DbType   string `json:"db_type"`
	DbSource string `json:"db_source"`
}

func SaveDbConfig(dbType, dbSource string) error {
	cfg := dbConfig{DbType: dbType, DbSource: dbSource}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	base.CreateDir("conf")
	return os.WriteFile(filepath.Join("conf", "db.json"), b, 0600)
}

func CreateBackup(backupType string, includeTables []string) (string, error) {
	cfg := base.GetCfg()
	cfgCopy := *cfg
	cfgCopy.JwtSecret = ""
	cfgCopy.AdminPass = ""
	cfgCopy.AdminOtp = ""

	data := &BackupData{
		Version:   currentBackupVersion,
		Type:      backupType,
		CreatedAt: time.Now().Format(time.RFC3339),
		DbType:    cfg.DbType,
		DbSource:  cfg.DbSource,
		Config:    &cfgCopy,
	}

	var tlsCert SettingTLSCert
	if err := SettingGet(&tlsCert); err == nil && tlsCert.CertContent != "" {
		data.TLSCert = &tlsCert
	}
	var clientCA SettingClientCA
	if err := SettingGet(&clientCA); err == nil && clientCA.CertContent != "" {
		data.ClientCA = &clientCA
	}

	if backupType == "full" {
		tables := includeTables
		if tables == nil {
			tables = allBusinessTableNames()
		}
		data.Tables = make(map[string]json.RawMessage, len(tables))
		for _, t := range tables {
			raw, err := tableExport(t)
			if err != nil {
				return "", fmt.Errorf("备份表 %s 失败: %w", t, err)
			}
			data.Tables[t] = raw
		}
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}

	tag := "config"
	if backupType == "full" {
		tag = "full"
	}
	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("remlink_backup_%s_%s.json", tag, ts)
	filePath := filepath.Join(backupFileDir, filename)

	base.CreateDir(backupFileDir)
	if err := os.WriteFile(filePath, b, 0600); err != nil {
		return "", err
	}

	base.Info("backup created:", filePath)
	return filename, nil
}

func allBusinessTableNames() []string {
	var names []string
	for _, t := range backupTables {
		if t.Group == "business" {
			names = append(names, t.Name)
		}
	}
	return names
}

func tableExport(name string) (json.RawMessage, error) {
	bt, ok := backupTableByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown table: %s", name)
	}
	slicePtr := bt.newSlicePtr()
	if err := xdb.Find(slicePtr); err != nil {
		return nil, err
	}
	return json.Marshal(slicePtr)
}

func ListBackups() ([]BackupFileInfo, error) {
	base.CreateDir(backupFileDir)
	entries, err := os.ReadDir(backupFileDir)
	if err != nil {
		return nil, err
	}

	var result []BackupFileInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "remlink_backup_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		bt := "config"
		if strings.Contains(name, "_full_") {
			bt = "full"
		}
		result = append(result, BackupFileInfo{
			Name:    name,
			Size:    info.Size(),
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
			Type:    bt,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ModTime > result[j].ModTime
	})
	return result, nil
}

func DeleteBackup(filename string) error {
	cleaned := filepath.Clean(filename)
	if cleaned != filepath.Base(cleaned) || cleaned == "." || cleaned == ".." {
		return fmt.Errorf("invalid backup filename")
	}
	if !strings.HasPrefix(cleaned, "remlink_backup_") {
		return fmt.Errorf("invalid backup filename")
	}
	return os.Remove(filepath.Join(backupFileDir, cleaned))
}

func RestoreBackup(filename string) error {
	data, err := backupFileRead(filename)
	if err != nil {
		return err
	}

	sess := xdb.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	cfgCopy, err := backupRestoreToSession(sess, data)
	if err != nil {
		sess.Rollback()
		return err
	}

	if err := sess.Commit(); err != nil {
		return err
	}

	if cfgCopy != nil {
		base.LoadPersistedConfig(*cfgCopy)
		resetClientCA()
	}

	base.Info("backup restored:", filename)
	return nil
}

func RestoreBackupToEngine(engine *xorm.Engine, filename string) error {
	data, err := backupFileRead(filename)
	if err != nil {
		return err
	}

	sess := engine.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	_, err = backupRestoreToSession(sess, data)
	if err != nil {
		sess.Rollback()
		return err
	}

	return sess.Commit()
}

func backupFileRead(filename string) (*BackupData, error) {
	cleaned := filepath.Clean(filename)
	if cleaned != filepath.Base(cleaned) || cleaned == "." || cleaned == ".." {
		return nil, fmt.Errorf("invalid backup filename")
	}
	if !strings.HasPrefix(cleaned, "remlink_backup_") {
		return nil, fmt.Errorf("invalid backup filename")
	}

	b, err := os.ReadFile(filepath.Join(backupFileDir, cleaned))
	if err != nil {
		return nil, fmt.Errorf("读取备份文件失败: %w", err)
	}

	var data BackupData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, fmt.Errorf("解析备份文件失败: %w", err)
	}

	if data.Version != currentBackupVersion {
		return nil, fmt.Errorf("备份文件版本不兼容: 当前支持版本 %d，备份文件版本 %d", currentBackupVersion, data.Version)
	}

	return &data, nil
}

func backupRestoreToSession(sess *xorm.Session, data *BackupData) (*base.ServerConfig, error) {
	if err := restoreTables(sess, data); err != nil {
		return nil, err
	}
	return restoreConfig(sess, data)
}

func restoreTables(sess *xorm.Session, data *BackupData) error {
	if data.Tables == nil {
		return nil
	}

	existing := make(map[string]bool, len(data.Tables))
	for name := range data.Tables {
		bt, ok := backupTableByName[name]
		if !ok {
			continue
		}
		exist, err := sess.IsTableExist(bt.newPtr())
		if err != nil {
			return fmt.Errorf("检查表 %s 是否存在失败: %w", name, err)
		}
		existing[name] = exist
	}

	for name := range data.Tables {
		if !existing[name] {
			continue
		}
		if err := tableClear(sess, name); err != nil {
			return fmt.Errorf("清空表 %s 失败: %w", name, err)
		}
	}

	for name, raw := range data.Tables {
		if !existing[name] {
			continue
		}
		if err := tableImport(sess, name, raw); err != nil {
			return fmt.Errorf("还原表 %s 失败: %w", name, err)
		}
	}

	return nil
}

func tableClear(sess *xorm.Session, name string) error {
	bt, ok := backupTableByName[name]
	if !ok {
		return fmt.Errorf("unknown table: %s", name)
	}
	_, err := sess.Where("1=1").Delete(bt.newPtr())
	return err
}

func tableImport(sess *xorm.Session, name string, raw json.RawMessage) error {
	bt, ok := backupTableByName[name]
	if !ok {
		return fmt.Errorf("unknown table: %s", name)
	}

	slicePtr := bt.newSlicePtr()
	if err := json.Unmarshal(raw, slicePtr); err != nil {
		return fmt.Errorf("解析表 %s 数据失败: %w", name, err)
	}

	v := reflect.ValueOf(slicePtr).Elem()
	n := v.Len()
	if n == 0 {
		return nil
	}

	if n <= restoreBatchSize {
		_, err := sess.Insert(slicePtr)
		return err
	}

	for i := 0; i < n; i += restoreBatchSize {
		end := i + restoreBatchSize
		if end > n {
			end = n
		}
		batch := v.Slice(i, end).Interface()
		if _, err := sess.Insert(batch); err != nil {
			return err
		}
	}
	return nil
}

func restoreConfig(sess *xorm.Session, data *BackupData) (*base.ServerConfig, error) {
	if data.Config == nil {
		return nil, nil
	}

	cfgCopy := *data.Config
	cfgSnapshot := base.GetCfg()
	cfgCopy.DbType = cfgSnapshot.DbType
	cfgCopy.DbSource = cfgSnapshot.DbSource

	// 恢复密钥
	var currentSC SettingServerConfig
	if err := SettingSessGet(sess, &currentSC); err == nil {
		if cfgCopy.JwtSecret == "" {
			cfgCopy.JwtSecret = currentSC.Config.JwtSecret
		}
		if cfgCopy.AdminPass == "" {
			cfgCopy.AdminPass = currentSC.Config.AdminPass
		}
		if cfgCopy.AdminOtp == "" {
			cfgCopy.AdminOtp = currentSC.Config.AdminOtp
		}
	}

	sc := &SettingServerConfig{Config: cfgCopy}
	if _, err := sess.Where("name = ?", "SettingServerConfig").Delete(&Setting{}); err != nil {
		return nil, err
	}
	if err := SettingSessAdd(sess, sc); err != nil {
		return nil, fmt.Errorf("还原配置失败: %w", err)
	}

	if data.TLSCert != nil && data.TLSCert.CertContent != "" {
		if err := restoreCertSetting(sess, "SettingTLSCert", data.TLSCert); err != nil {
			return nil, fmt.Errorf("还原 TLS 证书失败: %w", err)
		}
	}
	if data.ClientCA != nil && data.ClientCA.CertContent != "" {
		if err := restoreCertSetting(sess, "SettingClientCA", data.ClientCA); err != nil {
			return nil, fmt.Errorf("还原客户端 CA 证书失败: %w", err)
		}
	}

	return &cfgCopy, nil
}

func restoreCertSetting(sess *xorm.Session, name string, certData any) error {
	b, err := json.Marshal(certData)
	if err != nil {
		return fmt.Errorf("序列化 %s 失败: %w", name, err)
	}
	if _, err := sess.Where("name = ?", name).Delete(&Setting{}); err != nil {
		return err
	}
	_, err = sess.InsertOne(&Setting{Name: name, Data: b})
	return err
}
