// 在线升级：通过 GitHub Releases 检查更新、下载、校验、替换、重启
package base

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	upgradeRepoOwner = "wsczx"
	upgradeRepoName  = "RemLink"
)

type ReleaseInfo struct {
	Version     string `json:"version"`
	Body        string `json:"body"`
	URL         string `json:"url"`
	Size        int64  `json:"size"`
	Checksum    string `json:"checksum"`
	PublishedAt string `json:"published_at"`
}

type UpgradeProgress struct {
	Stage      string `json:"stage"`
	Progress   int    `json:"progress"`
	Downloaded int64  `json:"downloaded"`
	Total      int64  `json:"total"`
	Error      string `json:"error,omitempty"`
}

type githubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	Body        string        `json:"body"`
	PublishedAt string        `json:"published_at"`
	Assets      []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

type UpgradeStatus struct {
	Running  bool            `json:"running"`
	Progress UpgradeProgress `json:"progress"`
}

var (
	upgradeRunning  atomic.Bool
	upgradeProgress UpgradeProgress
	upgradeProgMux  sync.RWMutex
)

// 检查最新版本，返回 ReleaseInfo、是否需要更新
func CheckUpdate() (*ReleaseInfo, bool, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest",
		upgradeRepoOwner, upgradeRepoName)

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "RemLink-Upgrade")

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("访问 GitHub API 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GitHub API 返回状态码: %d", resp.StatusCode)
	}

	var gr githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return nil, false, fmt.Errorf("解析 GitHub 返回数据失败: %w", err)
	}

	// asset 格式: remlink-{version}-{os}-{arch}.tar.gz
	currentOS := runtime.GOOS
	currentArch := runtime.GOARCH

	var downloadAsset *githubAsset
	for i := range gr.Assets {
		a := &gr.Assets[i]
		name := strings.ToLower(a.Name)
		if strings.Contains(name, currentOS) && strings.Contains(name, currentArch) {
			downloadAsset = a
			break
		}
	}

	if downloadAsset == nil {
		return nil, false, fmt.Errorf("未找到适用于当前平台 %s-%s 的下载资源", currentOS, currentArch)
	}

	latestVersion := strings.TrimPrefix(gr.TagName, "v")
	currentVersion := APP_VER
	needUpgrade := compareVersion(latestVersion, currentVersion) > 0

	ri := &ReleaseInfo{
		Version:     gr.TagName,
		Body:        gr.Body,
		URL:         downloadAsset.BrowserDownloadURL,
		Size:        downloadAsset.Size,
		PublishedAt: gr.PublishedAt,
	}

	return ri, needUpgrade, nil
}

// 执行升级：下载 → 解压 → 校验 → 替换 → 重启
func DoUpgrade(info *ReleaseInfo, progressCh chan<- UpgradeProgress) {
	defer close(progressCh)

	if upgradeRunning.Load() {
		progressCh <- UpgradeProgress{Stage: "error", Error: "已有升级任务在运行"}
		return
	}
	upgradeRunning.Store(true)
	defer func() { upgradeRunning.Store(false) }()

	// 阶段1：下载
	sendProgress(progressCh, "downloading", 0, 0, info.Size)
	archiveFile, err := downloadBinary(info.URL, info.Size, progressCh)
	if err != nil {
		sendError(progressCh, "下载失败: "+err.Error())
		return
	}
	defer os.Remove(archiveFile)

	// 阶段2：解压
	sendProgress(progressCh, "extracting", 90, info.Size, info.Size)
	binFile, err := extractBinary(archiveFile)
	if err != nil {
		sendError(progressCh, "解压失败: "+err.Error())
		return
	}
	defer os.Remove(binFile)

	// 阶段3：校验（强制）
	if info.Checksum == "" {
		sendError(progressCh, "升级信息缺少校验和，拒绝执行")
		return
	}
	sendProgress(progressCh, "verifying", 95, info.Size, info.Size)
	if err := verifyChecksum(binFile, info.Checksum); err != nil {
		sendError(progressCh, "文件校验失败: "+err.Error())
		return
	}

	// 阶段4：替换
	sendProgress(progressCh, "replacing", 98, info.Size, info.Size)
	exePath, err := replaceBinary(binFile)
	if err != nil {
		sendError(progressCh, "替换二进制文件失败: "+err.Error())
		return
	}

	// 阶段5：重启
	sendProgress(progressCh, "restarting", 100, info.Size, info.Size)
	sendProgress(progressCh, "done", 100, info.Size, info.Size)

	time.Sleep(500 * time.Millisecond)
	closeNonStdFDs()
	if err := syscall.Exec(exePath, os.Args, os.Environ()); err != nil {
		Error("在线升级重启失败:", err)
	}
}

// 下载二进制到临时文件，通过 progressCh 推送进度
func downloadBinary(url string, totalSize int64, progressCh chan<- UpgradeProgress) (string, error) {
	client := &http.Client{Timeout: 30 * time.Minute}

	var resp *http.Response
	var err error
	for retry := 0; retry < 3; retry++ {
		req, reqErr := http.NewRequest("GET", url, nil)
		if reqErr != nil {
			return "", fmt.Errorf("创建下载请求失败: %w", reqErr)
		}
		req.Header.Set("User-Agent", "RemLink-Upgrade")

		resp, err = client.Do(req)
		if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if retry < 2 {
			time.Sleep(time.Duration(retry+1) * time.Second)
		}
	}
	if err != nil {
		return "", fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载返回状态码: %d", resp.StatusCode)
	}

	tmpDir := os.TempDir()
	if free, err := diskFree(tmpDir); err == nil && totalSize > 0 {
		if free < totalSize+50*1024*1024 {
			return "", fmt.Errorf("磁盘空间不足，需要 %s，剩余 %s", humanSize(totalSize), humanSize(free))
		}
	}

	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("remlink_upgrade_%d", time.Now().Unix()))
	f, err := os.Create(tmpFile)
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	var downloaded int64
	lastReport := time.Now()

	total := resp.ContentLength
	if total <= 0 {
		total = totalSize
	}

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := f.Write(buf[:n]); writeErr != nil {
				return "", fmt.Errorf("写入临时文件失败: %w", writeErr)
			}
			downloaded += int64(n)

			if time.Since(lastReport) > 200*time.Millisecond {
				sendProgress(progressCh, "downloading", calcPercent(downloaded, total), downloaded, total)
				lastReport = time.Now()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("下载过程出错: %w", readErr)
		}
	}

	sendProgress(progressCh, "downloading", 100, downloaded, total)
	Info("在线升级: 下载完成 ", tmpFile, " 大小:", humanSize(downloaded))
	return tmpFile, nil
}

// 从 .tar.gz 中提取 remlink 可执行文件，返回临时文件路径
func extractBinary(tarGzPath string) (string, error) {
	f, err := os.Open(tarGzPath)
	if err != nil {
		return "", fmt.Errorf("打开压缩包失败: %w", err)
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("创建 gzip reader 失败: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)

	tmpDir := os.TempDir()
	outFile := filepath.Join(tmpDir, fmt.Sprintf("remlink_bin_%d", time.Now().Unix()))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("读取 tar 条目失败: %w", err)
		}

		// 找到 remlink 可执行文件
		name := filepath.Base(header.Name)
		if name != "remlink" {
			continue
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		out, err := os.Create(outFile)
		if err != nil {
			return "", fmt.Errorf("创建解压文件失败: %w", err)
		}
		defer out.Close()

		if _, err := io.Copy(out, tarReader); err != nil {
			return "", fmt.Errorf("解压写入失败: %w", err)
		}

		if err := os.Chmod(outFile, 0755); err != nil {
			return "", fmt.Errorf("设置执行权限失败: %w", err)
		}

		Info("在线升级: 解压完成 ", outFile)
		return outFile, nil
	}

	return "", fmt.Errorf("压缩包中未找到 remlink 可执行文件")
}

// 校验 SHA256
func verifyChecksum(filePath, expectedChecksum string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("计算校验和失败: %w", err)
	}

	actualChecksum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		return fmt.Errorf("SHA256 校验不匹配:\n  期望: %s\n  实际: %s", expectedChecksum, actualChecksum)
	}
	Info("在线升级: SHA256 校验通过")
	return nil
}

// 复制到同名临时文件 → rename 替换 → 备份旧文件
func replaceBinary(newFile string) (string, error) {
	app, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取当前可执行文件路径失败: %w", err)
	}

	bakFile := app + ".bak"
	if err := copyFile(app, bakFile); err != nil {
		Warn("备份旧二进制失败:", err)
	} else {
		Info("在线升级: 旧二进制已备份到 ", bakFile)
	}

	tmpDest := app + ".new"
	if err := copyFile(newFile, tmpDest); err != nil {
		return app, fmt.Errorf("复制新文件失败: %w", err)
	}

	if err := os.Rename(tmpDest, app); err != nil {
		os.Remove(tmpDest)
		return app, fmt.Errorf("替换二进制文件失败: %w", err)
	}

	if err := os.Chmod(app, 0755); err != nil {
		Warn("设置执行权限失败:", err)
	}

	Info("在线升级: 二进制替换完成")
	return app, nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()

	if _, err := io.Copy(d, s); err != nil {
		return err
	}
	return d.Sync()
}

// 所在磁盘可用空间
func diskFree(path string) (int64, error) {
	var stat sysStatfs
	if err := statfs(path, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

type sysStatfs struct {
	Bsize  uint64
	Bavail uint64
}

// 字节数转为可读格式
func humanSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func sendProgress(ch chan<- UpgradeProgress, stage string, progress int, downloaded, total int64) {
	p := UpgradeProgress{
		Stage:      stage,
		Progress:   progress,
		Downloaded: downloaded,
		Total:      total,
	}
	upgradeProgMux.Lock()
	upgradeProgress = p
	upgradeProgMux.Unlock()
	select {
	case ch <- p:
	default:
	}
}

func sendError(ch chan<- UpgradeProgress, errMsg string) {
	Error("在线升级: ", errMsg)
	p := UpgradeProgress{
		Stage: "error",
		Error: errMsg,
	}
	upgradeProgMux.Lock()
	upgradeProgress = p
	upgradeProgMux.Unlock()
	select {
	case ch <- p:
	default:
	}
}

func calcPercent(downloaded, total int64) int {
	if total <= 0 {
		return 0
	}
	p := int(downloaded * 100 / total)
	if p > 100 {
		p = 100
	}
	return p
}

// compareVersion 比较两个语义化版本号
// 返回值: >0 表示 v1 > v2, <0 表示 v1 < v2, 0 表示相等
func compareVersion(v1, v2 string) int {
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// 分离预发布后缀
	v1Base, v1Pre := splitVersion(v1)
	v2Base, v2Pre := splitVersion(v2)

	// 比较基础版本号
	if c := compareBase(v1Base, v2Base); c != 0 {
		return c
	}

	// 基础版本相同，比较预发布
	// 无预发布 > 有预发布（正式版 > 测试版）
	if v1Pre == "" && v2Pre == "" {
		return 0
	}
	if v1Pre == "" {
		return 1
	}
	if v2Pre == "" {
		return -1
	}
	if v1Pre < v2Pre {
		return -1
	}
	if v1Pre > v2Pre {
		return 1
	}
	return 0
}

// 将版本号拆分为基础版本和预发布后缀
func splitVersion(v string) (base, pre string) {
	for i, c := range v {
		if c == '-' {
			return v[:i], v[i+1:]
		}
	}
	return v, ""
}

// 比较 x.y.z 形式的基础版本号
func compareBase(a, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	maxLen := len(partsA)
	if len(partsB) > maxLen {
		maxLen = len(partsB)
	}
	for i := 0; i < maxLen; i++ {
		na, nb := 0, 0
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na > nb {
			return 1
		}
		if na < nb {
			return -1
		}
	}
	return 0
}

func statfs(path string, stat *sysStatfs) error {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return err
	}
	stat.Bsize = uint64(s.Bsize)
	stat.Bavail = uint64(s.Bavail)
	return nil
}
