package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// 钉钉认证配置（企业内部应用 OAuth2 扫码登录）
type DingtalkConfig struct {
	ClientID           string `json:"client_id"`           // 钉钉应用 AppKey
	ClientSecret       string `json:"client_secret"`       // 钉钉应用 AppSecret
	AllowedDepartments string `json:"allowed_departments"` // 允许的部门 ID，逗号分隔；为空表示不限制
	BlockedUserIDs     string `json:"blocked_userids"`     // 拒绝的用户 ID 列表，逗号分隔
	UseDefaultBrowser  bool   `json:"use_default_browser"` // 默认使用浏览器打开钉钉授权页面
	SyncUsers          bool   `json:"sync_users"`          // 同步用户到本地
}

// 校验配置完整性
func (c *DingtalkConfig) ValidateConfig() error {
	if c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("钉钉配置不完整：client_id 与 client_secret 均必填")
	}
	return nil
}

// 解析允许的部门 ID 列表（仅保留非空项）
func (c *DingtalkConfig) ParseDepartments() []string {
	out := make([]string, 0)
	for part := range strings.SplitSeq(c.AllowedDepartments, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// 解析拒绝的用户 ID 列表
func (c *DingtalkConfig) ParseBlockedUserIDs() []string {
	out := make([]string, 0)
	for part := range strings.SplitSeq(c.BlockedUserIDs, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// 命中拒绝名单时返回 error。
func (c *DingtalkConfig) CheckUserID(userID string, list []string) error {
	userID = strings.TrimSpace(userID)
	for _, v := range list {
		if strings.TrimSpace(v) == userID {
			return fmt.Errorf("%s 在拒绝的用户列表中", userID)
		}
	}
	return nil
}

// accessToken 响应
type dingtalkTokenResp struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	Code        string `json:"code"`
	Message     string `json:"message"`
}

// sns 用户信息响应
type dingtalkSnsResp struct {
	Code     string              `json:"code"`
	Message  string              `json:"message"`
	UserInfo dingtalkSnsUserInfo `json:"user_info"`
}

type dingtalkSnsUserInfo struct {
	OpenID  string `json:"openid"`
	UnionID string `json:"unionid"`
	Nick    string `json:"nick"`
}

// unionid 换 userid 响应
type dingtalkUserIDResp struct {
	UserId  string `json:"userid"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// 用户详情（部门）
type dingtalkUserDetailResp struct {
	DeptIdList []int64 `json:"dept_id_list"`
	Code       string  `json:"code"`
	Message    string  `json:"message"`
}

// 用授权 code 换取 accessToken（钉钉新版 OAuth2）
func (c *DingtalkConfig) GetAccessToken(code string) (string, error) {
	body := map[string]string{
		"clientId":     c.ClientID,
		"clientSecret": c.ClientSecret,
		"code":         code,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/accessToken", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var tr dingtalkTokenResp
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return "", fmt.Errorf("解析钉钉 accessToken 响应失败: %w (raw=%s)", err, string(respBody))
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("获取钉钉 accessToken 失败: code=%s msg=%s", tr.Code, tr.Message)
	}
	return tr.AccessToken, nil
}

// 用 OAuth code 解析出登录用户标识。
// 优先返回企业工号(userid)，若通讯录权限不足无法解析时回退使用 unionid，保证可登录。
func (c *DingtalkConfig) GetDingtalkUser(code string) (string, string, error) {
	accessToken, err := c.GetAccessToken(code)
	if err != nil {
		return "", "", err
	}

	// 用 accessToken + code 换取 sns 用户信息（openid/unionid）
	body := map[string]string{"tmp_auth_code": code}
	data, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.dingtalk.com/v1.0/oauth2/sns/getuserinfo_bycode", bytes.NewReader(data))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	var sr dingtalkSnsResp
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return "", "", fmt.Errorf("解析钉钉用户信息失败: %w (raw=%s)", err, string(respBody))
	}
	unionID := strings.TrimSpace(sr.UserInfo.UnionID)
	if unionID == "" {
		return "", "", fmt.Errorf("钉钉未返回有效用户标识: code=%s msg=%s", sr.Code, sr.Message)
	}

	// 尝试将 unionid 转换为企业工号(userid)，失败则回退 unionid
	if userID, err := c.unionIDToUserID(accessToken, unionID); err == nil && userID != "" {
		return userID, accessToken, nil
	}
	return unionID, accessToken, nil
}

// 通过通讯录接口将 unionid 转换为用户工号
func (c *DingtalkConfig) unionIDToUserID(accessToken, unionID string) (string, error) {
	body := map[string]string{"unionid": unionID}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.dingtalk.com/v1.0/contact/users/by_unionid", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var ur dingtalkUserIDResp
	if err := json.Unmarshal(respBody, &ur); err != nil {
		return "", fmt.Errorf("解析钉钉 userid 响应失败: %w (raw=%s)", err, string(respBody))
	}
	if ur.UserId == "" {
		return "", fmt.Errorf("钉钉未返回 userid: code=%s msg=%s", ur.Code, ur.Message)
	}
	return ur.UserId, nil
}

// 校验用户是否在某允许部门内（通过通讯录接口查询用户部门）。
// 配置为空部门列表时直接放行；通讯录查询失败时返回 true（避免权限不足阻断登录）。
func (c *DingtalkConfig) CheckUserDepartment(accessToken, userID string, allowed []string) (bool, error) {
	if len(allowed) == 0 {
		return true, nil
	}
	req, err := http.NewRequest(http.MethodGet, "https://api.dingtalk.com/v1.0/contact/users/"+userID, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-acs-dingtalk-access-token", accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return true, nil
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return true, nil
	}
	var dr dingtalkUserDetailResp
	if err := json.Unmarshal(respBody, &dr); err != nil {
		return true, nil
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, d := range allowed {
		allowedSet[strings.TrimSpace(d)] = true
	}
	for _, d := range dr.DeptIdList {
		if allowedSet[fmt.Sprintf("%d", d)] {
			return true, nil
		}
	}
	return false, nil
}

// 获取通讯录访问令牌（用于用户同步）。
// 钉钉企业内部应用使用 appkey/appsecret 换取。
func (c *DingtalkConfig) GetContactToken() (string, error) {
	url := fmt.Sprintf("https://oapi.dingtalk.com/gettoken?appkey=%s&appsecret=%s", c.ClientID, c.ClientSecret)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
	}
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return "", fmt.Errorf("解析钉钉通讯录令牌失败: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("获取钉钉通讯录令牌失败: %s", tr.ErrMsg)
	}
	return tr.AccessToken, nil
}

// 钉钉部门成员项（导出，供 dbdata 同步使用）
type DingtalkDeptUser struct {
	UserId string `json:"userid"`
	Name   string `json:"name"`
}

// 拉取钉钉部门成员（通讯录接口）
func (c *DingtalkConfig) GetDepartmentUsers(contactToken string, deptID string) ([]DingtalkDeptUser, error) {
	var (
		result  []DingtalkDeptUser
		cursor  int64
		hasMore = true
		client  = &http.Client{Timeout: 15 * time.Second}
	)
	for hasMore {
		url := fmt.Sprintf("https://oapi.dingtalk.com/user/list?access_token=%s&department_id=%s&cursor=%d&size=100",
			contactToken, deptID, cursor)
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		var dr struct {
			ErrCode  int                `json:"errcode"`
			ErrMsg   string             `json:"errmsg"`
			UserList []DingtalkDeptUser `json:"userlist"`
			HasMore  bool               `json:"hasMore"`
		}
		if err := json.Unmarshal(respBody, &dr); err != nil {
			return nil, fmt.Errorf("解析钉钉部门成员失败: %w", err)
		}
		if dr.ErrCode != 0 {
			return nil, fmt.Errorf("拉取钉钉部门成员失败: %s", dr.ErrMsg)
		}
		result = append(result, dr.UserList...)
		hasMore = dr.HasMore
		cursor += 100
	}
	return result, nil
}
