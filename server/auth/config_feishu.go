// 飞书 Provider 配置类型及 API 调用

package auth

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

type FeishuConfig struct {
	AppID              string `json:"app_id"`
	AppSecret          string `json:"app_secret"`
	UseDefaultBrowser  bool   `json:"use_default_browser"`
	AllowedDepartments string `json:"allowed_departments"`
	BlockedUserIDs     string `json:"blocked_userids"` // 拒绝的用户 ID 列表，逗号分隔
	SyncUsers          bool   `json:"sync_users"`       // 定时自动同步用户
}

func (c *FeishuConfig) ValidateConfig() error {
	if c.AppID == "" {
		return fmt.Errorf("应用 ID 不能为空")
	}
	if c.AppSecret == "" {
		return fmt.Errorf("应用 Secret 不能为空")
	}
	if c.AllowedDepartments != "" {
		parts := strings.SplitSeq(c.AllowedDepartments, ",")
		for part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				if _, err := strconv.Atoi(part); err != nil {
					return fmt.Errorf("部门 ID 必须为数字: %s", part)
				}
			}
		}
	}
	return nil
}

// 解析允许的部门列表
func (c *FeishuConfig) ParseDepartments() []string {
	if c.AllowedDepartments == "" {
		return nil
	}
	var depts []string
	parts := strings.SplitSeq(c.AllowedDepartments, ",")
	for part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			depts = append(depts, part)
		}
	}
	return depts
}

// 解析拒绝的用户 ID 列表
func (c *FeishuConfig) ParseBlockedUserIDs() []string {
	if c.BlockedUserIDs == "" {
		return nil
	}
	var ids []string
	parts := strings.SplitSeq(c.BlockedUserIDs, ",")
	for part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			ids = append(ids, part)
		}
	}
	return ids
}

// CheckUserID 校验用户是否在拒绝名单中
func (c *FeishuConfig) CheckUserID(userID string, blockedIDs []string) error {
	if slices.Contains(blockedIDs, userID) {
		return fmt.Errorf("%s 在拒绝的用户列表中", userID)
	}
	return nil
}

type FeishuTokenResponse struct {
	Code              int    `json:"code"`
	Msg               string `json:"msg"`
	AppAccessToken    string `json:"app_access_token"`
	TenantAccessToken string `json:"tenant_access_token"`
	Expire            int    `json:"expire"`
}

type FeishuUserResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		UserID        string   `json:"user_id"`
		OpenID        string   `json:"open_id"`
		UnionID       string   `json:"union_id"`
		Name          string   `json:"name"`
		Mobile        string   `json:"mobile"`
		DepartmentIDs []string `json:"department_ids"`
	} `json:"data"`
}

// 获取飞书 app_access_token
func (c *FeishuConfig) GetAppAccessToken() (string, error) {
	type reqBody struct {
		AppID     string `json:"app_id"`
		AppSecret string `json:"app_secret"`
	}
	b, err := json.Marshal(reqBody{AppID: c.AppID, AppSecret: c.AppSecret})
	if err != nil {
		return "", fmt.Errorf("序列化请求体失败: %w", err)
	}

	url := "https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal"
	tokenResp := &FeishuTokenResponse{}
	if err := fetchJSON("获取飞书app_access_token", "POST", url, strings.NewReader(string(b)), nil, tokenResp, 0); err != nil {
		return "", err
	}
	if tokenResp.Code != 0 {
		return "", fmt.Errorf("获取 app_access_token 失败: %s", tokenResp.Msg)
	}
	return tokenResp.AppAccessToken, nil
}

// 通过 code 获取飞书用户信息
func (c *FeishuConfig) GetFeishuUser(code string) (string, error) {
	appAccessToken, err := c.GetAppAccessToken()
	if err != nil {
		return "", err
	}

	url := "https://open.feishu.cn/open-apis/authen/v1/user_info?code=" + code
	userInfo := &FeishuUserResponse{}
	headers := map[string]string{"Authorization": "Bearer " + appAccessToken}
	if err := fetchJSON("获取飞书用户信息", "GET", url, nil, headers, userInfo, 0); err != nil {
		return "", err
	}
	if userInfo.Code != 0 {
		return "", fmt.Errorf("获取用户信息失败: %s", userInfo.Msg)
	}
	return userInfo.Data.UserID, nil
}

// 获取飞书用户详细信息（含部门）
func (c *FeishuConfig) GetFeishuUserDetail(appAccessToken, userID string) (*FeishuUserResponse, error) {
	url := fmt.Sprintf("https://open.feishu.cn/open-apis/contact/v3/users/%s", userID)
	userInfo := &FeishuUserResponse{}
	headers := map[string]string{"Authorization": "Bearer " + appAccessToken}
	if err := fetchJSON("获取飞书用户详细信息", "GET", url, nil, headers, userInfo, 0); err != nil {
		return nil, err
	}
	if userInfo.Code != 0 {
		return nil, fmt.Errorf("获取用户详细信息失败: %s", userInfo.Msg)
	}
	return userInfo, nil
}

// 检查用户是否属于允许的部门
func (c *FeishuConfig) CheckUserDepartment(appAccessToken, userID string, allowedDepts []string) (bool, error) {
	userInfo, err := c.GetFeishuUserDetail(appAccessToken, userID)
	if err != nil {
		return false, err
	}
	for _, userDept := range userInfo.Data.DepartmentIDs {
		if slices.Contains(allowedDepts, userDept) {
			return true, nil
		}
	}
	return false, nil
}

type FeishuDeptUserListResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Items     []FeishuDeptUserItem `json:"items"`
		HasMore   bool                 `json:"has_more"`
		PageToken string               `json:"page_token"`
	} `json:"data"`
}

type FeishuDeptUserItem struct {
	UserID        string   `json:"user_id"`
	OpenID        string   `json:"open_id"`
	Name          string   `json:"name"`
	Mobile        string   `json:"mobile"`
	DepartmentIDs []string `json:"department_ids"`
}

// 获取飞书部门成员列表
func (c *FeishuConfig) GetDepartmentUsers(appAccessToken, departmentID string) ([]FeishuDeptUserItem, error) {
	var allUsers []FeishuDeptUserItem
	pageToken := ""
	headers := map[string]string{"Authorization": "Bearer " + appAccessToken}

	for {
		url := fmt.Sprintf(
			"https://open.feishu.cn/open-apis/contact/v3/users/find_by_department?department_id=%s&page_size=100",
			departmentID,
		)
		if pageToken != "" {
			url += "&page_token=" + pageToken
		}

		listResp := &FeishuDeptUserListResponse{}
		if err := fetchJSON("获取飞书部门成员", "GET", url, nil, headers, listResp, 30*time.Second); err != nil {
			return nil, err
		}
		if listResp.Code != 0 {
			return nil, fmt.Errorf("获取部门成员列表失败: %s", listResp.Msg)
		}

		allUsers = append(allUsers, listResp.Data.Items...)
		if !listResp.Data.HasMore {
			break
		}
		pageToken = listResp.Data.PageToken
	}

	return allUsers, nil
}

// 生成飞书 OAuth2 授权 URL
func (c *FeishuConfig) GetAuthURL(redirectURI, state string) string {
	return fmt.Sprintf(
		"https://open.feishu.cn/open-apis/authen/v1/authorize?app_id=%s&redirect_uri=%s&state=%s",
		c.AppID, redirectURI, state,
	)
}
