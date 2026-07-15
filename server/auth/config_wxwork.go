// 企业微信 Provider 配置类型及 API 调用

package auth

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

type WXWorkConfig struct {
	CorpID             string `json:"corp_id"`
	AgentID            string `json:"agent_id"`
	Secret             string `json:"secret"`
	UseDefaultBrowser  bool   `json:"use_default_browser"`
	AllowedDepartments string `json:"allowed_departments"`
}

func (c *WXWorkConfig) ValidateConfig() error {
	if c.CorpID == "" {
		return fmt.Errorf("企业 ID 不能为空")
	}
	if c.AgentID == "" {
		return fmt.Errorf("应用 ID 不能为空")
	}
	if c.Secret == "" {
		return fmt.Errorf("应用 Secret 不能为空")
	}
	if c.AllowedDepartments != "" {
		parts := strings.Split(c.AllowedDepartments, ",")
		for _, part := range parts {
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

// 解析允许的部门列表为整数数组
func (c *WXWorkConfig) ParseDepartments() []int {
	if c.AllowedDepartments == "" {
		return nil
	}
	var depts []int
	parts := strings.Split(c.AllowedDepartments, ",")
	for _, part := range parts {
		if id, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && id > 0 {
			depts = append(depts, id)
		}
	}
	return depts
}

type WXWorkTokenResponse struct {
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type WXWorkUserResponse struct {
	ErrCode    int    `json:"errcode"`
	ErrMsg     string `json:"errmsg"`
	UserID     string `json:"userid"`
	Name       string `json:"name"`
	Department []int  `json:"department"`
}

// 获取企业微信 access_token
func (c *WXWorkConfig) GetAccessToken() (string, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s", c.CorpID, c.Secret)

	tokenResp := &WXWorkTokenResponse{}
	if err := fetchJSON("获取企微access_token", "GET", url, nil, nil, tokenResp, 0); err != nil {
		return "", err
	}
	if tokenResp.ErrCode != 0 {
		return "", fmt.Errorf("获取 access_token 失败: %s", tokenResp.ErrMsg)
	}
	return tokenResp.AccessToken, nil
}

// 通过 code 获取企微用户 ID
func (c *WXWorkConfig) GetWeworkUser(code string) (string, error) {
	accessToken, err := c.GetAccessToken()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo?access_token=%s&code=%s", accessToken, code)
	userInfo := &WXWorkUserResponse{}
	if err := fetchJSON("获取企微用户信息", "GET", url, nil, nil, userInfo, 0); err != nil {
		return "", err
	}
	if userInfo.ErrCode != 0 {
		return "", fmt.Errorf("获取用户信息失败: %s", userInfo.ErrMsg)
	}
	return userInfo.UserID, nil
}

// 检查用户是否属于允许的部门
func (c *WXWorkConfig) CheckUserDepartment(accessToken, userID string, allowedDepts []int) (bool, error) {
	url := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s", accessToken, userID)
	userInfo := &WXWorkUserResponse{}
	if err := fetchJSON("获取企微用户详细信息", "GET", url, nil, nil, userInfo, 0); err != nil {
		return false, err
	}
	if userInfo.ErrCode != 0 {
		return false, fmt.Errorf("获取用户详细信息失败: %s", userInfo.ErrMsg)
	}

	for _, userDept := range userInfo.Department {
		if slices.Contains(allowedDepts, userDept) {
			return true, nil
		}
	}
	return false, nil
}

type WXWorkDepartmentUser struct {
	UserID     string `json:"userid"`
	Name       string `json:"name"`
	Department []int  `json:"department"`
}

type WXWorkUserListResponse struct {
	ErrCode  int                    `json:"errcode"`
	ErrMsg   string                 `json:"errmsg"`
	UserList []WXWorkDepartmentUser `json:"userlist"`
}

// 获取部门成员列表（含子部门）
func (c *WXWorkConfig) GetDepartmentUsers(accessToken string, departmentID int) ([]WXWorkDepartmentUser, error) {
	url := fmt.Sprintf(
		"https://qyapi.weixin.qq.com/cgi-bin/user/simplelist?access_token=%s&department_id=%d&fetch_child=1",
		accessToken, departmentID,
	)

	listResp := &WXWorkUserListResponse{}
	if err := fetchJSON("获取企微部门成员", "GET", url, nil, nil, listResp, 30*time.Second); err != nil {
		return nil, err
	}
	if listResp.ErrCode != 0 {
		return nil, fmt.Errorf("获取部门成员列表失败: %s", listResp.ErrMsg)
	}
	return listResp.UserList, nil
}

// 生成企业微信 OAuth2 授权 URL
func (c *WXWorkConfig) GetAuthURL(redirectURI, state string) string {
	return fmt.Sprintf(
		"https://login.work.weixin.qq.com/wwlogin/sso/login?login_type=CorpApp&appid=%s&agentid=%s&redirect_uri=%s&state=%s",
		c.CorpID, c.AgentID, redirectURI, state,
	)
}
