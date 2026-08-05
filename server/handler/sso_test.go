package handler

import "testing"

func TestSSOCallbackPathsMatchRoutes(t *testing.T) {
	expected := map[string]string{
		"wxwork":   "WXAuth",
		"feishu":   "FeishuAuth",
		"dingtalk": "DingtalkAuth",
	}
	for ssoType, want := range expected {
		p, ok := ssoProviders[ssoType]
		if !ok {
			t.Fatalf("ssoProviders 缺少类型 %q", ssoType)
		}
		if p.callbackPath != want {
			t.Errorf("ssoType=%q callbackPath=%q，期望 %q（须与 server.go 路由表一致）",
				ssoType, p.callbackPath, want)
		}
	}
}
