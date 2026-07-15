package dbdata

import (
	"encoding/json"
	"testing"

	"github.com/wsczx/remlink/pkg/security"
	"github.com/wsczx/remlink/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestGetGroupNames(t *testing.T) {
	ast := assert.New(t)

	preIpData(t)
	defer closeIpdata()

	err := SetProvider(&Provider{
		Name:   "test-radius",
		Type:   "radius",
		Status: 1,
		Config: security.EncryptedJSON[json.RawMessage]{Data: json.RawMessage(`{"addr":"192.168.8.12:1044","secret":"43214132"}`)},
	})
	ast.Nil(err)
	err = SetProvider(&Provider{
		Name:   "test-ldap",
		Type:   "ldap",
		Status: 1,
		Config: security.EncryptedJSON[json.RawMessage]{Data: json.RawMessage(`{"addr":"192.168.8.12:389","tls":true,"bind_name":"userfind@abc.com","bind_pwd":"afdbfdsafds","base_dn":"dc=abc,dc=com","object_class":"person","search_attr":"sAMAccountName","member_of":"cn=vpn,cn=user,dc=abc,dc=com"}`)},
	})
	ast.Nil(err)

	// 创建通用测试策略
	defaultPolicy := &Policy{
		Name:      "group-test-default",
		ClientDns: []ValData{{Val: "114.114.114.114"}},
		Status:    1,
	}
	err = SetPolicy(defaultPolicy)
	ast.Nil(err)
	pid := defaultPolicy.Id

	// 添加 group
	g1 := Group{Name: "g1", PolicyId: pid}
	err = SetGroup(&g1)
	ast.Nil(err)
	g2 := Group{Name: "g2", PolicyId: pid}
	err = SetGroup(&g2)
	ast.Nil(err)
	g3 := Group{Name: "g3", PolicyId: pid}
	err = SetGroup(&g3)
	ast.Nil(err)

	g4 := Group{Name: "g4", PolicyId: pid,
		AuthProfile: json.RawMessage(`{"step":[{"type":"radius","provider":"test-radius"}]}`)}
	err = SetGroup(&g4)
	ast.Nil(err)

	// g5: 含域名拆分，需新建策略
	p5 := &Policy{
		Name:             "group-test-g5",
		ClientDns:        []ValData{{Val: "114.114.114.114"}},
		RouteInclude:     []ValData{{Val: "10.0.0.0/8"}},
		DsIncludeDomains: "baidu.com,163.com",
		Status:           1,
	}
	err = SetPolicy(p5)
	ast.Nil(err)
	g5 := Group{Name: "g5", PolicyId: p5.Id}
	err = SetGroup(&g5)
	ast.Nil(err)

	// g6: 含排除域名
	p6 := &Policy{
		Name:             "group-test-g6",
		ClientDns:        []ValData{{Val: "114.114.114.114"}},
		DsExcludeDomains: "com.cn,qq.com",
		Status:           1,
	}
	err = SetPolicy(p6)
	ast.Nil(err)
	g6 := Group{Name: "g6", PolicyId: p6.Id}
	err = SetGroup(&g6)
	ast.Nil(err)

	g7 := Group{Name: "g7", PolicyId: pid,
		AuthProfile: json.RawMessage(`{"step":[{"type":"ldap","provider":"test-ldap"}]}`)}
	err = SetGroup(&g7)
	ast.Nil(err)

	// 判断所有数据
	gAll := []string{"g1", "g2", "g3", "g4", "g5", "g6", "g7"}
	gs := GetGroupNames()
	for _, v := range gs {
		ast.Equal(true, utils.InArrStr(gAll, v))
	}

	gni := GetGroupNamesIds()
	for _, v := range gni {
		ast.NotEqual(0, v.Id)
		ast.Equal(true, utils.InArrStr(gAll, v.Name))
	}
}
