package admin

import (
	"errors"
	"fmt"
	"maps"

	"github.com/golang-jwt/jwt/v4"
	"github.com/wsczx/remlink/base"
)

func SetJwtData(data map[string]any, expiresAt int64) (string, error) {
	jwtData := jwt.MapClaims{"exp": expiresAt}
	maps.Copy(jwtData, data)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtData)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(base.GetCfg().JwtSecret))
	return tokenString, err
}

func GetJwtData(jwtToken string) (map[string]any, error) {
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (any, error) {
		// 签发侧固定使用 HS256，验证侧强制只接受 HS256
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
		}
		return []byte(base.GetCfg().JwtSecret), nil
	})

	if err != nil || !token.Valid {
		if err == nil {
			err = errors.New("JWT token 无效")
		}
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("data is parse err")
	}

	return claims, nil
}
