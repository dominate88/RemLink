package dbdata

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/wsczx/remlink/base"
	"github.com/wsczx/remlink/pkg/security"
)

var (
	// nameToCertificate mutex
	ntcMux            sync.RWMutex
	nameToCertificate = make(map[string]*tls.Certificate)
	tempCert          *tls.Certificate
	tempCertMux       sync.Mutex
)

func init() {
	c, err := selfsign.GenerateSelfSignedWithDNS("localhost")
	if err != nil {
		base.Error("生成默认自签名证书失败:", err)
		return
	}
	tempCert = &c
}

type SettingLetsEncrypt struct {
	Domain      string `json:"domain"`
	Legomail    string `json:"legomail"`
	Name        string `json:"name"`
	Renew       bool   `json:"renew"`
	DNSResolver string `json:"dnsResolver"` // 自定义 DNS 服务器，多个用逗号分隔，留空使用默认
	DNSProvider
}

type DNSProvider struct {
	AliYun struct {
		APIKey    string                   `json:"apiKey"`
		SecretKey security.EncryptedString `json:"secretKey"`
	} `json:"aliyun"`

	TXCloud struct {
		SecretID  string                   `json:"secretId"`
		SecretKey security.EncryptedString `json:"secretKey"`
	} `json:"txcloud"`
	CfCloud struct {
		AuthToken security.EncryptedString `json:"authToken"`
	} `json:"cfcloud"`
}
type LegoUserData struct {
	Email        string                   `json:"email"`
	Registration *registration.Resource   `json:"registration"`
	Key          security.EncryptedString `json:"key"`
}
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	Key          *ecdsa.PrivateKey
}

type LeGoClient struct {
	mutex  sync.Mutex
	Client *lego.Client
	Cert   *certificate.Resource
	LegoUserData
}

func GetDNSProvider(l *SettingLetsEncrypt) (Provider challenge.Provider, err error) {
	switch l.Name {
	case "aliyun":
		if Provider, err = alidns.NewDNSProviderConfig(&alidns.Config{APIKey: l.DNSProvider.AliYun.APIKey, SecretKey: string(l.DNSProvider.AliYun.SecretKey), PropagationTimeout: 60 * time.Second, PollingInterval: 2 * time.Second, TTL: 600}); err != nil {
			return
		}
	case "txcloud":
		if Provider, err = tencentcloud.NewDNSProviderConfig(&tencentcloud.Config{SecretID: l.DNSProvider.TXCloud.SecretID, SecretKey: string(l.DNSProvider.TXCloud.SecretKey), PropagationTimeout: 60 * time.Second, PollingInterval: 2 * time.Second, TTL: 600}); err != nil {
			return
		}
	case "cfcloud":
		if Provider, err = cloudflare.NewDNSProviderConfig(&cloudflare.Config{AuthToken: string(l.DNSProvider.CfCloud.AuthToken), PropagationTimeout: 60 * time.Second, PollingInterval: 2 * time.Second, TTL: 600}); err != nil {
			return
		}
	default:
		return nil, fmt.Errorf("不支持的 DNS 提供商: %s", l.Name)
	}
	return
}
func (u *LegoUser) GetEmail() string {
	return u.Email
}
func (u LegoUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (l *LegoUserData) SaveUserData(u *LegoUser) error {
	key, err := x509.MarshalECPrivateKey(u.Key)
	if err != nil {
		return err
	}
	l.Email = u.Email
	l.Registration = u.Registration
	l.Key = security.EncryptedString(base64.StdEncoding.EncodeToString(key))
	if err := SettingSave(l); err != nil {
		return err
	}
	return nil
}

func (l *LegoUserData) GetUserData(d *SettingLetsEncrypt) (*LegoUser, error) {
	if err := SettingGet(l); err != nil {
		if CheckErrNotFound(err) {
			// 记录不存在时创建默认空记录，保证后续 SaveUserData 可更新
			if saveErr := SettingSave(l); saveErr != nil {
				base.Warn("创建默认 LegoUser 配置失败:", saveErr)
			}
		} else {
			return nil, err
		}
	}
	if l.Email != "" {
		der, err := base64.StdEncoding.DecodeString(string(l.Key))
		if err != nil {
			return nil, fmt.Errorf("LegoUserData.Key base64 解码失败（数据可能损坏）: %w", err)
		}
		key, err := x509.ParseECPrivateKey(der)
		if err != nil {
			return nil, fmt.Errorf("LegoUserData.Key 解析失败: %w", err)
		}
		return &LegoUser{
			Email:        l.Email,
			Registration: l.Registration,
			Key:          key,
		}, nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &LegoUser{
		Email: d.Legomail,
		Key:   privateKey,
	}, nil
}

// 检查证书过期时间，若距过期不足 7 天则自动续期
func CheckAndRenewCert() {
	_, certtime, err := ParseCert()
	if err != nil {
		base.Error(err)
		return
	}
	if certtime.AddDate(0, 0, -7).Before(time.Now()) {
		config := &SettingLetsEncrypt{}
		if err := SettingGet(config); err != nil {
			base.Error(err)
			return
		}
		if config.Renew {
			client := &LeGoClient{}
			if err := client.NewClient(config); err != nil {
				base.Error(err)
				return
			}
			if err := client.RenewCert(); err != nil {
				base.Error(err)
				return
			}
			base.Info("证书续期成功")
		}
	} else {
		base.Info(fmt.Sprintf("证书过期时间：%s", certtime.Local().Format("2006-1-2 15:04:05")))
	}
}

func (c *LeGoClient) NewClient(l *SettingLetsEncrypt) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	legouser, err := c.GetUserData(l)
	if err != nil {
		return err
	}
	config := lego.NewConfig(legouser)
	config.CADirURL = lego.LEDirectoryProduction
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}
	Provider, err := GetDNSProvider(l)
	if err != nil {
		return err
	}
	if l.DNSResolver != "" {
		servers := strings.Split(l.DNSResolver, ",")
		for i := range servers {
			servers[i] = strings.TrimSpace(servers[i])
		}
		if err := client.Challenge.SetDNS01Provider(Provider, dns01.AddRecursiveNameservers(servers)); err != nil {
			return err
		}
	} else {
		if err := client.Challenge.SetDNS01Provider(Provider, dns01.AddRecursiveNameservers([]string{"223.6.6.6", "223.5.5.5"})); err != nil {
			return err
		}
	}
	if legouser.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return err
		}
		legouser.Registration = reg
		c.SaveUserData(legouser)
	}
	c.Client = client
	return nil
}

func (c *LeGoClient) GetCert(domain string) error {
	// 申请证书
	certificates, err := c.Client.Certificate.Obtain(
		certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		})
	if err != nil {
		return err
	}
	c.Cert = certificates
	// 保存证书
	if err := c.SaveCert(); err != nil {
		return err
	}
	return nil
}

func (c *LeGoClient) RenewCert() error {
	tlsData := SettingTLSCert{}
	if err := SettingGet(&tlsData); err != nil {
		return err
	}
	cert := tlsData.CertContent
	key := string(tlsData.CertKeyContent)
	if cert == "" || key == "" {
		return fmt.Errorf("证书内容为空，无法续期")
	}
	// 续期证书
	renewcert, err := c.Client.Certificate.Renew(certificate.Resource{
		Certificate: []byte(cert),
		PrivateKey:  []byte(key),
	}, true, false, "")
	if err != nil {
		return err
	}
	c.Cert = renewcert
	// 保存更新证书
	if err := c.SaveCert(); err != nil {
		return err
	}
	return nil
}

func (c *LeGoClient) SaveCert() error {
	// 证书 PEM 大字段独立存储
	if err := SettingSaveTLSCert(string(c.Cert.Certificate), string(c.Cert.PrivateKey)); err != nil {
		return fmt.Errorf("保存TLS证书失败: %w", err)
	}
	if tlscert, _, err := ParseCert(); err != nil {
		return err
	} else {
		LoadCertificate(tlscert)
	}
	return nil
}

func ParseCert() (*tls.Certificate, *time.Time, error) {
	cert, err := tryLoadCert()
	if err != nil {
		// 证书加载失败（文件不存在 或 key 不匹配），重新生成自签名证书
		if e := PrivateCert(); e != nil {
			return nil, nil, e
		}
		cert, err = tryLoadCert()
		if err != nil {
			return nil, nil, fmt.Errorf("证书重新生成后仍加载失败: %w", err)
		}
	}
	parseCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	return cert, &parseCert.NotAfter, nil
}

func tryLoadCert() (*tls.Certificate, error) {
	tlsData := SettingTLSCert{}
	if err := SettingGet(&tlsData); err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair([]byte(tlsData.CertContent), []byte(string(tlsData.CertKeyContent)))
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func PrivateCert() error {
	// 创建一个RSA密钥对
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	pub := &priv.PublicKey

	// 生成一个自签名证书
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1658),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return err
	}

	// 编码为 PEM 并存入数据库
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	// 证书 PEM 独立存储
	if err := SettingSaveTLSCert(string(certPEM), string(keyPEM)); err != nil {
		return fmt.Errorf("保存证书到数据库失败: %w", err)
	}

	return nil
}

func getTempCertificate() (*tls.Certificate, error) {
	tempCertMux.Lock()
	defer tempCertMux.Unlock()
	if tempCert == nil {
		cert, err := selfsign.GenerateSelfSignedWithDNS("localhost")
		if err != nil {
			return nil, err
		}
		tempCert = &cert
	}
	return tempCert, nil
}

func GetCertificateBySNI(commonName string) (*tls.Certificate, error) {
	ntcMux.RLock()
	defer ntcMux.RUnlock()

	// Copy from tls.Config getCertificate()
	name := strings.ToLower(commonName)
	if cert, ok := nameToCertificate[name]; ok {
		return cert, nil
	}
	if len(name) > 0 {
		labels := strings.Split(name, ".")
		labels[0] = "*"
		wildcardName := strings.Join(labels, ".")
		if cert, ok := nameToCertificate[wildcardName]; ok {
			return cert, nil
		}
	}
	// TODO 默认证书 兼容不支持 SNI 的客户端
	if cert, ok := nameToCertificate["default"]; ok {
		return cert, nil
	}

	return getTempCertificate()
}

func LoadCertificate(cert *tls.Certificate) {
	buildNameToCertificate(cert)
}

// Copy from tls.Config BuildNameToCertificate()
func buildNameToCertificate(cert *tls.Certificate) {
	ntcMux.Lock()
	defer ntcMux.Unlock()

	// 清理旧映射，避免换证书后残留域名指向旧证书
	for k := range nameToCertificate {
		delete(nameToCertificate, k)
	}

	// 设置默认证书
	nameToCertificate["default"] = cert

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	startTime := x509Cert.NotBefore.String()
	expiredTime := x509Cert.NotAfter.String()
	if x509Cert.Subject.CommonName != "" && len(x509Cert.DNSNames) == 0 {
		commonName := x509Cert.Subject.CommonName
		base.Info("┏ Load Certificate: ", commonName)
		base.Info("┠╌╌ Start Time:     ", startTime)
		base.Info("┖╌╌ Expired Time:   ", expiredTime)
		nameToCertificate[commonName] = cert
	}
	for _, san := range x509Cert.DNSNames {
		base.Info("┏ Load Certificate: ", san)
		base.Info("┠╌╌ Start Time:     ", startTime)
		base.Info("┖╌╌ Expired Time:   ", expiredTime)
		nameToCertificate[san] = cert
	}
}
