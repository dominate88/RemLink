package security

import "testing"

// 固定测试密钥（32 字节），用于不依赖磁盘密钥文件的注入式单测。
var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestNewCipherEncryptDecryptRoundtrip(t *testing.T) {
	c, err := NewCipher(testKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	const plain = "hello-remlink-加密"
	enc, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == plain {
		t.Fatal("Encrypt 未改变明文")
	}
	if !IsEncrypted(enc) {
		t.Fatalf("密文缺前缀: %s", enc)
	}
	dec, err := c.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != plain {
		t.Fatalf("往返不一致: got %q want %q", dec, plain)
	}
}

func TestNewCipherRejectsWrongKeySize(t *testing.T) {
	if _, err := NewCipher([]byte("short")); err == nil {
		t.Fatal("短密钥应报错")
	}
	if _, err := NewCipher(make([]byte, 16)); err == nil {
		t.Fatal("16 字节密钥应报错（须 32）")
	}
	// 32 字节正常
	if _, err := NewCipher(testKey); err != nil {
		t.Fatalf("32 字节密钥应成功: %v", err)
	}
}

// NewCipher 与全局密钥包级函数应基于同一密钥，密文可互相解密。
// 注意：AES-GCM 每次加密使用随机 nonce，故密文字节本身不要求相同（这是安全特性）。
func TestNewCipherMatchesGlobalKey(t *testing.T) {
	enableForTest(t) // 全局 key 已加载

	key := getKeyLocked()
	if key == nil {
		t.Fatal("全局密钥未启用")
	}

	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	const plain = "一致性校验数据"
	encPkg, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("包级 Encrypt: %v", err)
	}
	encCipher, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Cipher.Encrypt: %v", err)
	}
	// 二者密文应可互相解密（验证同一密钥、同一算法）。
	if dec, err := Decrypt(encCipher); err != nil || dec != plain {
		t.Fatalf("包级 Decrypt 解 Cipher 密文失败: %v %q", err, dec)
	}
	if dec, err := c.Decrypt(encPkg); err != nil || dec != plain {
		t.Fatalf("Cipher.Decrypt 解包级密文失败: %v %q", err, dec)
	}
}

func TestNewCipherNonPrefixPassthrough(t *testing.T) {
	c, _ := NewCipher(testKey)
	if v, _ := c.Decrypt("明文无前缀"); v != "明文无前缀" {
		t.Fatalf("非前缀应透传: got %q", v)
	}
}
