package encrypt

import (
	"crypto/des"
)

// k长度必须为8 iv长度必须为8

// =================== CBC ======================
func DesEncryptCBC(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return encryptCBC(block, origData, iv, padding), nil
}

func DesDecryptCBC(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewCipher(key) // 分组秘钥
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return decryptCBC(block, encrypted, iv, padding), nil
}

// =================== ECB ======================
func DesEncryptECB(origData []byte, key []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return encryptECB(block, origData, padding), nil
}
func DesDecryptECB(encrypted []byte, key []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return decryptECB(block, encrypted, padding), nil
}

// =================== CFB ======================
func DesEncryptCFB(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return encryptCFB(block, origData, iv, padding), nil
}

func DesDecryptCFB(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return decryptCFB(block, encrypted, iv, padding), nil
}
