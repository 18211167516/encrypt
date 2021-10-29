package encrypt

import (
	"crypto/aes"
)

// 输入k的长度必须为16, 24或者32   iv 为 16

// =================== CBC ======================
func AesEncryptCBC(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if err := vaildIv(16, iv); err != nil {
		return nil, err
	}
	return encryptCBC(block, origData, iv, padding), nil
}
func AesDecryptCBC(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key) // 分组秘钥
	if err != nil {
		return nil, err
	}
	if err := vaildIv(16, iv); err != nil {
		return nil, err
	}
	return decryptCBC(block, encrypted, iv, padding), nil
}

// =================== ECB ======================
func AesEncryptECB(origData []byte, key []byte, padding string) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return encryptECB(block, origData, padding), nil
}
func AesDecryptECB(encrypted []byte, key []byte, padding string) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return decryptECB(block, encrypted, padding), nil
}

// =================== CFB ======================

func AesEncryptCFB(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(16, iv); err != nil {
		return nil, err
	}
	return encryptCFB(block, origData, iv, padding), nil
}

func AesDecryptCFB(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(16, iv); err != nil {
		return nil, err
	}
	return decryptCFB(block, encrypted, iv, padding), nil
}
