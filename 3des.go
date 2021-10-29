package encrypt

import (
	"crypto/des"
)

// k长度必须为24 iv长度必须为8

// =================== CBC ======================
func TripleDesEncryptCBC(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return encryptCBC(block, origData, iv, padding), nil
}

func TripleDesDecryptCBC(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key) // 分组秘钥
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return decryptCBC(block, encrypted, iv, padding), nil
}

// =================== ECB ======================
func TripleDesEncryptECB(origData []byte, key []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return encryptECB(block, origData, padding), nil
}
func TripleDesDecryptECB(encrypted []byte, key []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	return decryptECB(block, encrypted, padding), nil
}

// =================== CFB ======================
func TripleDesEncryptCFB(origData, key, iv []byte, padding string) (encrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return encryptCFB(block, origData, iv, padding), nil
}

func TripleDesDecryptCFB(encrypted, key, iv []byte, padding string) (decrypted []byte, err error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if err := vaildIv(8, iv); err != nil {
		return nil, err
	}
	return decryptCFB(block, encrypted, iv, padding), nil
}
