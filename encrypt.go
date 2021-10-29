package encrypt

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var ErrNotFoundMode = errors.New("not found mode")
var ErrIvLength8 = errors.New("invalid iv size must 8 bytes")
var ErrIvLength16 = errors.New("invalid iv size must 16 bytes")

const (
	AES_CBC  = "AES_CBC"
	AES_ECB  = "AES_ECB"
	AES_CFB  = "AES_CFB"
	DES_CBC  = "DES_CBC"
	DES_ECB  = "DES_ECB"
	DES_CFB  = "DES_CFB"
	DES3_CBC = "DES3_CBC"
	DES3_ECB = "DES3_ECB"
	DES3_CFB = "DES3_CFB"
)

type Encrypt struct {
	Mode    string
	Key, Iv []byte
	Padding string
}

//实例化加密
func NewEncrypt(mode string, key, iv []byte, padding string) *Encrypt {
	return &Encrypt{
		Mode:    mode,
		Key:     key,
		Iv:      iv,
		Padding: padding,
	}
}

//################ Encrypt ##################

//加密生成base64格式的字符串
func (en *Encrypt) EncryptBase64(origData []byte) string {
	encrypted, _ := en.Encrypt(origData)
	return base64.StdEncoding.EncodeToString(encrypted)
}

//加密生成hex格式的字符串
func (en *Encrypt) EncryptHex(origData []byte) string {
	encrypted, _ := en.Encrypt(origData)
	return hex.EncodeToString(encrypted)
}

func (en *Encrypt) Encrypt(origData []byte) (encrypted []byte, err error) {
	switch en.Mode {
	case AES_CBC:
		return AesEncryptCBC(origData, en.Key, en.Iv, en.Padding)
	case AES_ECB:
		return AesEncryptECB(origData, en.Key, en.Padding)
	case AES_CFB:
		return AesEncryptCFB(origData, en.Key, en.Iv, en.Padding)
	case DES_CBC:
		return DesEncryptCBC(origData, en.Key, en.Iv, en.Padding)
	case DES_ECB:
		return DesEncryptECB(origData, en.Key, en.Padding)
	case DES_CFB:
		return DesEncryptCFB(origData, en.Key, en.Iv, en.Padding)
	case DES3_CBC:
		return TripleDesEncryptCBC(origData, en.Key, en.Iv, en.Padding)
	case DES3_ECB:
		return TripleDesEncryptECB(origData, en.Key, en.Padding)
	case DES3_CFB:
		return TripleDesEncryptCFB(origData, en.Key, en.Iv, en.Padding)
	}

	return nil, ErrNotFoundMode
}

//################ Decrypt ##################
func (en *Encrypt) Decrypt(encrypted []byte) (decrypted []byte, err error) {
	switch en.Mode {
	case AES_CBC:
		return AesDecryptCBC(encrypted, en.Key, en.Iv, en.Padding)
	case AES_ECB:
		return AesDecryptECB(encrypted, en.Key, en.Padding)
	case AES_CFB:
		return AesDecryptCFB(encrypted, en.Key, en.Iv, en.Padding)
	case DES_CBC:
		return DesDecryptCBC(encrypted, en.Key, en.Iv, en.Padding)
	case DES_ECB:
		return DesDecryptECB(encrypted, en.Key, en.Padding)
	case DES_CFB:
		return DesDecryptCFB(encrypted, en.Key, en.Iv, en.Padding)
	case DES3_CBC:
		return TripleDesDecryptCBC(encrypted, en.Key, en.Iv, en.Padding)
	case DES3_ECB:
		return TripleDesDecryptECB(encrypted, en.Key, en.Padding)
	case DES3_CFB:
		return TripleDesDecryptCFB(encrypted, en.Key, en.Iv, en.Padding)
	}

	return nil, ErrNotFoundMode
}

//传入base64格式字符串解密
func (en *Encrypt) Base64Decrypt(encrypted string) (decrypted []byte, err error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	return en.Decrypt(encryptedBytes)
}

//传入hex格式解密
func (en *Encrypt) HexDecrypt(encrypted string) (decrypted []byte, err error) {
	encryptedBytes, err := hex.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	return en.Decrypt(encryptedBytes)
}

//验证iv长度
func vaildIv(length int, iv []byte) error {
	if length != len(iv) {
		if length == 8 {
			return ErrIvLength8
		}
		return ErrIvLength16
	}
	return nil
}

func encryptCBC(block cipher.Block, origData, iv []byte, padding string) (encrypted []byte) {
	blockSize := block.BlockSize()
	origData = Padding(padding, origData, blockSize) // 补全码
	blockMode := cipher.NewCBCEncrypter(block, iv)   // 加密模式
	encrypted = make([]byte, len(origData))          // 创建数组
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted
}

func decryptCBC(block cipher.Block, encrypted, iv []byte, padding string) (decrypted []byte) {
	blockMode := cipher.NewCBCDecrypter(block, iv) // 加密模式
	decrypted = make([]byte, len(encrypted))       // 创建数组
	blockMode.CryptBlocks(decrypted, encrypted)    // 解密
	decrypted = UnPadding(padding, decrypted)      // 去除补全码
	return decrypted
}

func encryptECB(block cipher.Block, origData []byte, padding string) (encrypted []byte) {
	origData = Padding(padding, origData, block.BlockSize())

	tmpData := make([]byte, block.BlockSize())

	for index := 0; index < len(origData); index += block.BlockSize() {
		block.Encrypt(tmpData, origData[index:index+block.BlockSize()])
		encrypted = append(encrypted, tmpData...)
	}
	return encrypted
}

func decryptECB(block cipher.Block, encrypted []byte, padding string) (decrypted []byte) {
	tmpData := make([]byte, block.BlockSize())
	for index := 0; index < len(encrypted); index += block.BlockSize() {
		block.Decrypt(tmpData, encrypted[index:index+block.BlockSize()])
		decrypted = append(decrypted, tmpData...)
	}

	return UnPadding(padding, decrypted)
}

func encryptCFB(block cipher.Block, origData, iv []byte, padding string) (encrypted []byte) {
	blockSize := block.BlockSize()
	origData = Padding(padding, origData, blockSize)
	encrypted = make([]byte, len(origData))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted, origData)
	return encrypted
}

func decryptCFB(block cipher.Block, encrypted, iv []byte, padding string) (decrypted []byte) {
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	decrypted = UnPadding(padding, encrypted)
	return decrypted
}
