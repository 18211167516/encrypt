package main

import (
	"fmt"

	"github.com/18211167516/encrypt"
)

func main() {
	origData := []byte("Hello")       // 待加密的数据
	key := []byte("1234567812345678") // 加密的密钥
	iv := []byte("1234567812345678")  //16位
	padding := encrypt.PKCS5_PADDING
	fmt.Println("原文：", string(origData))

	/* 	fmt.Println("------------------ CBC Struct模式 --------------------")
	   	aes := encrypt.NewEncrypt(encrypt.AES_CBC, key, iv, padding)
	   	encryp := aes.EncryptBase64(origData)
	   	encrypHex := aes.EncryptHex(origData)
	   	fmt.Println("密文(base64)：", encryp)
	   	fmt.Println("密文(hex)：", encrypHex)
	   	decryp, _ := aes.Base64Decrypt(encryp)
	   	decrypHex, _ := aes.HexDecrypt(encrypHex)
	   	fmt.Println("解密(base64)结果：", string(decryp))
	   	fmt.Println("解密(Hex)结果：", string(decrypHex))

	   	fmt.Println("------------------ ECB Struct模式模式 --------------------")
	   	aes = encrypt.NewEncrypt(encrypt.AES_ECB, key, iv, padding)
	   	encryp = aes.EncryptBase64(origData)
	   	encrypHex = aes.EncryptHex(origData)
	   	fmt.Println("密文(base64)：", encryp)
	   	fmt.Println("密文(hex)：", encrypHex)
	   	decryp, _ = aes.Base64Decrypt(encryp)
	   	decrypHex, _ = aes.HexDecrypt(encrypHex)
	   	fmt.Println("解密(base64)结果：", string(decryp))
	   	fmt.Println("解密(Hex)结果：", string(decrypHex))

	   	fmt.Println("------------------ CFB Struct模式模式 --------------------")
	   	aes = encrypt.NewEncrypt(encrypt.AES_CFB, key, iv, padding)
	   	encryp = aes.EncryptBase64(origData)
	   	encrypHex = aes.EncryptHex(origData)
	   	fmt.Println("密文(base64)：", encryp)
	   	fmt.Println("密文(hex)：", encrypHex)
	   	decryp, _ = aes.Base64Decrypt(encryp)
	   	decrypHex, _ = aes.HexDecrypt(encrypHex)
	   	fmt.Println("解密(base64)结果：", string(decryp))
	   	fmt.Println("解密(Hex)结果：", string(decrypHex)) */

	key = []byte("123456781234567812345678") // 加密的密钥
	iv = []byte("12345678")

	fmt.Println("------------------DES CBC Struct模式 --------------------")
	aes := encrypt.NewEncrypt(encrypt.DES3_CBC, key, iv, padding)
	encryp := aes.EncryptBase64(origData)
	encrypHex := aes.EncryptHex(origData)
	fmt.Println("密文(base64)：", encryp)
	fmt.Println("密文(hex)：", encrypHex)
	decryp, _ := aes.Base64Decrypt(encryp)
	decrypHex, _ := aes.HexDecrypt(encrypHex)
	fmt.Println("解密(base64)结果：", string(decryp))
	fmt.Println("解密(Hex)结果：", string(decrypHex))

	fmt.Println("------------------DES ECB Struct模式模式 --------------------")
	aes = encrypt.NewEncrypt(encrypt.DES3_ECB, key, iv, padding)
	encryp = aes.EncryptBase64(origData)
	encrypHex = aes.EncryptHex(origData)
	fmt.Println("密文(base64)：", encryp)
	fmt.Println("密文(hex)：", encrypHex)
	decryp, _ = aes.Base64Decrypt(encryp)
	decrypHex, _ = aes.HexDecrypt(encrypHex)
	fmt.Println("解密(base64)结果：", string(decryp))
	fmt.Println("解密(Hex)结果：", string(decrypHex))

	fmt.Println("------------------DES CFB Struct模式模式 --------------------")
	aes = encrypt.NewEncrypt(encrypt.DES3_CFB, key, iv, padding)
	encryp = aes.EncryptBase64(origData)
	encrypHex = aes.EncryptHex(origData)
	fmt.Println("密文(base64)：", encryp)
	fmt.Println("密文(hex)：", encrypHex)
	decryp, _ = aes.Base64Decrypt(encryp)
	decrypHex, _ = aes.HexDecrypt(encrypHex)
	fmt.Println("解密(base64)结果：", string(decryp))
	fmt.Println("解密(Hex)结果：", string(decrypHex))
}
