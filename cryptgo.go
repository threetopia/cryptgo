package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func Encrypt(data []byte, secret string, ivByte []byte) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, ivByte)
	cipherText := make([]byte, len(data))
	cfb.XORKeyStream(cipherText, data)
	return bas64Encode(cipherText), nil
}

func Decrypt(encryptStr, secret string, ivByte []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	cipherText := base64Decode(encryptStr)
	cfb := cipher.NewCFBDecrypter(block, ivByte)
	data := make([]byte, len(cipherText))
	cfb.XORKeyStream(data, cipherText)
	return data, nil
}

func bas64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
