package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
)

func Encrypt(data []byte, secret string, ivByte []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, ivByte)
	encryptedData := make([]byte, len(data))
	cfb.XORKeyStream(encryptedData, data)
	return encryptedData, nil
}

func Decrypt(encryptedData []byte, secret string, ivByte []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBDecrypter(block, ivByte)
	data := make([]byte, len(encryptedData))
	cfb.XORKeyStream(data, encryptedData)
	return data, nil
}
