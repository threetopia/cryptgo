package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	"gitlab.com/threetopia/envgo"
)

func EncryptStr(plainStr, secret string) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}
	plainStrByte := []byte(plainStr)
	cfb := cipher.NewCFBEncrypter(block, getBytes())
	cipherText := make([]byte, len(plainStrByte))
	cfb.XORKeyStream(cipherText, plainStrByte)
	return encode(cipherText), nil
}

func DecryptStr(encryptStr, secret string) (string, error) {
	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}
	cipherText := decode(encryptStr)
	cfb := cipher.NewCFBDecrypter(block, getBytes())
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func getBytes() []byte {
	return []byte(envgo.GetString("CRYPTGO_BYTES_STR", "1234567890abcdef"))
}
