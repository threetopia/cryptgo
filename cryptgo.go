// This is the package cryptgo
// a simple crypt utils for Go
package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
)

// Encrypt returns a encrypted data in []byte and error.
// The arguments consists with data []byte, secret string, and ivByte []byte.
// The data argument is unecrypted data in []byte format.
// The secret argument is an secret key in string with 24 char length.
// The ivByte argument is an Initialization vector in string with 16 char length.
//
// Here is an example how to use Encrypt function:
//
//	func Encrypt() {
//	    unecryptedStr := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
//	    secret := "abcdefghij1234567890-+*/"
//		iv := "1234567890abcdef"
//		byteUnecryptedStr := []byte(unecryptedStr)
//		encryptedData, err := Encrypt(byteStr, secret, []byte(iv))
//		if err != nil {
//			t.Errorf("error when encrypting text (%s)", err.Error())
//			return
//		}
//		fmt.Println(string(encryptedData))
//	}
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

// Decrypt returns a decrypted data in []byte and error.
// The arguments consists with data []byte, secret string, and ivByte []byte.
// The data argument is ecrypted data in []byte format.
// The secret argument is an secret key in string with 24 char length.
// The ivByte argument is an Initialization vector in string with 16 char length.
//
// Here is an example how to use Decrypt function:
//
//	func Decrypt() {
//	    ecryptedByte := []byte{29, 151, 234, 190, 13, 168, 36, 139, 157, 247, 141}
//	    secret := "abcdefghij1234567890-+*/"
//		iv := "1234567890abcdef"
//		decryptedData, err := Decrypt(ecryptedByte, secret, []byte(iv))
//		if err != nil {
//			t.Errorf("error when encrypting text (%s)", err.Error())
//			return
//		}
//		fmt.Println(string(decryptedData))
//	}
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
