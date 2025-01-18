// This is the package cryptgo
// a simple crypt utils for Go
package cryptgo

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
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
	// Decode the secret key (hex-encoded)
	key, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}

	// Ensure key is 32 bytes for AES-256
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d bytes", len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := ivByte
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d bytes", gcm.NonceSize(), len(nonce))
	}

	// Seal the data with AES-GCM
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
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
	// Decode the secret key (hex-encoded)
	key, err := hex.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}

	// Ensure key is 32 bytes for AES-256
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d bytes", len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create AES-GCM cipher mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Ensure nonce is the correct size for AES-GCM
	nonce := ivByte
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid IV size: expected %d bytes, got %d bytes", gcm.NonceSize(), len(nonce))
	}

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}
