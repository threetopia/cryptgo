package cryptgo

import (
	"bytes"
	"testing"
)

var unecryptedStr = "Lorem ipsum"
var secret = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef" // 32 bytes hex string
var iv = "1234567890ab"

func TestEncryptDecryptStr(t *testing.T) {
	byteStr := []byte(unecryptedStr)
	encryptData, err := Encrypt(byteStr, secret, []byte(iv))
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if encryptData == nil {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	}

	decryptedData, err := Decrypt(encryptData, secret, []byte(iv))
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if !bytes.Equal(decryptedData, byteStr) || decryptedData == nil {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	} else if string(decryptedData) != string(byteStr) {
		t.Errorf("error when encrypting text. somehow the output is not correct")
		return
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	data := []byte("test data")
	shortKey := "shortkey"
	iv := "1234567890abcdef"
	_, err := Encrypt(data, shortKey, []byte(iv))
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestEncrypt_InvalidIVSize(t *testing.T) {
	data := []byte("test data")
	key := "12345678901234567890123456789012" // 32 bytes
	shortIV := "shortiv"
	_, err := Encrypt(data, key, []byte(shortIV))
	if err == nil {
		t.Error("expected error for invalid IV size, got nil")
	}
}

func TestDecrypt_InvalidKeySize(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	shortKey := "shortkey"
	iv := "1234567890abcdef"
	_, err := Decrypt(data, shortKey, []byte(iv))
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestDecrypt_InvalidIVSize(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	key := "12345678901234567890123456789012" // 32 bytes
	shortIV := "shortiv"
	_, err := Decrypt(data, key, []byte(shortIV))
	if err == nil {
		t.Error("expected error for invalid IV size, got nil")
	}
}

var keyRt = "1234567890123456789012345678901212345678901234567890123456789012" // 32 bytes
var ivRt = "123456789012"                      // 12 bytes for GCM
var plainRt = []byte("The quick brown fox jumps over the lazy dog")

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	ciphertext, err := Encrypt(plainRt, keyRt, []byte(ivRt))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	decrypted, err := Decrypt(ciphertext, keyRt, []byte(ivRt))
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plainRt, decrypted) {
		t.Errorf("decrypted data does not match original. got %q, want %q", decrypted, plainRt)
	}
}

func TestDecrypt_BadCiphertext(t *testing.T) {
	key := "12345678901234567890123456789012" // 32 bytes
	iv := "123456789012"                      // 12 bytes for GCM
	badCipher := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	_, err := Decrypt(badCipher, key, []byte(iv))
	if err == nil {
		t.Error("expected error for bad ciphertext, got nil")
	}
}
