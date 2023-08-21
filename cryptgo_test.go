package cryptgo

import (
	"bytes"
	"testing"
)

var plainStr = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
var secret = "abcdefghij1234567890-+*/"
var iv = "1234567890abcdef"

func TestEncryptDecryptStr(t *testing.T) {
	byteStr := []byte(plainStr)
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
