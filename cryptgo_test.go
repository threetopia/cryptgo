package cryptgo

import (
	"bytes"
	"os"
	"testing"
)

var plainStr = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
var secret = "abcdefghij1234567890-+*/"
var iv = "1234567890abcdef"

func TestEncryptDecryptStr(t *testing.T) {
	err := os.Setenv("CRYPTGO_BYTES_STR", "abcdefghij123456")
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	byteStr := []byte(plainStr)
	encryptStr, err := Encrypt(byteStr, secret, []byte(iv))
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if encryptStr == plainStr || encryptStr == "" {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	}
	decryptByte, err := Decrypt(encryptStr, secret, []byte(iv))
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if !bytes.Equal(decryptByte, byteStr) || decryptByte == nil {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	} else if string(decryptByte) != string(byteStr) {
		t.Errorf("error when encrypting text. somehow the output is not correct")
		return
	}
}
