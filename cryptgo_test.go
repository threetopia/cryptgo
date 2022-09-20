package cryptgo

import (
	"os"
	"testing"
)

var plainStr = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
var secret = "abcdefghij1234567890-+*/"

func TestEncryptDecryptStr(t *testing.T) {
	err := os.Setenv("CRYPTGO_BYTES_STR", "abcdefghij123456")
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	encryptStr, err := EncryptStr(plainStr, secret)
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if encryptStr == plainStr || encryptStr == "" {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	}
	decryptStr, err := DecryptStr(encryptStr, secret)
	if err != nil {
		t.Errorf("error when encrypting text (%s)", err.Error())
		return
	}
	if decryptStr != plainStr || decryptStr == "" {
		t.Errorf("error when encrypting text. somehow it output nothing")
		return
	}
	t.Logf("encryptStr: %s , decryptStr: %s", encryptStr, decryptStr)
}
