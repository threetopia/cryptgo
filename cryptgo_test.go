package cryptgo

import (
	"bytes"
	"testing"
)

var unecryptedStr = "Lorem ipsum"
var secret = "abcdefghij1234567890-+*/"
var iv = "1234567890abcdef"

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

	decryptedData, err := Decrypt([]byte{29, 151, 234, 190, 13, 168, 36, 139, 157, 247, 141}, secret, []byte(iv))
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
