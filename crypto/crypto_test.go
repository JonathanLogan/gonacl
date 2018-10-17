package crypto

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

func TestPadding(t *testing.T) {
	td := []byte("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890")
	maxLen := len(td)
	padded, err := addPadding(td, maxLen)
	if err != nil {
		t.Errorf("addPadding 1: %s", err)
	}
	unpadded, err := removePadding(padded, maxLen)
	if err != nil {
		t.Errorf("removePadding 1: %s", err)
	}
	if !bytes.Equal(td, unpadded) {
		t.Errorf("Padding destroyed message 1: \n\t%s\n\t%s", td, unpadded)
	}
	td2 := td[2:]
	padded, err = addPadding(td2, maxLen)
	if err != nil {
		t.Errorf("addPadding 2: %s", err)
	}
	unpadded, err = removePadding(padded, maxLen)
	if err != nil {
		t.Errorf("removePadding 2: %s", err)
	}
	if !bytes.Equal(td2, unpadded) {
		t.Errorf("Padding destroyed message 2: \n\t%s\n\t%s", td2, unpadded)
	}

	td3 := td[aesKeySize+aes.BlockSize+2:]
	padded, err = addPadding(td3, maxLen)
	if err != nil {
		t.Errorf("addPadding 3: %s", err)
	}
	unpadded, err = removePadding(padded, maxLen)
	if err != nil {
		t.Errorf("removePadding 3: %s", err)
	}
	if !bytes.Equal(td3, unpadded) {
		t.Errorf("Padding destroyed message 3: \n\t%s\n\t%s", td3, unpadded)
	}

	td4 := []byte("1")
	padded, err = addPadding(td4, maxLen)
	if err != nil {
		t.Errorf("addPadding 4: %s", err)
	}
	unpadded, err = removePadding(padded, maxLen)
	if err != nil {
		spew.Dump(padded)

		t.Errorf("removePadding 4: %s", err)
	}
	if !bytes.Equal(td4, unpadded) {
		t.Errorf("Padding destroyed message 4: \n\t%s\n\t%s", td4, unpadded)
	}

	td5 := []byte("")
	padded, err = addPadding(td5, maxLen)
	if err == nil {
		unpadded, err = removePadding(padded, maxLen)
		if err == nil {
			t.Error("removePadding 5: Empty message should trigger error")
		}
		t.Errorf("addPadding 5: Empty message should trigger error")
	}
	td6 := make([]byte, maxLen+1)
	padded, err = addPadding(td6, maxLen)
	if err == nil {
		unpadded, err = removePadding(padded, maxLen)
		if err == nil {
			t.Error("removePadding 6: Long message should trigger error")
		}
		t.Errorf("addPadding 6: Long message should trigger error")
	}
}

func TestEncryption(t *testing.T) {
	td := []byte("Super secret message to be encrypted.")
	pub, priv, err := GenerateKeys()
	if err != nil {
		t.Fatalf("GenerateKeys: %s", err)
	}
	encrypted, err := Encrypt(pub, td)
	if err != nil {
		t.Fatalf("Encrypt: %s", err)
	}
	decrypted, err := Decrypt(encrypted[:], nil, priv)
	if err != nil {
		t.Errorf("Decrypt: %s", err)
	}
	if !bytes.Equal(decrypted, td) {
		t.Error("Encrypt/Decrypt modified message")
	}
	_, err = Decrypt(encrypted[:], pub, priv)
	if err != nil {
		t.Fatalf("Decrypt Receiver: %s", err)
	}
}
