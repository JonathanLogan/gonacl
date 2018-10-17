package encode

import (
	"bytes"
	"strings"
	"testing"

	"github.com/JonathanLogan/gonacl/crypto"
)

func TestPrivateKey(t *testing.T) {
	k := [crypto.PrivateKeySize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	encoded := EncodePrivateKey(&k)
	decoded, err := DecodePrivateKey(encoded)
	if err != nil {
		t.Fatalf("DecodePrivateKey: %s", err)
	}
	if *decoded != k {
		t.Error("Decode Privatekey wrong data.")
	}
}

func TestPublicKey(t *testing.T) {
	k := [crypto.PublicKeySize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	encoded := EncodePublicKey(&k)
	decoded, err := DecodePublicKey(encoded)
	if err != nil {
		t.Fatalf("DecodePublicKey: %s", err)
	}
	if *decoded != k {
		t.Error("Decode Publickey wrong data.")
	}
}

func TestMessage(t *testing.T) {
	td := "supersecretmessage"
	k := []byte(strings.Repeat(td, (500/len(td))+1))
	k = k[:500]
	encoded := EncodeMessage(k)
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage: %s", err)
	}
	if !bytes.Equal(k, decoded) {
		t.Error("Decode Message wrong data.")
	}
}

func TestFormatting(t *testing.T) {
	td := "supersecretmessage"
	k := []byte(strings.Repeat(td, (500/len(td))+1))
	encoded := EncodeMessage(k)

	for i := 0; i < len(encoded); i++ {
		formatted := FormatMessage(encoded[0:i])
		unformatted := ParseMessage(formatted)
		if unformatted != encoded[0:i] {
			t.Errorf("Formatting error: %d", i)
		}
	}
}
