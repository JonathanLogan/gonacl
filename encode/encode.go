// Package encode provides functions to encode/decode keys and messages.
package encode

import (
	"errors"
	"strings"

	"github.com/JonathanLogan/gonacl/crypto"
	"github.com/btcsuite/btcutil/base58"
)

const (
	PublicKeyType  = 0xf0
	PrivateKeyType = 0xf1
	MessageType    = 0xf2
	messageHeader  = "----- NACL ENCRYPTED MESSAGE BEGIN -----\n\n"
	messageFooter  = "\n----- NACL ENCRYPTED MESSAGE END -----"
	maxWidth       = 48
)

var ErrWrongType = errors.New("gonacl/encode: Wrong type")

func EncodePublicKey(publicKey *[crypto.PublicKeySize]byte) string {
	return base58.CheckEncode(publicKey[:], PublicKeyType)
}

func DecodePublicKey(publicKeyEncoded string) (*[crypto.PublicKeySize]byte, error) {
	k, version, err := base58.CheckDecode(publicKeyEncoded)
	if err != nil {
		return nil, err
	}
	if version != PublicKeyType {
		return nil, ErrWrongType
	}
	o := new([crypto.PublicKeySize]byte)
	copy(o[:], k)
	return o, nil
}

func EncodePrivateKey(privateKey *[crypto.PrivateKeySize]byte) string {
	return base58.CheckEncode(privateKey[:], PrivateKeyType)
}

func DecodePrivateKey(privateKeyEncoded string) (*[crypto.PrivateKeySize]byte, error) {
	k, version, err := base58.CheckDecode(privateKeyEncoded)
	if err != nil {
		return nil, err
	}
	if version != PrivateKeyType {
		return nil, ErrWrongType
	}
	o := new([crypto.PrivateKeySize]byte)
	copy(o[:], k)
	return o, nil
}

func EncodeMessage(msg []byte) string {
	return base58.CheckEncode(msg, MessageType)
}

func DecodeMessage(msgEncoded string) ([]byte, error) {
	k, version, err := base58.CheckDecode(msgEncoded)
	if err != nil {
		return nil, err
	}
	if version != MessageType {
		return nil, ErrWrongType
	}
	return k, nil
}

func EncodeFormatMessage(msg []byte) string {
	return FormatMessage(EncodeMessage(msg))
}

func DecodeParseMessage(msg string) ([]byte, error) {
	return DecodeMessage(ParseMessage(msg))
}

func FormatMessage(s string) string {
	msglen := len(s)
	op := make([]string, 0, (msglen/maxWidth)+1)
	for i := 0; i < msglen; i += maxWidth {
		e := i + maxWidth
		if i+maxWidth > msglen {
			e = msglen
		}
		op = append(op, s[i:e])
	}
	return messageHeader + strings.Join(op, "\n") + messageFooter
}

func ParseMessage(s string) string {
	op := make([]string, 0, (len(s)/maxWidth)+1)
	substr := strings.Split(s, "\n")
	for _, k := range substr {
		if len(k) == 0 {
			continue
		}
		if len(k) >= 1 && k[0] == '-' {
			continue
		}
		op = append(op, k)
	}
	return strings.Join(op, "")
}
