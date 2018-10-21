// Package crypto implements cryptographic functions for gonacl.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/nacl/box"
)

var randomSource = rand.Reader

var (
	// ErrMaximumMessageSize is returned if a given message is too long.
	ErrMaximumMessageSize = errors.New("gonacl/crypto: Maximum message size exceeded")
	// ErrMessageLength is returned whenever a message slice is encountered that has an unexpected length.
	ErrMessageLength = errors.New("gonacl/crypto: Unexpected message length")
	// ErrDecryptionFailed is returned if a message cannot be decrypted.
	ErrDecryptionFailed = errors.New("gonacal/crypto: Decryption failed")
)

const (
	// PublicKeySize is the size of a public key.
	PublicKeySize = 32
	// PrivateKeySize is the size of a private key.
	PrivateKeySize = 32
	// MaximumCleartextSize is the number of bytes a cleartext may contain AT MOST.
	MaximumCleartextSize = 500
	// NonceSize is the size of nonces.
	NonceSize = 24
	// paddingLengthFieldSize => size of padding length field in message.
	paddingLengthFieldSize = 2
	// messageHeaderSize => prefix to encrypted message
	messageHeaderSize = NonceSize + PublicKeySize
	// CyphertextSize is the fixed length of any binary cyphertext.
	CyphertextSize = messageHeaderSize + paddingLengthFieldSize + MaximumCleartextSize + box.Overhead
	// aesKeySize is the size of AES keys (256bit)
	aesKeySize = 32
)

// GenerateKeys returns a keypair for curve25519.
func GenerateKeys() (publicKey *[PublicKeySize]byte, privatekey *[PrivateKeySize]byte, err error) {
	pubkey, privkey, err := box.GenerateKey(randomSource)
	if err != nil {
		return nil, nil, err
	}
	return pubkey, privkey, nil
}

// addPadding prepends the length of the message to the output, followed by the message, followed by padding.
func addPadding(d []byte, maxLength int) ([]byte, error) {
	msgLen := len(d)
	if msgLen == 0 {
		return nil, ErrMessageLength
	}
	padLen := maxLength - msgLen
	if padLen < 0 {
		return nil, ErrMaximumMessageSize
	}
	paddedMessage := make([]byte, maxLength+paddingLengthFieldSize)                    // We only add the length field.
	padding := paddedMessage[paddingLengthFieldSize+msgLen:]                           // Only the part after length field and message.
	binary.BigEndian.PutUint16(paddedMessage[:paddingLengthFieldSize], uint16(len(d))) // Write length field.
	copy(paddedMessage[paddingLengthFieldSize:paddingLengthFieldSize+msgLen], d)       // Copy message
	if padLen == 0 {                                                                   // Nothing to do today.
		return paddedMessage, nil
	}
	if padLen <= aes.BlockSize+aesKeySize { // IV plus Key. We try to be a little nice on random source without going insecure.
		_, err := io.ReadFull(randomSource, padding)
		if err != nil {
			return nil, err
		}
		return paddedMessage, nil
	}
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(randomSource, iv)
	if err != nil {
		return nil, err
	}
	key := make([]byte, aesKeySize)
	_, err = io.ReadFull(randomSource, key)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(padding, padding)
	return paddedMessage, nil
}

func removePadding(d []byte, maxLength int) ([]byte, error) {
	if len(d) != maxLength+paddingLengthFieldSize {
		return nil, ErrMessageLength
	}
	msgLen := int(binary.BigEndian.Uint16(d[:paddingLengthFieldSize]))
	if msgLen == 0 {
		return nil, ErrMessageLength
	}
	return d[paddingLengthFieldSize : paddingLengthFieldSize+msgLen], nil
}

func genNonce() (*[NonceSize]byte, error) {
	out := new([NonceSize]byte)
	_, err := io.ReadFull(randomSource, out[:])
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Encrypt the given cleartext to the public key. Message is always padded to 500 byte.
func Encrypt(publicKey *[PublicKeySize]byte, cleartext []byte) (encrypted *[CyphertextSize]byte, err error) {
	paddedMessage, err := addPadding(cleartext, MaximumCleartextSize)
	if err != nil {
		return nil, err
	}
	messagePublicKey, messagePrivateKey, err := GenerateKeys()
	if err != nil {
		return nil, err
	}
	nonce, err := genNonce()
	if err != nil {
		return nil, err
	}
	outN := box.Seal(nil, paddedMessage, nonce, publicKey, messagePrivateKey)
	out := new([CyphertextSize]byte)
	copy(out[:PublicKeySize], messagePublicKey[:])
	copy(out[PublicKeySize:messageHeaderSize], nonce[:])
	copy(out[messageHeaderSize:], outN)
	return out, nil
}

// Decrypt a cyphertext with a private key.
func Decrypt(cyphertext []byte, privatekey *[PrivateKeySize]byte) (cleartest []byte, err error) {
	if len(cyphertext) != CyphertextSize {
		return nil, ErrMessageLength
	}
	nonce := new([NonceSize]byte)
	senderPubKey := new([PublicKeySize]byte)
	copy(senderPubKey[:], cyphertext[:PublicKeySize])
	copy(nonce[:], cyphertext[PublicKeySize:messageHeaderSize])
	msgPadded, ok := box.Open(nil, cyphertext[messageHeaderSize:], nonce, senderPubKey, privatekey)
	if !ok {
		return nil, ErrDecryptionFailed
	}
	msg, err := removePadding(msgPadded, MaximumCleartextSize)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
