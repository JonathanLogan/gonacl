// Package main provides an easy tool for naclbox encryption.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/JonathanLogan/gonacl/crypto"
	"github.com/JonathanLogan/gonacl/encode"
)

var (
	cmdEncrypt string
	cmdDecrypt string
	cmdKeygen  bool
)

func init() {
	flag.StringVar(&cmdEncrypt, "encrypt", "publickey", "encrypt to publickey")
	flag.StringVar(&cmdDecrypt, "decrypt", "privatekey", "decrypt with privatekey")
	flag.BoolVar(&cmdKeygen, "keygen", false, "generate keypair")
	flag.Parse()
	if flag.NFlag() > 1 || flag.NFlag() == 0 {
		printHelp()
	}
}

func printHelp() {
	fmt.Fprint(os.Stderr, "Select exactly one of -encrypt, -decrypt or -keygen.\n")
	flag.PrintDefaults()
	os.Exit(1)
}

func printError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	os.Exit(1)
}

func main() {
	unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	var publicKey *[crypto.PublicKeySize]byte
	var privateKey *[crypto.PrivateKeySize]byte
	var data []byte
	var err error
	if cmdKeygen {
		publicKey, privateKey, err = crypto.GenerateKeys()
		if err != nil {
			printError(err)
		}
		publicKeyEnc := encode.EncodePublicKey(publicKey)
		privateKeyEnc := encode.EncodePrivateKey(privateKey)
		fmt.Fprintf(os.Stdout, "PublicKey: %s\nPrivateKey: %s\n", publicKeyEnc, privateKeyEnc)
		os.Exit(0)
	}
	if cmdEncrypt != "publickey" && cmdEncrypt != "" {
		publicKey, err = encode.DecodePublicKey(cmdEncrypt)
		if err != nil {
			fmt.Println("HERE1")
			printError(err)
		}
	}
	if cmdDecrypt != "privatekey" && cmdDecrypt != "" {
		privateKey, err = encode.DecodePrivateKey(cmdDecrypt)
		if err != nil {
			fmt.Println("HERE2")
			printError(err)
		}
	}
	if privateKey != nil || publicKey != nil {
		data, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			printError(err)
		}
	}
	if publicKey != nil {
		encrypted, err := crypto.Encrypt(publicKey, data)
		if err != nil {
			printError(err)
		}
		fmt.Fprint(os.Stdout, encode.EncodeFormatMessage(encrypted[:])+"\n")
		os.Exit(0)
	}
	if privateKey != nil {
		decoded, err := encode.DecodeParseMessage(string(data))
		if err != nil {
			printError(err)
		}
		cleartext, err := crypto.Decrypt(decoded, nil, privateKey)
		if err != nil {
			printError(err)
		}
		fmt.Fprint(os.Stdout, string(cleartext))
		os.Exit(0)
	}
	printHelp()
}
