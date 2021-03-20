package yubi

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/wojciech-malota-wojcik/legacy/config"
	"os"
	"strings"
)

var pin string

// Decrypt decrypts AES key used to encrypt successor's part using private key stored on YubiKey
func Decrypt(ciphertext []byte) ([]byte, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			return nil, err
		}
		defer yk.Close()

		cert, err := yk.Certificate(piv.SlotAuthentication)
		if err != nil {
			return nil, err
		}

		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("wrong format of public key on YubiKey, RSA expected")
		}

		_, err = findSuccessor(pubKey)
		if err != nil {
			return nil, err
		}

		if pin == "" {
			fmt.Println("YubiKey PIN:")
			pin = readline()
		}

		pk, err := yk.PrivateKey(piv.SlotAuthentication, cert.PublicKey, piv.KeyAuth{PIN: pin, PINPolicy: piv.PINPolicyOnce})
		if err != nil {
			return nil, err
		}
		privKey, ok := pk.(crypto.Decrypter)
		if !ok {
			return nil, errors.New("private key stored on YubiKey can't be used for decryption")
		}
		return privKey.Decrypt(rand.Reader, ciphertext, nil)
	}
	return nil, errors.New("no YubiKey detected")
}

func findSuccessor(pubKey *rsa.PublicKey) ([]byte, error) {
	raw := x509.MarshalPKCS1PublicKey(pubKey)
	for _, s := range config.Successors {
		if bytes.Equal(raw, s) {
			return s, nil
		}
	}
	return nil, errors.New("successor not recognized based on public key stored on YubiKey")
}

func readline() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}
