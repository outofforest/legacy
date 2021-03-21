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
	"os"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/wojciech-malota-wojcik/legacy/parts"
	"github.com/wojciech-malota-wojcik/legacy/types"
)

// Decrypt decrypts AES key used to encrypt successor's part using private key stored on YubiKey
func Decrypt(ciphertext []byte) ([]byte, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	for _, ykCard := range cards {
		if !strings.Contains(strings.ToLower(ykCard), "yubikey") {
			continue
		}
		return decrypt(ciphertext, ykCard)
	}
	return nil, errors.New("no YubiKey detected")
}

func decrypt(ciphertext []byte, ykCard string) ([]byte, error) {
	yk, err := piv.Open(ykCard)
	if err != nil {
		return nil, err
	}
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
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

	fmt.Printf("Hello %s, provide your YubiKey PIN: ", cert.Subject.CommonName)

	pin := readline()
	pk, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, piv.KeyAuth{PIN: pin, PINPolicy: piv.PINPolicyAlways})
	if err != nil {
		return nil, err
	}
	privKey, ok := pk.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("private key stored on YubiKey can't be used for decryption")
	}
	return privKey.Decrypt(rand.Reader, ciphertext, nil)
}

func findSuccessor(pubKey *rsa.PublicKey) (types.Successor, error) {
	raw := x509.MarshalPKCS1PublicKey(pubKey)
	for _, s := range parts.Successors {
		if bytes.Equal(raw, s.PublicKey) {
			return s, nil
		}
	}
	return types.Successor{}, errors.New("successor not recognized based on public key stored on YubiKey")
}

func readline() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}
