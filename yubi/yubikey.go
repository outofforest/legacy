package yubi

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"github.com/wojciech-malota-wojcik/legacy/config"
	"strings"
)

func Test() error {
	cards, err := piv.Cards()
	if err != nil {
		return err
	}
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yk, err := piv.Open(card)
			if err != nil {
				return err
			}
			cert, err := yk.Certificate(piv.SlotAuthentication)
			if err != nil {
				return err
			}

			pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			if !ok {
				return errors.New("wrong format of public key on YubiKey, RSA expected")
			}

			successor, err := findSuccessor(pubKey)
			if err != nil {
				return err
			}
			fmt.Printf("Hello %s\n", successor.Name)
		}
	}
	return nil
}

func findSuccessor(pubKey *rsa.PublicKey) (config.Successor, error) {
	raw := x509.MarshalPKCS1PublicKey(pubKey)
	for _, s := range config.Successors {
		if bytes.Equal(raw, s.PublicKey) {
			return s, nil
		}
	}
	return config.Successor{}, errors.New("successor not recognized based on public key stored on YubiKey")
}
