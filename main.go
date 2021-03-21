package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/go-piv/piv-go/piv"
	"github.com/wojciech-malota-wojcik/legacy/config"
	"github.com/wojciech-malota-wojcik/legacy/parts"
	"github.com/wojciech-malota-wojcik/legacy/types"
	"github.com/wojciech-malota-wojcik/legacy/util"
)

func main() {
	util.WorkingDir(0)
	if err := integrate(); err != nil {
		log.Fatal(err)
	}
}

func integrate() error {
	processedPublicKeys := map[string]bool{}
	fmt.Print("Connect YubiKey and press ENTER...")
	readline()
	for {
		var masterTree types.SeedNode
		cards, err := piv.Cards()
		if err != nil {
			return fmt.Errorf("fetching YubiKey devices failed: %w", err)
		}
		for _, ykCard := range cards {
			if !strings.Contains(strings.ToLower(ykCard), "yubikey") {
				continue
			}

			s, partKey, ok, err := decrypt(processedPublicKeys, ykCard)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}

			// decrypt part file using symmetric key

			block, err := aes.NewCipher(partKey)
			if err != nil {
				return err
			}

			rawTree := make([]byte, len(s.Part))

			stream := cipher.NewCFBDecrypter(block, s.IV)
			stream.XORKeyStream(rawTree, s.Part)

			var sTree types.SeedNode
			if err := json.Unmarshal(rawTree, &sTree); err != nil {
				return err
			}
			integratePart(&masterTree, &sTree)
			fill(&masterTree, map[int]bool{})
			pr := progress(&masterTree)
			fmt.Printf("PIN correct, %d%% of seed integrated, missing bytes: %d\n", int(math.Round(100.*float64(pr)/float64(config.SeedSize))), config.SeedSize-pr)
			if pr == config.SeedSize {
				break
			}
		}
		if masterTree.Data == nil {
			fmt.Print("Connect another YubiKey and press ENTER...")
			readline()
			continue
		}
		key := util.BuildPrivateKey(masterTree.Data)
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}

		rawData := make([]byte, len(parts.Data.Data))

		stream := cipher.NewCFBDecrypter(block, parts.Data.IV)
		stream.XORKeyStream(rawData, parts.Data.Data)

		return ioutil.WriteFile("./data.img", rawData, 0o444)
	}
}

func decrypt(processedPublicKeys map[string]bool, ykCard string) (successor types.Successor, decryptedKey []byte, ok bool, err error) {
	yk, err := piv.Open(ykCard)
	if err != nil {
		return types.Successor{}, nil, false, fmt.Errorf("opening YubiKey device failed: %w", err)
	}
	defer func() {
		if err2 := yk.Close(); err == nil && err2 != nil {
			err = fmt.Errorf("closing YubiKey device failed: %w", err2)
		}
	}()

	cert, err := yk.Certificate(piv.SlotSignature)
	if err != nil {
		return types.Successor{}, nil, false, fmt.Errorf("fetching certificate failed: %w", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return types.Successor{}, nil, false, errors.New("wrong format of public key on YubiKey, RSA expected")
	}
	pubKeyRaw := x509.MarshalPKCS1PublicKey(pubKey)
	pubKeyStr := fmt.Sprintf("%x", pubKeyRaw)
	if processedPublicKeys[pubKeyStr] {
		fmt.Printf("Hello %s, part of decryption key represented by your YubiKey has been already applied\n", cert.Subject.CommonName)
		return types.Successor{}, nil, false, nil
	}

	s, err := findSuccessor(pubKeyRaw)
	if err != nil {
		return types.Successor{}, nil, false, err
	}

	fmt.Printf("Hello %s, provide your YubiKey PIN: ", cert.Subject.CommonName)

	pin := readline()
	pk, err := yk.PrivateKey(piv.SlotSignature, cert.PublicKey, piv.KeyAuth{PIN: pin, PINPolicy: piv.PINPolicyAlways})
	if err != nil {
		return types.Successor{}, nil, false, fmt.Errorf("fetching private key failed: %w", err)
	}

	privKey, ok := pk.(crypto.Decrypter)
	if !ok {
		return types.Successor{}, nil, false, errors.New("private key stored on YubiKey can't be used for decryption")
	}
	decrypted, err := privKey.Decrypt(rand.Reader, s.Key, nil)
	if err != nil {
		return types.Successor{}, nil, false, fmt.Errorf("decryption failed: %w", err)
	}
	processedPublicKeys[pubKeyStr] = true
	return s, decrypted, true, nil
}

func findSuccessor(pubKey []byte) (types.Successor, error) {
	for _, s := range parts.Successors {
		if bytes.Equal(pubKey, s.PublicKey) {
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

func integratePart(masterNode *types.SeedNode, successorNode *types.SeedNode) {
	if masterNode.Data != nil {
		return
	}
	if successorNode.Data != nil {
		masterNode.Data = successorNode.Data
		masterNode.Sub = nil
		return
	}
	if masterNode.Sub == nil {
		masterNode.Sub = map[int]types.SeedNode{}
	}
	for i, sN := range successorNode.Sub {
		node, ok := masterNode.Sub[i]
		if !ok {
			node = types.SeedNode{}
		}
		integratePart(&node, &sN)
		masterNode.Sub[i] = node
	}
}

func fill(masterNode *types.SeedNode, stack map[int]bool) {
	if masterNode.Data != nil {
		return
	}
	expectedChildren := len(parts.Successors) - len(stack)
	if len(masterNode.Sub) < expectedChildren {
		return
	}
	keys := make([]int, 0, expectedChildren)
	for k := range masterNode.Sub {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	var data []byte
	for _, k := range keys {
		stack[k] = true
		node := masterNode.Sub[k]
		fill(&node, stack)
		delete(stack, k)
		if node.Data == nil {
			return
		}
		masterNode.Sub[k] = node
		data = append(data, node.Data...)
	}
	dLen := 0
	for _, k := range keys {
		dLen += len(masterNode.Sub[k].Data)
	}
	masterNode.Data = make([]byte, 0, dLen)
	for i := 0; i < dLen; i++ {
		j := i / expectedChildren
		k := i % expectedChildren
		masterNode.Data = append(masterNode.Data, masterNode.Sub[keys[k]].Data[j])
	}
	masterNode.Sub = nil
}

func progress(masterNode *types.SeedNode) int {
	if masterNode.Data != nil {
		return len(masterNode.Data)
	}
	var res int
	for _, sN := range masterNode.Sub {
		res += progress(&sN)
	}
	return res
}
