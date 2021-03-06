package build

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strings"
	"text/template"

	"github.com/go-piv/piv-go/piv"
	"github.com/wojciech-malota-wojcik/build"
	"github.com/wojciech-malota-wojcik/ioc"
	"github.com/wojciech-malota-wojcik/legacy/config"
	"github.com/wojciech-malota-wojcik/legacy/types"
	"github.com/wojciech-malota-wojcik/legacy/util"
)

func printPublicKey() error {
	cards, err := piv.Cards()
	if err != nil {
		return err
	}
	for _, card := range cards {
		if !strings.Contains(strings.ToLower(card), "yubikey") {
			continue
		}
		yk, err := piv.Open(card)
		if err != nil {
			return err
		}
		defer yk.Close()

		cert, err := yk.Certificate(piv.SlotSignature)
		if err != nil {
			return err
		}

		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("wrong format of public key on YubiKey, RSA expected")
		}

		fmt.Printf("Public key of %s:\n\n%#v\n\n", cert.Subject.CommonName, x509.MarshalPKCS1PublicKey(pubKey))
	}
	return nil
}

func buildLegacyProd(c *ioc.Container, deps build.DepsFunc) {
	c.Singleton(func() config.Config {
		return config.Prod
	})
	deps(buildLegacy)
}

func buildLegacyDev(c *ioc.Container, deps build.DepsFunc) {
	c.Singleton(func() config.Config {
		return config.Dev
	})
	deps(buildLegacy)
}

func generateLegacy(cfg config.Config) error {
	knownParts(cfg)

	if err := os.RemoveAll("./parts"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir("./parts", 0o755); err != nil {
		return err
	}

	seed := make([]byte, config.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}

	// encrypt data using symmetric key

	key := util.BuildPrivateKey(seed)
	rawData, err := ioutil.ReadFile(cfg.DataFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	data := types.Data{
		IV:   make([]byte, block.BlockSize()),
		Data: make([]byte, len(rawData)),
	}

	if _, err := rand.Read(data.IV); err != nil {
		return err
	}
	stream := cipher.NewCFBEncrypter(block, data.IV)
	stream.XORKeyStream(data.Data, rawData)

	buf := &bytes.Buffer{}
	if err := pTplData.Execute(buf, data); err != nil {
		return err
	}
	if err := ioutil.WriteFile("./parts/data.go", buf.Bytes(), 0o444); err != nil {
		return err
	}

	// create parts

	masterTree := types.SeedNode{Data: seed}
	buildSeedTree(cfg, &masterTree, map[int]bool{})
	ss := make([]int, 0, len(cfg.Successors))
	for i, s := range cfg.Successors {
		var sTree types.SeedNode
		successorTree(&masterTree, &sTree, i)
		rawTree, err := json.Marshal(sTree)
		if err != nil {
			panic(err)
		}

		// encrypt part file using symmetric key

		partKey := make([]byte, config.AESKeySize)
		if _, err := rand.Read(partKey); err != nil {
			return err
		}
		block, err := aes.NewCipher(partKey)
		if err != nil {
			return err
		}

		sInfo := types.Successor{
			PublicKey: s,
			IV:        make([]byte, block.BlockSize()),
			Part:      make([]byte, len(rawTree)),
		}

		if _, err := rand.Read(sInfo.IV); err != nil {
			return err
		}
		stream := cipher.NewCFBEncrypter(block, sInfo.IV)
		stream.XORKeyStream(sInfo.Part, rawTree)

		// encrypt symmetric key using public key of successor

		pubKey, err := x509.ParsePKCS1PublicKey(s)
		if err != nil {
			return err
		}
		sInfo.Key, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, partKey)
		if err != nil {
			return err
		}

		buf := &bytes.Buffer{}
		if err := pTplSuccessor.Execute(buf, successorEntry{Index: i, Data: sInfo}); err != nil {
			return err
		}
		if err := ioutil.WriteFile(fmt.Sprintf("./parts/s%d.go", i), buf.Bytes(), 0o444); err != nil {
			return err
		}
		ss = append(ss, i)
	}
	buf = &bytes.Buffer{}
	if err := pTplSuccessors.Execute(buf, ss); err != nil {
		return err
	}
	if err := ioutil.WriteFile("./parts/parts.go", buf.Bytes(), 0o444); err != nil {
		return err
	}
	return nil
}

func buildLegacy(ctx context.Context, cfg config.Config, deps build.DepsFunc) error {
	deps(generateLegacy)
	return goBuildPkg(ctx, ".", "bin/"+cfg.ExeName)
}

const tplSuccessors = `package parts

import "github.com/wojciech-malota-wojcik/legacy/types"

var Successors = []types.Successor{
	{{- range $val := . }}
    successor{{ $val }},{{ end }}
}
`

const tplSuccessor = `package parts

import "github.com/wojciech-malota-wojcik/legacy/types"

var successor{{ .Index }} = {{ .Data }}
`

const tplData = `package parts

import "github.com/wojciech-malota-wojcik/legacy/types"

var Data = {{ . }}
`

var pTplSuccessors = template.Must(template.New("").Parse(tplSuccessors))
var pTplSuccessor = template.Must(template.New("").Parse(tplSuccessor))
var pTplData = template.Must(template.New("").Parse(tplData))

type successorEntry struct {
	Index int
	Data  types.Successor
}

func knownParts(cfg config.Config) {
	leafLen := 1
	for i := len(cfg.Successors); i >= cfg.RequiredToDecrypt; i-- {
		leafLen *= i
	}
	bytesInLeaf := int(math.Floor(float64(config.SeedSize) / float64(leafLen)))
	fmt.Printf("Bytes in leaf: %d\n", bytesInLeaf)
	if bytesInLeaf < 5 {
		panic("minimum required bytes per leaf is 5, use longer seed")
	}
	sLen := len(cfg.Successors)
	for i := 1; i <= cfg.RequiredToDecrypt; i++ {
		known := 0.
		for j := sLen; j >= cfg.RequiredToDecrypt; j-- {
			known += (1. - known) * float64(i) / float64(j)
		}
		missingBytes := int(math.Floor((1. - known) * float64(config.SeedSize)))
		fmt.Printf("Knowledge owned by %d successor(s): %d%%, Missing bytes: %d\n", i, int(math.Round(100.*known)), missingBytes)
	}
}

func buildSeedTree(cfg config.Config, node *types.SeedNode, stack map[int]bool) {
	numOfBuckets := len(cfg.Successors) - len(stack)
	if numOfBuckets < cfg.RequiredToDecrypt {
		return
	}
	node.Sub = map[int]types.SeedNode{}
	buckets := equalDiv(node.Data, numOfBuckets)
	bI := 0
	for i := 0; i < len(cfg.Successors); i++ {
		if stack[i] {
			continue
		}
		if len(buckets[bI]) == 0 {
			return
		}
		stack[i] = true
		subNode := types.SeedNode{Data: buckets[bI]}
		buildSeedTree(cfg, &subNode, stack)
		node.Sub[i] = subNode
		bI += 1
		delete(stack, i)
	}
}

func equalDiv(data []byte, numOfBuckets int) [][]byte {
	buckets := make([][]byte, numOfBuckets)
	for i, v := range data {
		// this will spread bytes of each seed across buckets
		bucket := i % numOfBuckets
		buckets[bucket] = append(buckets[bucket], v)
	}
	return buckets
}

func successorTree(masterNode *types.SeedNode, successorNode *types.SeedNode, successorIndex int) {
	if masterNode.Sub == nil {
		return
	}
	successorNode.Sub = map[int]types.SeedNode{}
	for i, mN := range masterNode.Sub {
		if i == successorIndex {
			successorNode.Sub[i] = types.SeedNode{Data: mN.Data}
		} else {
			var node types.SeedNode
			successorTree(&mN, &node, successorIndex)
			if node.Sub != nil {
				successorNode.Sub[i] = node
			}
		}
	}
}
